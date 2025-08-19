// Package singpass provides a Go client library for Singapore's Singpass OpenID Connect (OIDC) authentication.
// It supports PKCE (Proof Key for Code Exchange) for secure authentication flows and includes
// comprehensive JWT/JWE token validation with JWKS (JSON Web Key Set) support.
package singpass

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid" //nolint:depguard // UUID generation is required for OIDC state
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/redis/go-redis/v9"

	"github.com/vector233/go-singpass/internal/auth"
	"github.com/vector233/go-singpass/internal/utils"
)

// ClientInterface defines the contract for Singpass authentication operations
type ClientInterface interface {
	// GenerateAuthURL generates the authorization URL for Singpass authentication
	// Returns the URL that users should be redirected to for authentication
	GenerateAuthURL(ctx context.Context) (string, error)

	// ExchangeCodeForUserInfo processes the callback from Singpass after user authentication
	// Takes the authorization code and state from the callback URL
	// Returns the complete user information after token validation
	ExchangeCodeForUserInfo(ctx context.Context, code, state string) (*UserInfo, error)

	// ExchangeCodeForTokens processes the callback and returns only the validated tokens
	// Takes the authorization code and state from the callback URL
	// Returns the token response after validation, without fetching user info
	ExchangeCodeForTokens(ctx context.Context, code, state string) (*TokenResponse, error)

	// GetUserInfo retrieves additional user information using the access token
	// This method calls the Singpass UserInfo endpoint for detailed user data
	GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error)

	// Close closes the client and cleans up resources (Redis connection, etc.)
	Close() error
}

// Client represents the Singpass authentication client
// It implements the ClientInterface
type Client struct {
	config         Config
	stateManager   *auth.StateManager
	tokenValidator *auth.TokenValidator
	httpClient     *http.Client
	redisClient    *redis.Client // Only used when UseRedis is true
}

// Ensure Client implements ClientInterface at compile time
var _ ClientInterface = (*Client)(nil)

// NewClient creates a new Singpass client with the given configuration
func NewClient(config *Config) (*Client, error) {
	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Initialize Redis client only if UseRedis is true
	var redisClient *redis.Client
	if config.UseRedis {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     config.RedisAddr,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		})

		// Test Redis connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			return nil, fmt.Errorf("redis ping failed: %w", err)
		}
	}

	// Initialize HTTP client
	httpClient := &http.Client{
		Timeout: config.HTTPTimeout,
	}

	// Initialize state manager based on configuration
	var stateManager *auth.StateManager
	if config.UseRedis {
		stateManager = auth.NewStateManagerWithRedis(redisClient, config.StateExpiration)
	} else {
		stateManager = auth.NewStateManagerWithMemory(config.StateExpiration)
	}

	// Initialize token validator
	tokenValidator := auth.NewTokenValidator(config.JWKSURL, config.Issuer, config.ClientID)

	client := &Client{
		config:         *config,
		stateManager:   stateManager,
		tokenValidator: tokenValidator,
		httpClient:     httpClient,
		redisClient:    redisClient,
	}

	return client, nil
}

// GenerateAuthURL generates the authorization URL for Singpass login
func (c *Client) GenerateAuthURL(ctx context.Context) (string, error) {
	// Generate state and nonce
	state := utils.GenerateState()
	nonce, err := utils.GenerateNonce()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, err := utils.GenerateRandomBase64(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	codeChallenge := utils.GenerateCodeChallenge(codeVerifier)

	// Store state data
	stateData := &auth.StateData{
		CodeVerifier: codeVerifier,
		Nonce:        nonce,
	}

	if err := c.stateManager.Store(ctx, state, stateData); err != nil {
		return "", fmt.Errorf("failed to store state data: %w", err)
	}

	// Build authorization URL
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.config.ClientID},
		"redirect_uri":          {c.config.RedirectURI},
		"scope":                 {c.config.Scope},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	authURL := fmt.Sprintf("%s?%s", c.config.AuthURL, params.Encode())
	return authURL, nil
}

// ExchangeCodeForTokens processes the callback and returns only the validated tokens
func (c *Client) ExchangeCodeForTokens(ctx context.Context, code, state string) (*TokenResponse, error) {
	// Retrieve and validate state data
	stateData, err := c.stateManager.Get(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("invalid state: state not found or expired")
	}

	// Exchange code for tokens
	tokenResp, err := c.exchangeCodeForTokens(ctx, code, stateData.CodeVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}

	// Validate ID token
	_, err = c.tokenValidator.ValidateIDToken(ctx, tokenResp.IDToken, stateData.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to validate ID token: %w", err)
	}

	// Clean up state data
	c.stateManager.Delete(ctx, state)

	return tokenResp, nil
}

// ExchangeCodeForUserInfo processes the callback from Singpass after user authentication
func (c *Client) ExchangeCodeForUserInfo(ctx context.Context, code, state string) (*UserInfo, error) {
	// Get validated tokens first
	tokenResp, err := c.ExchangeCodeForTokens(ctx, code, state)
	if err != nil {
		return nil, err
	}

	// Get user info from UserInfo endpoint using access token
	userInfo, err := c.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return userInfo, nil
}

// exchangeCodeForTokens exchanges authorization code for tokens
func (c *Client) exchangeCodeForTokens(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	// Create client assertion for authentication
	clientAssertion, err := c.createClientAssertion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create client assertion: %w", err)
	}

	data := url.Values{
		"grant_type":            {"authorization_code"},
		"client_id":             {c.config.ClientID},
		"code":                  {code},
		"redirect_uri":          {c.config.RedirectURI},
		"code_verifier":         {codeVerifier},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {clientAssertion},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Warning: failed to close response body: %v\n", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token response: %w", err)
	}

	return &tokenResp, nil
}

// createClientAssertion creates a JWT client assertion for token exchange
func (c *Client) createClientAssertion(_ context.Context) (string, error) {
	// Load private key for signing
	privateKey, err := c.loadPrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %w", err)
	}

	// Create JWT claims
	now := time.Now()
	claims := map[string]interface{}{
		"iss": c.config.ClientID,
		"sub": c.config.ClientID,
		"aud": c.config.TokenURL,
		"jti": uuid.New().String(),
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	}

	// Create JWT token from claims map
	builder := jwt.NewBuilder()
	for key, value := range claims {
		builder = builder.Claim(key, value)
	}
	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("failed to build JWT: %w", err)
	}

	// Get algorithm from the private key
	alg, ok := privateKey.Algorithm()
	if !ok {
		return "", fmt.Errorf("algorithm not found in JWK")
	}

	// Sign the token
	signed, err := jwt.Sign(token, jwt.WithKey(alg, privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return string(signed), nil
}

// loadPrivateKey loads the private key from file
func (c *Client) loadPrivateKey() (jwk.Key, error) {
	return c.loadPrivateKeyFromPath(c.config.SigPrivateKeyPath, "signature")
}

// loadJWKFromFile loads a JWK from file
func (c *Client) loadJWKFromFile(filePath string) (jwk.Key, error) {
	// Validate file path to prevent directory traversal attacks
	if strings.Contains(filePath, "..") || strings.Contains(filePath, "~") {
		return nil, fmt.Errorf("invalid file path: %s", filePath)
	}

	// Read the JWK file content
	sigKeyJSON, err := os.ReadFile(filePath) // #nosec G304 - file path is validated above
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", filePath, err)
	}

	// Parse the JWK key
	key, err := jwk.ParseKey(sigKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK private key: %w", err)
	}

	return key, nil
}

// GetUserInfo retrieves user information using access token
func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Create request to UserInfo endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.UserInfoURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status: %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// For Singpass, UserInfo response is typically JWE encrypted
	// Decrypt JWE if needed
	userInfoData, err := c.decryptUserInfo(body)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt user info: %w", err)
	}

	// Parse user info
	var userInfo UserInfo
	if err := json.Unmarshal(userInfoData, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	return &userInfo, nil
}

// decryptUserInfo decrypts JWE encrypted user info response
func (c *Client) decryptUserInfo(encryptedData []byte) ([]byte, error) {
	// Try to parse as JSON first (unencrypted response)
	var testJSON map[string]interface{}
	if err := json.Unmarshal(encryptedData, &testJSON); err == nil {
		// Data is already in JSON format, return as-is
		return encryptedData, nil
	}

	// Load encryption private key for decryption
	privateKey, err := c.loadEncryptionPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load encryption private key: %w", err)
	}

	// Get algorithm from the private key
	alg, ok := privateKey.Algorithm()
	if !ok {
		return nil, fmt.Errorf("algorithm not found in encryption key")
	}

	// Decrypt JWE
	decrypted, err := jwe.Decrypt(encryptedData, jwe.WithKey(alg, privateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt JWE: %w", err)
	}

	return decrypted, nil
}

// loadEncryptionPrivateKey loads the encryption private key from file
func (c *Client) loadEncryptionPrivateKey() (jwk.Key, error) {
	return c.loadPrivateKeyFromPath(c.config.EncPrivateKeyPath, "encryption")
}

// loadPrivateKeyFromPath loads a private key from the specified path
func (c *Client) loadPrivateKeyFromPath(keyPath, keyType string) (jwk.Key, error) {
	if keyPath == "" {
		return nil, fmt.Errorf("%s private key path not configured", keyType)
	}

	// Load JWK from file
	jwkKey, err := c.loadJWKFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s private key: %w", keyType, err)
	}

	return jwkKey, nil
}

// Close closes the client and cleans up resources
func (c *Client) Close() error {
	if c.redisClient != nil {
		return c.redisClient.Close()
	}
	return nil
}
