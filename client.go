// Package singpass provides a Go client library for Singapore's Singpass OpenID Connect (OIDC) authentication.
// It supports PKCE (Proof Key for Code Exchange) for secure authentication flows and includes
// comprehensive JWT/JWE token validation with JWKS (JSON Web Key Set) support.
package singpass

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid" //nolint:depguard // UUID generation is required for OIDC state
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/redis/go-redis/v9"
)

// Constants for Redis key prefixes and cache intervals
const (
	StateKeyPrefix = "singpass:state:"
	NonceKeyPrefix = "singpass:nonce:"

	// Expiration durations
	stateExpiration = 10 * time.Minute
	nonceExpiration = 10 * time.Minute
)

// StateData represents OAuth state information
type StateData struct {
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

// Client represents the Singpass authentication client
type Client struct {
	config      Config
	redisClient *redis.Client
	httpClient  *http.Client
	jwksCache   *jwk.Cache
}

// NewClient creates a new Singpass client with the given configuration
func NewClient(config *Config) (*Client, error) {
	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		return nil, ErrRedisOperation{Operation: "ping", Message: err.Error()}
	}

	// Initialize HTTP client
	httpClient := &http.Client{
		Timeout: config.HTTPTimeout,
	}

	// Initialize JWKS cache
	jwksCache, err := jwk.NewCache(context.Background(), httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS cache: %w", err)
	}

	// Register JWKS URL with cache
	err = jwksCache.Register(context.Background(),
		config.JWKSURL,
		jwk.WithMinInterval(time.Hour),    // min 1 hour
		jwk.WithMaxInterval(24*time.Hour), // max 24 hours
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL in cache: %w", err)
	}

	client := &Client{
		config:      *config,
		redisClient: redisClient,
		httpClient:  httpClient,
		jwksCache:   jwksCache,
	}

	return client, nil
}

// GenerateAuthURL generates the authorization URL for Singpass login
func (c *Client) GenerateAuthURL(ctx context.Context) (string, error) {
	// Generate state and nonce
	state := generateState()
	nonce, err := generateNonce()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, err := generateRandomBase64(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	codeChallenge := c.generateCodeChallenge(codeVerifier)

	// Store state data in Redis
	stateData := &StateData{
		CodeVerifier: codeVerifier,
		Nonce:        nonce,
	}

	if err := c.storeStateData(ctx, state, stateData); err != nil {
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

// HandleCallback handles the OAuth2 callback and returns user information
func (c *Client) HandleCallback(ctx context.Context, code, state string) (*UserInfo, error) {
	// Retrieve and validate state data
	stateData, err := c.getStateData(ctx, state)
	if err != nil {
		return nil, ErrInvalidState{Message: "state not found or expired"}
	}

	// Exchange code for tokens
	tokenResp, err := c.exchangeCodeForTokens(ctx, code, stateData.CodeVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}

	// Validate ID token (for security, but we'll get user info from UserInfo endpoint)
	_, err = c.validateIDToken(ctx, tokenResp.IDToken, stateData.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to validate ID token: %w", err)
	}

	// Get user info from UserInfo endpoint using access token
	userInfo, err := c.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Clean up state data
	c.deleteStateData(ctx, state)

	return userInfo, nil
}

// generateRandomString generates a cryptographically secure random string
func (c *Client) generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// generateRandomBase64 generates a base64 encoded random string
func generateRandomBase64(byteLength int) (string, error) {
	bytes := make([]byte, byteLength)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// generateState generates a unique state parameter
func generateState() string {
	return uuid.New().String()
}

// generateNonce generates a random nonce
func generateNonce() (string, error) {
	return generateRandomBase64(16)
}

// generateCodeChallenge generates PKCE code challenge from verifier
func (c *Client) generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	encoded := base64.URLEncoding.EncodeToString(hash[:])
	return strings.TrimRight(encoded, "=")
}

// storeStateData stores state data in Redis
func (c *Client) storeStateData(ctx context.Context, state string, stateData *StateData) error {
	data, err := json.Marshal(stateData)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s%s", StateKeyPrefix, state)
	err = c.redisClient.Set(ctx, key, data, stateExpiration).Err()
	if err != nil {
		return ErrRedisOperation{Operation: "set", Message: err.Error()}
	}

	return nil
}

// getStateData retrieves state data from Redis
func (c *Client) getStateData(ctx context.Context, state string) (*StateData, error) {
	key := fmt.Sprintf("%s%s", StateKeyPrefix, state)
	data, err := c.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrInvalidState{Message: "state not found"}
		}
		return nil, ErrRedisOperation{Operation: "get", Message: err.Error()}
	}

	var stateData StateData
	if err := json.Unmarshal([]byte(data), &stateData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state data: %w", err)
	}

	return &stateData, nil
}

// deleteStateData removes state data from Redis
func (c *Client) deleteStateData(ctx context.Context, state string) {
	key := fmt.Sprintf("%s%s", StateKeyPrefix, state)
	c.redisClient.Del(ctx, key)
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
		return nil, ErrHTTPRequest{StatusCode: resp.StatusCode, Message: string(body)}
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token response: %w", err)
	}

	return &tokenResp, nil
}

// validateIDToken validates the ID token and extracts user information
func (c *Client) validateIDToken(ctx context.Context, idToken, expectedNonce string) (*UserInfo, error) {
	// Parse and validate token
	claims, err := c.parseAndValidateToken(ctx, idToken)
	if err != nil {
		return nil, err
	}

	// Validate token claims
	if err := c.validateTokenClaims(claims, expectedNonce); err != nil {
		return nil, err
	}

	// Extract user information
	return c.extractUserInfoFromClaims(claims), nil
}

// parseAndValidateToken parses and validates the JWT token
func (c *Client) parseAndValidateToken(ctx context.Context, idToken string) (map[string]interface{}, error) {
	// Get JWKS
	jwks, err := c.getJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Verify the JWS token with algorithm inference
	buf, err := jws.Verify([]byte(idToken), jws.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		return nil, ErrTokenValidation{Message: err.Error()}
	}

	// Parse claims from verified payload
	var claims map[string]interface{}
	if err := json.Unmarshal(buf, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	return claims, nil
}

// validateTokenClaims validates the token claims
func (c *Client) validateTokenClaims(claims map[string]interface{}, expectedNonce string) error {
	// Validate issuer
	issuer, ok := claims["iss"].(string)
	if !ok || issuer != c.config.Issuer {
		return ErrTokenValidation{Message: "invalid issuer"}
	}

	// Validate audience
	audience, ok := claims["aud"].(string)
	if !ok || audience != c.config.ClientID {
		return ErrTokenValidation{Message: "invalid audience"}
	}

	// Validate expiration
	exp, ok := claims["exp"].(float64)
	if !ok || float64(time.Now().Unix()) >= exp {
		return ErrTokenValidation{Message: "token has expired"}
	}

	// Validate issued at
	iat, ok := claims["iat"].(float64)
	if !ok || float64(time.Now().Unix()) < iat {
		return ErrTokenValidation{Message: "token issued in the future"}
	}

	// Validate nonce
	tokenNonce, ok := claims["nonce"].(string)
	if !ok || tokenNonce != expectedNonce {
		return ErrTokenValidation{Message: "invalid nonce"}
	}

	return nil
}

// extractUserInfoFromClaims extracts user information from the claims
func (c *Client) extractUserInfoFromClaims(claims map[string]interface{}) *UserInfo {
	userInfo := &UserInfo{}

	if issuer, ok := claims["iss"].(string); ok {
		userInfo.Iss = issuer
	}

	if subject, ok := claims["sub"].(string); ok {
		userInfo.Sub = subject
	}

	if iat, ok := claims["iat"].(float64); ok {
		userInfo.Iat = int64(iat)
	}

	if exp, ok := claims["exp"].(float64); ok {
		userInfo.Exp = int64(exp)
	}

	if audience, ok := claims["aud"].(string); ok {
		userInfo.Aud = audience
	}

	// Extract custom claims
	c.extractCustomClaimsFromMap(claims, userInfo)
	// Extract address information
	c.extractAddressInfoFromMap(claims, userInfo)

	return userInfo
}

// extractCustomClaimsFromMap extracts custom claims from the claims map
func (c *Client) extractCustomClaimsFromMap(claims map[string]interface{}, userInfo *UserInfo) {
	// Extract custom claims
	if name, ok := claims["name"].(string); ok {
		userInfo.Name = ValueField{Value: name}
	}

	if uinfin, ok := claims["uinfin"].(string); ok {
		userInfo.UINFIN = ValueField{Value: uinfin}
	}

	if sex, ok := claims["sex"].(string); ok {
		userInfo.Sex = CodedField{Code: sex}
	}

	if dob, ok := claims["dob"].(string); ok {
		userInfo.DOB = ValueField{Value: dob}
	}

	if nationality, ok := claims["nationality"].(string); ok {
		userInfo.Nationality = CodedField{Code: nationality}
	}

	if mobile, ok := claims["mobileno"].(string); ok {
		userInfo.MobileNo = PhoneField{Number: ValueWrapper{Value: mobile}}
	}

	if email, ok := claims["email"].(string); ok {
		userInfo.Email = ValueField{Value: email}
	}
}

// extractAddressInfoFromMap extracts address information from the claims map
func (c *Client) extractAddressInfoFromMap(claims map[string]interface{}, userInfo *UserInfo) {
	if regAddr, ok := claims["regadd"].(map[string]interface{}); ok {
		address := RegisteredAddress{}
		if addrType, ok := regAddr["type"].(string); ok {
			address.Type = addrType
		}
		if country, ok := regAddr["country"].(map[string]interface{}); ok {
			if code, ok := country["code"].(string); ok {
				address.Country.Code = code
			}
			if desc, ok := country["desc"].(string); ok {
				address.Country.Desc = desc
			}
		}
		if unit, ok := regAddr["unit"].(string); ok {
			address.Unit = ValueWrapper{Value: unit}
		}
		if floor, ok := regAddr["floor"].(string); ok {
			address.Floor = ValueWrapper{Value: floor}
		}
		if block, ok := regAddr["block"].(string); ok {
			address.Block = ValueWrapper{Value: block}
		}
		if building, ok := regAddr["building"].(string); ok {
			address.Building = ValueWrapper{Value: building}
		}
		if street, ok := regAddr["street"].(string); ok {
			address.Street = ValueWrapper{Value: street}
		}
		if postal, ok := regAddr["postal"].(string); ok {
			address.Postal = ValueWrapper{Value: postal}
		}
		userInfo.RegAdd = address
	}
}

// getJWKS retrieves the JWKS from cache or fetches it
func (c *Client) getJWKS(ctx context.Context) (jwk.Set, error) {
	jwks, err := c.jwksCache.Lookup(ctx, c.config.JWKSURL)
	if err != nil {
		return nil, ErrJWKSFetch{Message: err.Error()}
	}
	return jwks, nil
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

	// Create and sign JWT
	token, err := jwt.NewBuilder().
		Claim("iss", claims["iss"]).
		Claim("sub", claims["sub"]).
		Claim("aud", claims["aud"]).
		Claim("jti", claims["jti"]).
		Claim("iat", claims["iat"]).
		Claim("exp", claims["exp"]).
		Build()
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
	if c.config.SigPrivateKeyPath == "" {
		return nil, fmt.Errorf("signature private key path not configured")
	}

	// Load JWK from file
	jwkKey, err := c.loadJWKFromFile(c.config.SigPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	return jwkKey, nil
}

// loadEncryptionPrivateKey loads the encryption private key from file
func (c *Client) loadEncryptionPrivateKey() (jwk.Key, error) {
	if c.config.EncPrivateKeyPath == "" {
		return nil, fmt.Errorf("encryption private key path not configured")
	}

	// Load JWK from file
	jwkKey, err := c.loadJWKFromFile(c.config.EncPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load encryption private key: %w", err)
	}

	return jwkKey, nil
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
	// Load encryption private key for decryption
	privateKey, err := c.loadEncryptionPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load encryption private key: %w", err)
	}

	alg, ok := privateKey.Algorithm()
	if !ok {
		return nil, fmt.Errorf("invalid encryption algorithm")
	}

	// Decrypt JWE
	decrypted, err := jwe.Decrypt(encryptedData, jwe.WithKey(alg, privateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt JWE: %w", err)
	}

	// The decrypted content might be a JWS, verify it
	verified, err := c.verifyJWS(decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWS: %w", err)
	}

	return verified, nil
}

// verifyJWS verifies JWS signature
func (c *Client) verifyJWS(jwsData []byte) ([]byte, error) {
	// Get JWKS for verification
	jwks, err := c.getJWKS(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Verify JWS with algorithm inference
	verified, err := jws.Verify(jwsData, jws.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWS: %w", err)
	}

	return verified, nil
}

// Close closes the client and cleans up resources
func (c *Client) Close() error {
	if c.redisClient != nil {
		return c.redisClient.Close()
	}
	return nil
}
