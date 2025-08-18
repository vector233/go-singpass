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
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
)

// Client represents the Singpass authentication client
type Client struct {
	config      Config
	redisClient *redis.Client
	httpClient  *http.Client
	jwksCache   jwk.Cache
}

// NewClient creates a new Singpass client with the given configuration
func NewClient(config Config) (*Client, error) {
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
	jwksCache := jwk.NewCache(context.Background())

	client := &Client{
		config:      config,
		redisClient: redisClient,
		httpClient:  httpClient,
		jwksCache:   *jwksCache,
	}

	// Pre-fetch JWKS
	if err := client.refreshJWKS(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	return client, nil
}

// GenerateAuthURL generates the authorization URL for Singpass login
func (c *Client) GenerateAuthURL(ctx context.Context) (string, error) {
	// Generate state and nonce
	state, err := c.generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	nonce, err := c.generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, err := c.generateRandomString(128)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	codeChallenge := c.generateCodeChallenge(codeVerifier)

	// Store auth state in Redis
	authState := &AuthState{
		State:         state,
		Nonce:         nonce,
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(c.config.StateExpiration),
	}

	if err := c.storeAuthState(ctx, state, authState); err != nil {
		return "", fmt.Errorf("failed to store auth state: %w", err)
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
	// Retrieve and validate auth state
	authState, err := c.getAuthState(ctx, state)
	if err != nil {
		return nil, ErrInvalidState{Message: "state not found or expired"}
	}

	if authState.IsExpired() {
		return nil, ErrInvalidState{Message: "state expired"}
	}

	// Exchange code for tokens
	tokenResp, err := c.exchangeCodeForTokens(ctx, code, authState.CodeVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}

	// Validate and parse ID token
	userInfo, err := c.validateIDToken(ctx, tokenResp.IDToken, authState.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to validate ID token: %w", err)
	}

	// Clean up auth state
	c.deleteAuthState(ctx, state)

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

// generateCodeChallenge generates PKCE code challenge from verifier
func (c *Client) generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	encoded := base64.URLEncoding.EncodeToString(hash[:])
	return strings.TrimRight(encoded, "=")
}

// storeAuthState stores auth state in Redis
func (c *Client) storeAuthState(ctx context.Context, state string, authState *AuthState) error {
	data, err := json.Marshal(authState)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("singpass:state:%s", state)
	err = c.redisClient.Set(ctx, key, data, c.config.StateExpiration).Err()
	if err != nil {
		return ErrRedisOperation{Operation: "set", Message: err.Error()}
	}

	return nil
}

// getAuthState retrieves auth state from Redis
func (c *Client) getAuthState(ctx context.Context, state string) (*AuthState, error) {
	key := fmt.Sprintf("singpass:state:%s", state)
	data, err := c.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrInvalidState{Message: "state not found"}
		}
		return nil, ErrRedisOperation{Operation: "get", Message: err.Error()}
	}

	var authState AuthState
	if err := json.Unmarshal([]byte(data), &authState); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth state: %w", err)
	}

	return &authState, nil
}

// deleteAuthState removes auth state from Redis
func (c *Client) deleteAuthState(ctx context.Context, state string) {
	key := fmt.Sprintf("singpass:state:%s", state)
	c.redisClient.Del(ctx, key)
}

// exchangeCodeForTokens exchanges authorization code for tokens
func (c *Client) exchangeCodeForTokens(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {c.config.ClientID},
		"code":          {code},
		"redirect_uri":  {c.config.RedirectURI},
		"code_verifier": {codeVerifier},
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
	defer resp.Body.Close()

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
	// Get JWKS
	jwks, err := c.getJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Parse and validate token
	token, err := jwt.Parse([]byte(idToken), jwt.WithKeySet(jwks), jwt.WithValidate(true))
	if err != nil {
		return nil, ErrTokenValidation{Message: err.Error()}
	}

	// Validate issuer
	if token.Issuer() != c.config.Issuer {
		return nil, ErrTokenValidation{Message: "invalid issuer"}
	}

	// Validate audience
	if !c.validateAudience(token.Audience(), c.config.ClientID) {
		return nil, ErrTokenValidation{Message: "invalid audience"}
	}

	// Validate nonce
	nonce, ok := token.Get("nonce")
	if !ok || nonce != expectedNonce {
		return nil, ErrTokenValidation{Message: "invalid nonce"}
	}

	// Extract user information
	userInfo := &UserInfo{
		Issuer:   token.Issuer(),
		Subject:  token.Subject(),
		IssuedAt: token.IssuedAt().Unix(),
	}

	if !token.Expiration().IsZero() {
		userInfo.ExpiresAt = token.Expiration().Unix()
	}

	if aud := token.Audience(); len(aud) > 0 {
		userInfo.Audience = aud[0]
	}

	// Extract custom claims
	if name, ok := token.Get("name"); ok {
		if nameStr, ok := name.(string); ok {
			userInfo.Name = nameStr
		}
	}

	if uinfin, ok := token.Get("uinfin"); ok {
		if uinfinStr, ok := uinfin.(string); ok {
			userInfo.UINFIN = uinfinStr
		}
	}

	if sex, ok := token.Get("sex"); ok {
		if sexStr, ok := sex.(string); ok {
			userInfo.Sex = sexStr
		}
	}

	if dob, ok := token.Get("date_of_birth"); ok {
		if dobStr, ok := dob.(string); ok {
			userInfo.DateOfBirth = dobStr
		}
	}

	if nationality, ok := token.Get("nationality"); ok {
		if nationalityStr, ok := nationality.(string); ok {
			userInfo.Nationality = nationalityStr
		}
	}

	if mobile, ok := token.Get("mobileno"); ok {
		if mobileStr, ok := mobile.(string); ok {
			userInfo.MobileNumber = mobileStr
		}
	}

	if email, ok := token.Get("email"); ok {
		if emailStr, ok := email.(string); ok {
			userInfo.Email = emailStr
		}
	}

	// Extract address information
	if regAddr, ok := token.Get("registered_address"); ok {
		if addrMap, ok := regAddr.(map[string]interface{}); ok {
			address := &Address{}
			if addrType, ok := addrMap["type"].(string); ok {
				address.Type = addrType
			}
			if country, ok := addrMap["country"].(string); ok {
				address.Country = country
			}
			if unit, ok := addrMap["unit"].(string); ok {
				address.Unit = unit
			}
			if floor, ok := addrMap["floor"].(string); ok {
				address.Floor = floor
			}
			if block, ok := addrMap["block"].(string); ok {
				address.Block = block
			}
			if building, ok := addrMap["building"].(string); ok {
				address.Building = building
			}
			if street, ok := addrMap["street"].(string); ok {
				address.Street = street
			}
			if postal, ok := addrMap["postal"].(string); ok {
				address.PostalCode = postal
			}
			userInfo.RegisteredAddress = address
		}
	}

	return userInfo, nil
}

// validateAudience validates the token audience
func (c *Client) validateAudience(audiences []string, expectedAudience string) bool {
	for _, aud := range audiences {
		if aud == expectedAudience {
			return true
		}
	}
	return false
}

// getJWKS retrieves the JWKS from cache or fetches it
func (c *Client) getJWKS(ctx context.Context) (jwk.Set, error) {
	jwks, err := c.jwksCache.Get(ctx, c.config.JWKSURL)
	if err != nil {
		return nil, ErrJWKSFetch{Message: err.Error()}
	}
	return jwks, nil
}

// refreshJWKS refreshes the JWKS cache
func (c *Client) refreshJWKS(ctx context.Context) error {
	err := c.jwksCache.Register(c.config.JWKSURL, jwk.WithMinRefreshInterval(c.config.JWKSCacheTTL))
	if err != nil {
		return ErrJWKSFetch{Message: err.Error()}
	}

	_, err = c.jwksCache.Refresh(ctx, c.config.JWKSURL)
	if err != nil {
		return ErrJWKSFetch{Message: err.Error()}
	}

	return nil
}

// Close closes the client and cleans up resources
func (c *Client) Close() error {
	if c.redisClient != nil {
		return c.redisClient.Close()
	}
	return nil
}
