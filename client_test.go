package singpass

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vector233/go-singpass/internal/constants"
	"github.com/vector233/go-singpass/internal/utils"
)

func TestConfig_SetDefaults(t *testing.T) {
	config := &Config{}
	config.SetDefaults()

	if config.StateExpiration != 10*time.Minute {
		t.Errorf("Expected StateExpiration to be 10m, got %v", config.StateExpiration)
	}
	if config.NonceExpiration != 10*time.Minute {
		t.Errorf("Expected NonceExpiration to be 10m, got %v", config.NonceExpiration)
	}
	if config.JWKSCacheTTL != 24*time.Hour {
		t.Errorf("Expected JWKSCacheTTL to be 24h, got %v", config.JWKSCacheTTL)
	}
	if config.HTTPTimeout != 30*time.Second {
		t.Errorf("Expected HTTPTimeout to be 30s, got %v", config.HTTPTimeout)
	}
	if config.Scope != "openid profile" {
		t.Errorf("Expected Scope to be 'openid profile', got %s", config.Scope)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				ClientID:    "test-client",
				RedirectURI: "http://localhost:8080/callback",
				AuthURL:     "https://example.com/auth",
				TokenURL:    "https://example.com/token",
				UserInfoURL: "https://example.com/userinfo",
				JWKSURL:     "https://example.com/jwks",
				RedisAddr:   "localhost:6379",
			},
			wantErr: false,
		},
		{
			name: "missing client ID",
			config: Config{
				RedirectURI: "http://localhost:8080/callback",
				AuthURL:     "https://example.com/auth",
				TokenURL:    "https://example.com/token",
				UserInfoURL: "https://example.com/userinfo",
				JWKSURL:     "https://example.com/jwks",
				RedisAddr:   "localhost:6379",
			},
			wantErr: true,
		},
		{
			name: "missing redis addr",
			config: Config{
				ClientID:    "test-client",
				RedirectURI: "http://localhost:8080/callback",
				AuthURL:     "https://example.com/auth",
				TokenURL:    "https://example.com/token",
				UserInfoURL: "https://example.com/userinfo",
				JWKSURL:     "https://example.com/jwks",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUserInfo_GetAddress(t *testing.T) {
	tests := []struct {
		name     string
		userInfo UserInfo
		want     string
	}{
		{
			name:     "no address",
			userInfo: UserInfo{},
			want:     "",
		},
		{
			name: "full address",
			userInfo: UserInfo{
				RegAdd: RegisteredAddress{
					Block:    ValueWrapper{Value: "123"},
					Unit:     ValueWrapper{Value: "12-34"},
					Building: ValueWrapper{Value: "Test Building"},
					Street:   ValueWrapper{Value: "Test Street"},
					Postal:   ValueWrapper{Value: "123456"},
				},
			},
			want: "123 Test Street #12-34 Test Building Singapore 123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.userInfo.GetAddress()
			if got != tt.want {
				t.Errorf("UserInfo.GetAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthState_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		authState AuthState
		want      bool
	}{
		{
			name: "not expired",
			authState: AuthState{
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			want: false,
		},
		{
			name: "expired",
			authState: AuthState{
				ExpiresAt: time.Now().Add(-5 * time.Minute),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.authState.IsExpired()
			if got != tt.want {
				t.Errorf("AuthState.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Integration test helper - requires Redis to be running
func setupTestClient(t *testing.T) *Client {
	// Skip if Redis is not available
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15, // Use test database
	})

	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping integration test")
	}
	rdb.Close()

	// Use Singpass staging endpoints for testing
	config := Config{
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/callback",
		AuthURL:     "https://stg-id.singpass.gov.sg/auth",
		TokenURL:    "https://stg-id.singpass.gov.sg/token",
		UserInfoURL: "https://stg-id.singpass.gov.sg/userinfo",
		JWKSURL:     "https://stg-id.singpass.gov.sg/.well-known/keys",
		Issuer:      "https://stg-id.singpass.gov.sg",
		RedisAddr:   "localhost:6379",
		RedisDB:     15,
	}

	client, err := NewClient(&config)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	t.Cleanup(func() {
		client.Close()
	})

	return client
}

func TestClient_GenerateAuthURL(t *testing.T) {
	client := setupTestClient(t)

	authURL, err := client.GenerateAuthURL(context.Background())
	if err != nil {
		t.Fatalf("GenerateAuthURL() error = %v", err)
	}

	if authURL == "" {
		t.Error("GenerateAuthURL() returned empty URL")
	}

	// Basic URL validation
	if !strings.Contains(authURL, "response_type=code") {
		t.Error("Auth URL should contain response_type=code")
	}
	if !strings.Contains(authURL, "client_id=test-client") {
		t.Error("Auth URL should contain client_id")
	}
	if !strings.Contains(authURL, "code_challenge") {
		t.Error("Auth URL should contain code_challenge for PKCE")
	}
}

// Mock HTTP server for testing token exchange
func TestClient_ExchangeCodeForToken(t *testing.T) {
	// Skip this test as it requires complex JWKS mocking
	t.Skip("Skipping token exchange test - requires JWKS server mocking")

	// Create mock token response
	mockResponse := TokenResponse{
		AccessToken: "mock-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		IDToken:     "mock-id-token",
		Scope:       "openid profile",
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	// Setup client with mock server
	config := &Config{
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/callback",
		AuthURL:     "https://test.singpass.gov.sg/authorize",
		TokenURL:    server.URL,
		UserInfoURL: "https://test.singpass.gov.sg/userinfo",
		JWKSURL:     "https://test.singpass.gov.sg/.well-known/jwks",
		RedisAddr:   "localhost:6379",
		RedisDB:     15,
	}
	config.SetDefaults()

	client, err := NewClient(config)
	require.NoError(t, err)
	defer client.Close()

	// First generate auth URL to create state
	_, err = client.GenerateAuthURL(context.Background())
	require.NoError(t, err)

	// Test token exchange (this will fail without proper state, but tests the HTTP call)
	ctx := context.Background()
	_, err = client.exchangeCodeForTokens(ctx, "test-code", "test-verifier")
	// We expect an error here since we don't have proper state setup
	assert.Error(t, err)
}

// Test PKCE code generation
func TestPKCEGeneration(t *testing.T) {
	// Test code verifier generation
	codeVerifier, err := utils.GenerateRandomBase64(32)
	require.NoError(t, err)
	assert.NotEmpty(t, codeVerifier)

	// Test code challenge generation
	codeChallenge := utils.GenerateCodeChallenge(codeVerifier)
	assert.NotEmpty(t, codeChallenge)
	assert.NotEqual(t, codeVerifier, codeChallenge)

	// Test that different verifiers produce different challenges
	codeVerifier2, err := utils.GenerateRandomBase64(32)
	require.NoError(t, err)
	codeChallenge2 := utils.GenerateCodeChallenge(codeVerifier2)
	assert.NotEqual(t, codeChallenge, codeChallenge2)
}

// Test environment configurations
func TestEnvironmentConfigs(t *testing.T) {
	// Test sandbox config
	sandboxConfig := SandboxConfig()
	assert.Equal(t, constants.EnvironmentSandbox, sandboxConfig.Environment)
	assert.True(t, sandboxConfig.IsSandbox())
	assert.False(t, sandboxConfig.IsProduction())
	assert.Contains(t, sandboxConfig.AuthURL, "stg-id.singpass.gov.sg")

	// Test production config
	prodConfig := ProductionConfig()
	assert.Equal(t, constants.EnvironmentProduction, prodConfig.Environment)
	assert.False(t, prodConfig.IsSandbox())
	assert.True(t, prodConfig.IsProduction())
	assert.Contains(t, prodConfig.AuthURL, "id.singpass.gov.sg")
	assert.NotContains(t, prodConfig.AuthURL, "stg-")
}

// Test UserInfo methods
func TestUserInfo_Methods(t *testing.T) {
	userInfo := &UserInfo{
		Name: ValueField{
			Value:          "John Doe",
			LastUpdated:    "2023-01-01",
			Source:         "1",
			Classification: "C",
		},
		UINFIN: ValueField{
			Value:          "S1234567A",
			LastUpdated:    "2023-01-01",
			Source:         "1",
			Classification: "C",
		},
		RegAdd: RegisteredAddress{
			Block:    ValueWrapper{Value: "123"},
			Street:   ValueWrapper{Value: "Main Street"},
			Unit:     ValueWrapper{Value: "01-01"},
			Building: ValueWrapper{Value: "Test Building"},
			Postal:   ValueWrapper{Value: "123456"},
		},
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	// Test getter methods
	assert.Equal(t, "John Doe", userInfo.GetName())
	assert.Equal(t, "S1234567A", userInfo.GetUINFIN())
	assert.False(t, userInfo.IsExpired())

	// Test address formatting
	address := userInfo.GetAddress()
	assert.Contains(t, address, "123")
	assert.Contains(t, address, "Main Street")
	assert.Contains(t, address, "#01-01")
	assert.Contains(t, address, "Test Building")
	assert.Contains(t, address, "Singapore 123456")

	// Test expired user info
	userInfo.Exp = time.Now().Add(-time.Hour).Unix()
	assert.True(t, userInfo.IsExpired())
}
