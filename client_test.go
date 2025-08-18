package singpass

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
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

func TestUserInfo_GetFormattedAddress(t *testing.T) {
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
				RegisteredAddress: &Address{
					Type:       "SG",
					Country:    "SG",
					Unit:       "12-34",
					Floor:      "12",
					Block:      "123",
					Building:   "Test Building",
					Street:     "Test Street",
					PostalCode: "123456",
				},
			},
			want: "Unit 12-34, Floor 12, Block 123, Test Building, Test Street, Singapore 123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.userInfo.GetFormattedAddress()
			if got != tt.want {
				t.Errorf("UserInfo.GetFormattedAddress() = %v, want %v", got, tt.want)
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

	client, err := NewClient(config)
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
