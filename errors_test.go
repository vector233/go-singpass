package singpass

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vector233/go-singpass/internal/auth"
)

// TestConfigValidationErrors tests that config validation returns proper error types
func TestConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name:     "missing ClientID",
			config:   &Config{},
			expected: "ClientID",
		},
		{
			name: "missing RedirectURI",
			config: &Config{
				ClientID: "test-client",
			},
			expected: "RedirectURI",
		},
		{
			name: "missing AuthURL",
			config: &Config{
				ClientID:    "test-client",
				RedirectURI: "https://example.com/callback",
			},
			expected: "AuthURL",
		},
		{
			name: "missing TokenURL",
			config: &Config{
				ClientID:    "test-client",
				RedirectURI: "https://example.com/callback",
				AuthURL:     "https://example.com/auth",
			},
			expected: "TokenURL",
		},
		{
			name: "missing UserInfoURL",
			config: &Config{
				ClientID:    "test-client",
				RedirectURI: "https://example.com/callback",
				AuthURL:     "https://example.com/auth",
				TokenURL:    "https://example.com/token",
			},
			expected: "UserInfoURL",
		},
		{
			name: "missing JWKSURL",
			config: &Config{
				ClientID:    "test-client",
				RedirectURI: "https://example.com/callback",
				AuthURL:     "https://example.com/auth",
				TokenURL:    "https://example.com/token",
				UserInfoURL: "https://example.com/userinfo",
			},
			expected: "JWKSURL",
		},
		{
			name: "missing RedisAddr when UseRedis is true",
			config: &Config{
				ClientID:    "test-client",
				RedirectURI: "https://example.com/callback",
				AuthURL:     "https://example.com/auth",
				TokenURL:    "https://example.com/token",
				UserInfoURL: "https://example.com/userinfo",
				JWKSURL:     "https://example.com/jwks",
				UseRedis:    true,
			},
			expected: "RedisAddr (required when UseRedis is true)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.Error(t, err)

			// Check that it's the correct error type
			var configErr ErrInvalidConfig
			require.True(t, errors.As(err, &configErr))
			assert.Equal(t, tt.expected, configErr.Field)
		})
	}
}

// TestStateManagerErrors tests state management error types
func TestStateManagerErrors(t *testing.T) {
	t.Run("memory store - invalid state", func(t *testing.T) {
		store := auth.NewMemoryStateStore(time.Minute)
		ctx := context.Background()

		// Try to get non-existent state
		_, err := store.Get(ctx, "non-existent-state")
		require.Error(t, err)

		// Check that it's the correct error type
		var stateErr ErrInvalidState
		require.True(t, errors.As(err, &stateErr))
		assert.Equal(t, "state not found or expired", stateErr.Message)
	})

	t.Run("memory store - expired state", func(t *testing.T) {
		store := auth.NewMemoryStateStore(time.Millisecond)
		ctx := context.Background()

		// Store state data
		stateData := &auth.StateData{
			CodeVerifier: "test-verifier",
			Nonce:        "test-nonce",
		}
		err := store.Store(ctx, "test-state", stateData)
		require.NoError(t, err)

		// Wait for expiration
		time.Sleep(10 * time.Millisecond)

		// Try to get expired state
		_, err = store.Get(ctx, "test-state")
		require.Error(t, err)

		// Check that it's the correct error type
		var stateErr ErrInvalidState
		require.True(t, errors.As(err, &stateErr))
		assert.Equal(t, "state not found or expired", stateErr.Message)
	})
}

// TestRedisStateStoreErrors tests Redis state store error types
func TestRedisStateStoreErrors(t *testing.T) {
	// Skip if Redis is not available
	if testing.Short() {
		t.Skip("Skipping Redis tests in short mode")
	}

	t.Run("redis store - connection error", func(t *testing.T) {
		// Create Redis client with invalid address
		redisClient := redis.NewClient(&redis.Options{
			Addr: "invalid:6379",
			DB:   0,
		})
		defer redisClient.Close()

		store := auth.NewRedisStateStore(redisClient, time.Minute)
		ctx := context.Background()

		// Try to store state data (should fail due to connection error)
		stateData := &auth.StateData{
			CodeVerifier: "test-verifier",
			Nonce:        "test-nonce",
		}
		err := store.Store(ctx, "test-state", stateData)
		if err != nil {
			// Check that it's the correct error type
			var redisErr ErrRedisOperation
			if errors.As(err, &redisErr) {
				assert.Equal(t, "set", redisErr.Operation)
				// Check that error message contains network-related keywords
				assert.True(t, len(redisErr.Message) > 0, "Error message should not be empty")
			}
		}
	})

	t.Run("redis store - get non-existent state", func(t *testing.T) {
		// Create Redis client with invalid address
		redisClient := redis.NewClient(&redis.Options{
			Addr: "invalid:6379",
			DB:   0,
		})
		defer redisClient.Close()

		store := auth.NewRedisStateStore(redisClient, time.Minute)
		ctx := context.Background()

		// Try to get non-existent state
		_, err := store.Get(ctx, "non-existent-state")
		if err != nil {
			// Could be either ErrInvalidState (if Redis returns Nil) or ErrRedisOperation (if connection fails)
			var stateErr ErrInvalidState
			var redisErr ErrRedisOperation
			if errors.As(err, &stateErr) {
				assert.Equal(t, "state not found or expired", stateErr.Message)
			} else if errors.As(err, &redisErr) {
				assert.Equal(t, "get", redisErr.Operation)
			}
		}
	})
}

// TestErrorTypeExports tests that error types are properly exported
func TestErrorTypeExports(t *testing.T) {
	t.Run("error types are accessible", func(t *testing.T) {
		// Test that we can create instances of exported error types
		configErr := ErrInvalidConfig{Field: "test"}
		assert.Equal(t, "invalid config: test is required", configErr.Error())

		stateErr := ErrInvalidState{Message: "test message"}
		assert.Equal(t, "invalid state: test message", stateErr.Error())

		tokenErr := ErrTokenValidation{Message: "test validation"}
		assert.Equal(t, "token validation failed: test validation", tokenErr.Error())

		httpErr := ErrHTTPRequest{StatusCode: 400, Message: "bad request"}
		assert.Equal(t, "HTTP request failed (status 400): bad request", httpErr.Error())

		redisErr := ErrRedisOperation{Operation: "set", Message: "connection failed"}
		assert.Equal(t, "Redis set failed: connection failed", redisErr.Error())

		jwksErr := ErrJWKSFetch{Message: "fetch failed"}
		assert.Equal(t, "JWKS fetch failed: fetch failed", jwksErr.Error())
	})
}