// Package singpass provides configuration management for Singpass OIDC authentication.
package singpass

import (
	"fmt"
	"time"

	"github.com/vector233/go-singpass/internal/constants"
	"github.com/vector233/go-singpass/internal/errors"
)

// Config holds the configuration for Singpass authentication
type Config struct {
	// OAuth2/OIDC Configuration
	ClientID    string `json:"client_id"`
	Scope       string `json:"scope"`
	Issuer      string `json:"issuer"`
	RedirectURI string `json:"redirect_uri"`
	AuthURL     string `json:"auth_url"`
	TokenURL    string `json:"token_url"`
	UserInfoURL string `json:"userinfo_url"`
	JWKSURL     string `json:"jwks_url"`

	// Cryptographic Keys
	SigPrivateKeyPath string `json:"sig_private_key_path,omitempty"`
	EncPrivateKeyPath string `json:"enc_private_key_path,omitempty"`

	// Redis Configuration for state management
	RedisAddr     string `json:"redis_addr"`
	RedisPassword string `json:"redis_password,omitempty"`
	RedisDB       int    `json:"redis_db"`

	// Timeouts and Expiration
	StateExpiration time.Duration `json:"state_expiration,omitempty"`
	NonceExpiration time.Duration `json:"nonce_expiration,omitempty"`
	JWKSCacheTTL    time.Duration `json:"jwks_cache_ttl,omitempty"`
	HTTPTimeout     time.Duration `json:"http_timeout,omitempty"`

	// Environment
	Environment string `json:"environment,omitempty"`
}

// SetDefaults sets default values for optional configuration fields
func (c *Config) SetDefaults() {
	if c.StateExpiration == 0 {
		c.StateExpiration = constants.DefaultStateExpiration
	}
	if c.NonceExpiration == 0 {
		c.NonceExpiration = constants.DefaultNonceExpiration
	}
	if c.JWKSCacheTTL == 0 {
		c.JWKSCacheTTL = constants.DefaultJWKSCacheTTL
	}
	if c.HTTPTimeout == 0 {
		c.HTTPTimeout = constants.DefaultHTTPTimeout
	}
	if c.Scope == "" {
		c.Scope = constants.DefaultScope
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return errors.ErrInvalidConfig{Field: "ClientID"}
	}
	if c.RedirectURI == "" {
		return errors.ErrInvalidConfig{Field: "RedirectURI"}
	}
	if c.AuthURL == "" {
		return errors.ErrInvalidConfig{Field: "AuthURL"}
	}
	if c.TokenURL == "" {
		return errors.ErrInvalidConfig{Field: "TokenURL"}
	}
	if c.UserInfoURL == "" {
		return errors.ErrInvalidConfig{Field: "UserInfoURL"}
	}
	if c.JWKSURL == "" {
		return errors.ErrInvalidConfig{Field: "JWKSURL"}
	}
	if c.RedisAddr == "" {
		return errors.ErrInvalidConfig{Field: "RedisAddr"}
	}
	if c.Environment != "" && c.Environment != constants.EnvironmentSandbox && c.Environment != constants.EnvironmentProduction {
		return fmt.Errorf("environment must be '%s' or '%s', got: %s", constants.EnvironmentSandbox, constants.EnvironmentProduction, c.Environment)
	}
	return nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	config := &Config{
		Scope:           constants.DefaultScope,
		StateExpiration: constants.DefaultStateExpiration,
		NonceExpiration: constants.DefaultNonceExpiration,
		JWKSCacheTTL:    constants.DefaultJWKSCacheTTL,
		HTTPTimeout:     constants.DefaultHTTPTimeout,
		Environment:     constants.EnvironmentSandbox,
		RedisDB:         0,
	}
	return config
}

// SandboxConfig returns a configuration for sandbox environment
func SandboxConfig() *Config {
	config := DefaultConfig()
	config.Environment = constants.EnvironmentSandbox
	config.AuthURL = constants.SandboxAuthURL
	config.TokenURL = constants.SandboxTokenURL
	config.UserInfoURL = constants.SandboxUserInfoURL
	config.JWKSURL = constants.SandboxJWKSURL
	return config
}

// ProductionConfig returns a configuration for production environment
func ProductionConfig() *Config {
	config := DefaultConfig()
	config.Environment = constants.EnvironmentProduction
	config.AuthURL = constants.ProductionAuthURL
	config.TokenURL = constants.ProductionTokenURL
	config.UserInfoURL = constants.ProductionUserInfoURL
	config.JWKSURL = constants.ProductionJWKSURL
	return config
}

// IsSandbox returns true if the configuration is for sandbox environment
func (c *Config) IsSandbox() bool {
	return c.Environment == constants.EnvironmentSandbox
}

// IsProduction returns true if the configuration is for production environment
func (c *Config) IsProduction() bool {
	return c.Environment == constants.EnvironmentProduction
}

// GetRedisKeyPrefix returns the Redis key prefix based on environment
func (c *Config) GetRedisKeyPrefix() string {
	if c.IsSandbox() {
		return "singpass:sandbox:"
	}
	return "singpass:prod:"
}
