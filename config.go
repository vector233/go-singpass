// Package singpass provides configuration management for Singpass OIDC authentication.
package singpass

import (
	"fmt"
	"time"
)

// Default configuration values
const (
	DefaultScope = "openid profile"

	// Environment constants
	EnvironmentSandbox    = "sandbox"
	EnvironmentProduction = "production"

	// Singpass URLs
	SandboxAuthURL     = "https://stg-id.singpass.gov.sg/auth"
	SandboxTokenURL    = "https://stg-id.singpass.gov.sg/token" // #nosec G101 -- This is a public URL, not a credential
	SandboxUserInfoURL = "https://stg-id.singpass.gov.sg/userinfo"
	SandboxJWKSURL     = "https://stg-id.singpass.gov.sg/.well-known/keys"

	ProductionAuthURL     = "https://id.singpass.gov.sg/auth"
	ProductionTokenURL    = "https://id.singpass.gov.sg/token" // #nosec G101 -- This is a public URL, not a credential
	ProductionUserInfoURL = "https://id.singpass.gov.sg/userinfo"
	ProductionJWKSURL     = "https://id.singpass.gov.sg/.well-known/keys"
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
		c.StateExpiration = 10 * time.Minute
	}
	if c.NonceExpiration == 0 {
		c.NonceExpiration = 10 * time.Minute
	}
	if c.JWKSCacheTTL == 0 {
		c.JWKSCacheTTL = 24 * time.Hour
	}
	if c.HTTPTimeout == 0 {
		c.HTTPTimeout = 30 * time.Second
	}
	if c.Scope == "" {
		c.Scope = DefaultScope
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return ErrInvalidConfig{Field: "ClientID"}
	}
	if c.RedirectURI == "" {
		return ErrInvalidConfig{Field: "RedirectURI"}
	}
	if c.AuthURL == "" {
		return ErrInvalidConfig{Field: "AuthURL"}
	}
	if c.TokenURL == "" {
		return ErrInvalidConfig{Field: "TokenURL"}
	}
	if c.UserInfoURL == "" {
		return ErrInvalidConfig{Field: "UserInfoURL"}
	}
	if c.JWKSURL == "" {
		return ErrInvalidConfig{Field: "JWKSURL"}
	}
	if c.RedisAddr == "" {
		return ErrInvalidConfig{Field: "RedisAddr"}
	}
	if c.Environment != "" && c.Environment != EnvironmentSandbox && c.Environment != EnvironmentProduction {
		return fmt.Errorf("environment must be '%s' or '%s', got: %s", EnvironmentSandbox, EnvironmentProduction, c.Environment)
	}
	return nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	config := &Config{
		Scope:           DefaultScope,
		StateExpiration: 10 * time.Minute,
		NonceExpiration: 10 * time.Minute,
		JWKSCacheTTL:    24 * time.Hour,
		HTTPTimeout:     30 * time.Second,
		Environment:     EnvironmentSandbox,
		RedisDB:         0,
	}
	return config
}

// SandboxConfig returns a configuration for sandbox environment
func SandboxConfig() *Config {
	config := DefaultConfig()
	config.Environment = EnvironmentSandbox
	config.AuthURL = SandboxAuthURL
	config.TokenURL = SandboxTokenURL
	config.UserInfoURL = SandboxUserInfoURL
	config.JWKSURL = SandboxJWKSURL
	return config
}

// ProductionConfig returns a configuration for production environment
func ProductionConfig() *Config {
	config := DefaultConfig()
	config.Environment = EnvironmentProduction
	config.AuthURL = ProductionAuthURL
	config.TokenURL = ProductionTokenURL
	config.UserInfoURL = ProductionUserInfoURL
	config.JWKSURL = ProductionJWKSURL
	return config
}

// IsSandbox returns true if the configuration is for sandbox environment
func (c *Config) IsSandbox() bool {
	return c.Environment == EnvironmentSandbox
}

// IsProduction returns true if the configuration is for production environment
func (c *Config) IsProduction() bool {
	return c.Environment == EnvironmentProduction
}

// GetRedisKeyPrefix returns the Redis key prefix based on environment
func (c *Config) GetRedisKeyPrefix() string {
	if c.IsSandbox() {
		return "singpass:sandbox:"
	}
	return "singpass:prod:"
}
