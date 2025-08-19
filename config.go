// Package singpass provides configuration management for Singpass OIDC authentication.
package singpass

import (
	"fmt"
	"time"

	"github.com/vector233/go-singpass/internal/constants"
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

	// State Storage Configuration
	UseRedis      bool   `json:"use_redis,omitempty"`      // Whether to use Redis for state storage (default: false, uses memory)
	RedisAddr     string `json:"redis_addr,omitempty"`     // Redis address (only used when UseRedis is true)
	RedisPassword string `json:"redis_password,omitempty"` // Redis password (optional)
	RedisDB       int    `json:"redis_db,omitempty"`       // Redis database number (optional)

	// Timeouts and Expiration
	StateExpiration time.Duration `json:"state_expiration,omitempty"`
	NonceExpiration time.Duration `json:"nonce_expiration,omitempty"`
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
		return fmt.Errorf("invalid config: ClientID is required")
	}
	if c.RedirectURI == "" {
		return fmt.Errorf("invalid config: RedirectURI is required")
	}
	if c.AuthURL == "" {
		return fmt.Errorf("invalid config: AuthURL is required")
	}
	if c.TokenURL == "" {
		return fmt.Errorf("invalid config: TokenURL is required")
	}
	if c.UserInfoURL == "" {
		return fmt.Errorf("invalid config: UserInfoURL is required")
	}
	if c.JWKSURL == "" {
		return fmt.Errorf("invalid config: JWKSURL is required")
	}
	// Only validate Redis configuration if UseRedis is true
	if c.UseRedis && c.RedisAddr == "" {
		return fmt.Errorf("invalid config: RedisAddr is required when UseRedis is true")
	}
	if c.Environment != "" && c.Environment != constants.EnvironmentSandbox && c.Environment != constants.EnvironmentProduction {
		return fmt.Errorf("environment must be '%s' or '%s', got: %s",
			constants.EnvironmentSandbox, constants.EnvironmentProduction, c.Environment)
	}
	return nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	config := &Config{
		Scope:           constants.DefaultScope,
		StateExpiration: constants.DefaultStateExpiration,
		NonceExpiration: constants.DefaultNonceExpiration,
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
