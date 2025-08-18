package singpass

import (
	"time"
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
		c.Scope = "openid profile"
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
	return nil
}
