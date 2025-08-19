// Package constants defines all constants used in the Singpass client.
package constants

import "time"

// OAuth2/OIDC constants
const (
	// Default scope for Singpass authentication
	DefaultScope = "openid profile"

	// Environment constants
	EnvironmentSandbox    = "sandbox"
	EnvironmentProduction = "production"
)

// Singpass Sandbox URLs
const (
	SandboxAuthURL     = "https://stg-id.singpass.gov.sg/auth"
	SandboxTokenURL    = "https://stg-id.singpass.gov.sg/token" // #nosec G101 -- This is a public URL, not a credential
	SandboxUserInfoURL = "https://stg-id.singpass.gov.sg/userinfo"
	SandboxJWKSURL     = "https://stg-id.singpass.gov.sg/.well-known/keys"
)

// Singpass Production URLs
const (
	ProductionAuthURL     = "https://id.singpass.gov.sg/auth"
	ProductionTokenURL    = "https://id.singpass.gov.sg/token" // #nosec G101 -- This is a public URL, not a credential
	ProductionUserInfoURL = "https://id.singpass.gov.sg/userinfo"
	ProductionJWKSURL     = "https://id.singpass.gov.sg/.well-known/keys"
)

// Redis key prefixes
const (
	StateKeyPrefix = "singpass:state:"
	NonceKeyPrefix = "singpass:nonce:"
)

// Default timeout and expiration durations
const (
	DefaultStateExpiration = 10 * time.Minute
	DefaultNonceExpiration = 10 * time.Minute
	DefaultHTTPTimeout     = 30 * time.Second
)
