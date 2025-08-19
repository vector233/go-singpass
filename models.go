// Package singpass provides data models for Singpass authentication responses.
// These models represent the structure of data returned from Singpass OIDC endpoints.
package singpass

import (
	"strings"
	"time"
)

// UserInfo represents the complete user information returned from Singpass OIDC endpoints
// It contains both standard OIDC claims and Singpass-specific user attributes
type UserInfo struct {
	// Personal Information (Singpass format)
	Name        ValueField `json:"name"`        // User's full legal name
	UINFIN      ValueField `json:"uinfin"`      // Singapore NRIC or FIN number
	Sex         CodedField `json:"sex"`         // Gender code (M/F)
	DOB         ValueField `json:"dob"`         // Date of birth in YYYY-MM-DD format
	Nationality CodedField `json:"nationality"` // Nationality code (e.g., "SG" for Singapore)

	// Address Information
	RegAdd RegisteredAddress `json:"regadd"` // Complete registered address

	// Contact Information
	MobileNo PhoneField `json:"mobileno"` // Mobile phone number
	Email    ValueField `json:"email"`    // Email address

	// Housing Information
	Housingtype CodedField `json:"housingtype"` // Housing type code

	// Standard OIDC claims as defined in OpenID Connect specification
	Iss string `json:"iss"`           // Issuer - identifies the Singpass OIDC provider
	Sub string `json:"sub"`           // Subject - unique identifier for the user
	Aud string `json:"aud"`           // Audience - client ID that this token is intended for
	Iat int64  `json:"iat"`           // Issued At - timestamp when the token was issued
	Exp int64  `json:"exp,omitempty"` // Expiration Time - timestamp when the token expires
}

// ValueField represents a Singpass field containing a simple string value with metadata
// This is commonly used for basic user attributes like name, email, etc.
type ValueField struct {
	LastUpdated    string `json:"lastupdated"`    // Timestamp when this field was last updated
	Source         string `json:"source"`         // Data source identifier
	Classification string `json:"classification"` // Data classification level
	Value          string `json:"value"`          // The actual field value
}

// CodedField represents a Singpass field containing a coded value with metadata
// This is used for standardized values like gender, nationality codes
type CodedField struct {
	LastUpdated    string `json:"lastupdated"`    // Timestamp when this field was last updated
	Source         string `json:"source"`         // Data source identifier
	Classification string `json:"classification"` // Data classification level
	Code           string `json:"code"`           // Machine-readable code
	Desc           string `json:"desc"`           // Human-readable description
}

// PhoneField represents a Singpass phone number with structured format and metadata
// Contains the phone number components in nested value wrappers
type PhoneField struct {
	LastUpdated    string       `json:"lastupdated"`    // Timestamp when this field was last updated
	Source         string       `json:"source"`         // Data source identifier
	Classification string       `json:"classification"` // Data classification level
	AreaCode       ValueWrapper `json:"areacode"`       // Country/area code
	Prefix         ValueWrapper `json:"prefix"`         // Phone number prefix
	Number         ValueWrapper `json:"nbr"`            // Phone number
}

// RegisteredAddress represents a complete registered address structure with metadata
// Contains all components of a Singapore address including unit, floor, block, etc.
type RegisteredAddress struct {
	LastUpdated    string       `json:"lastupdated"`    // Timestamp when this field was last updated
	Source         string       `json:"source"`         // Data source identifier
	Classification string       `json:"classification"` // Data classification level
	Country        CodeDesc     `json:"country"`        // Country code and description
	Unit           ValueWrapper `json:"unit"`           // Unit number
	Street         ValueWrapper `json:"street"`         // Street name
	Block          ValueWrapper `json:"block"`          // Block number
	Postal         ValueWrapper `json:"postal"`         // Postal code
	Floor          ValueWrapper `json:"floor"`          // Floor number
	Building       ValueWrapper `json:"building"`       // Building name
	Type           string       `json:"type"`           // Address type (e.g., "SG")
}

// CodeDesc represents a field with both code and human-readable description
// Used for standardized values that need both machine-readable codes and display text
type CodeDesc struct {
	Code string `json:"code"` // Machine-readable code
	Desc string `json:"desc"` // Human-readable description
}

// ValueWrapper represents a simple value wrapped in a standard structure
// Provides consistent formatting for nested value fields
type ValueWrapper struct {
	Value string `json:"value"` // The wrapped value
}

// GetName returns the user's full name
func (u *UserInfo) GetName() string {
	return u.Name.Value
}

// GetUINFIN returns the user's UINFIN (unique identification number)
func (u *UserInfo) GetUINFIN() string {
	return u.UINFIN.Value
}

// GetAddress returns the formatted address string
func (u *UserInfo) GetAddress() string {
	return u.RegAdd.String()
}

// IsExpired checks if the user info has expired
func (u *UserInfo) IsExpired() bool {
	if u.Exp == 0 {
		return false
	}
	return time.Now().Unix() > u.Exp
}

// String returns a formatted address string for RegisteredAddress
func (r *RegisteredAddress) String() string {
	parts := []string{}
	if r.Block.Value != "" {
		parts = append(parts, r.Block.Value)
	}
	if r.Street.Value != "" {
		parts = append(parts, r.Street.Value)
	}
	if r.Unit.Value != "" {
		parts = append(parts, "#"+r.Unit.Value)
	}
	if r.Building.Value != "" {
		parts = append(parts, r.Building.Value)
	}
	if r.Postal.Value != "" {
		parts = append(parts, "Singapore "+r.Postal.Value)
	}
	return strings.Join(parts, " ")
}

// TokenResponse represents the OAuth2/OIDC token response from Singpass
// Contains all tokens and metadata returned after successful authorization code exchange
type TokenResponse struct {
	AccessToken  string `json:"access_token"`            // Bearer token for API access
	TokenType    string `json:"token_type"`              // Token type, typically "Bearer"
	ExpiresIn    int    `json:"expires_in,omitempty"`    // Token lifetime in seconds
	RefreshToken string `json:"refresh_token,omitempty"` // Refresh token (if available)
	IDToken      string `json:"id_token"`                // JWT ID token containing user claims
	Scope        string `json:"scope,omitempty"`         // Granted scopes
}

// AuthState represents the OAuth2 authorization state for PKCE flow
// Used internally to maintain state during the authorization process
type AuthState struct {
	State         string    `json:"state"`          // Random state parameter for CSRF protection
	Nonce         string    `json:"nonce"`          // Random nonce for ID token validation
	CodeVerifier  string    `json:"code_verifier"`  // PKCE code verifier
	CodeChallenge string    `json:"code_challenge"` // PKCE code challenge
	CreatedAt     time.Time `json:"created_at"`     // Timestamp when state was created
	ExpiresAt     time.Time `json:"expires_at"`     // Timestamp when state expires
}

// IsExpired checks if the auth state is expired
func (s *AuthState) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
