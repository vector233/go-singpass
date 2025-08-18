// Package singpass defines data models for Singpass authentication and user information.
package singpass

import (
	"strings"
	"time"
)

// UserInfo represents the user information returned by Singpass
// This is the complete structure as returned by Singpass UserInfo endpoint
type UserInfo struct {
	// Personal Information (Singpass format)
	Name        ValueField `json:"name"`
	UINFIN      ValueField `json:"uinfin"`
	Sex         CodedField `json:"sex"`
	DOB         ValueField `json:"dob"`
	Nationality CodedField `json:"nationality"`

	// Address Information
	RegAdd RegisteredAddress `json:"regadd"`

	// Contact Information
	MobileNo PhoneField `json:"mobileno"`
	Email    ValueField `json:"email"`

	// Housing Information
	Housingtype CodedField `json:"housingtype"`

	// JWT Claims
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp,omitempty"`
}

// ValueField represents a Singpass field with metadata
type ValueField struct {
	LastUpdated    string `json:"lastupdated"`
	Source         string `json:"source"`
	Classification string `json:"classification"`
	Value          string `json:"value"`
}

// CodedField represents a Singpass field with code and description
type CodedField struct {
	LastUpdated    string `json:"lastupdated"`
	Source         string `json:"source"`
	Classification string `json:"classification"`
	Code           string `json:"code"`
	Desc           string `json:"desc"`
}

// PhoneField represents a Singpass phone number field
type PhoneField struct {
	LastUpdated    string       `json:"lastupdated"`
	Source         string       `json:"source"`
	Classification string       `json:"classification"`
	AreaCode       ValueWrapper `json:"areacode"`
	Prefix         ValueWrapper `json:"prefix"`
	Number         ValueWrapper `json:"nbr"`
}

// RegisteredAddress represents a Singpass registered address
type RegisteredAddress struct {
	LastUpdated    string       `json:"lastupdated"`
	Source         string       `json:"source"`
	Classification string       `json:"classification"`
	Country        CodeDesc     `json:"country"`
	Unit           ValueWrapper `json:"unit"`
	Street         ValueWrapper `json:"street"`
	Block          ValueWrapper `json:"block"`
	Postal         ValueWrapper `json:"postal"`
	Floor          ValueWrapper `json:"floor"`
	Building       ValueWrapper `json:"building"`
	Type           string       `json:"type"`
}

// CodeDesc represents a code-description pair
type CodeDesc struct {
	Code string `json:"code"`
	Desc string `json:"desc"`
}

// ValueWrapper wraps a simple value
type ValueWrapper struct {
	Value string `json:"value"`
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

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope,omitempty"`
}

// AuthState represents the state stored during OAuth2 flow
type AuthState struct {
	State         string    `json:"state"`
	Nonce         string    `json:"nonce"`
	CodeVerifier  string    `json:"code_verifier"`
	CodeChallenge string    `json:"code_challenge"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// IsExpired checks if the auth state is expired
func (s *AuthState) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
