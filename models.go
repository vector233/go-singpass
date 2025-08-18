package singpass

import (
	"fmt"
	"time"
)

// UserInfo represents the user information returned by Singpass
type UserInfo struct {
	// Personal Information
	Name        string `json:"name"`
	UINFIN      string `json:"uinfin"`
	Sex         string `json:"sex"`
	DateOfBirth string `json:"date_of_birth"`
	Nationality string `json:"nationality"`

	// Address Information
	RegisteredAddress *Address `json:"registered_address,omitempty"`

	// Contact Information
	MobileNumber string `json:"mobileno,omitempty"`
	Email        string `json:"email,omitempty"`

	// JWT Claims
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

// Address represents the registered address information
type Address struct {
	Type       string `json:"type"`
	Country    string `json:"country"`
	Unit       string `json:"unit,omitempty"`
	Floor      string `json:"floor,omitempty"`
	Block      string `json:"block,omitempty"`
	Building   string `json:"building,omitempty"`
	Street     string `json:"street,omitempty"`
	PostalCode string `json:"postal,omitempty"`
}

// GetFullName returns the full name of the user
func (u *UserInfo) GetFullName() string {
	return u.Name
}

// GetIDNumber returns the UINFIN (unique identification number)
func (u *UserInfo) GetIDNumber() string {
	return u.UINFIN
}

// GetFormattedAddress returns a formatted address string
func (u *UserInfo) GetFormattedAddress() string {
	if u.RegisteredAddress == nil {
		return ""
	}
	return u.RegisteredAddress.Format()
}

// IsTokenExpired checks if the token is expired
func (u *UserInfo) IsTokenExpired() bool {
	if u.ExpiresAt == 0 {
		return false
	}
	return time.Now().Unix() > u.ExpiresAt
}

// Format returns a formatted address string
func (a *Address) Format() string {
	var parts []string

	if a.Unit != "" {
		parts = append(parts, fmt.Sprintf("Unit %s", a.Unit))
	}
	if a.Floor != "" {
		parts = append(parts, fmt.Sprintf("Floor %s", a.Floor))
	}
	if a.Block != "" {
		parts = append(parts, fmt.Sprintf("Block %s", a.Block))
	}
	if a.Building != "" {
		parts = append(parts, a.Building)
	}
	if a.Street != "" {
		parts = append(parts, a.Street)
	}
	if a.PostalCode != "" {
		parts = append(parts, fmt.Sprintf("Singapore %s", a.PostalCode))
	}

	result := ""
	for i, part := range parts {
		if i > 0 {
			result += ", "
		}
		result += part
	}
	return result
}

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
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
