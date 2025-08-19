// Package errors defines error types for Singpass authentication operations.
package errors

import "fmt"

// ErrInvalidConfig represents a configuration validation error
type ErrInvalidConfig struct {
	Field string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid config: %s is required", e.Field)
}

// ErrInvalidState represents an invalid state parameter error
type ErrInvalidState struct {
	Message string
}

func (e ErrInvalidState) Error() string {
	return fmt.Sprintf("invalid state: %s", e.Message)
}

// ErrTokenValidation represents a token validation error
type ErrTokenValidation struct {
	Message string
}

func (e ErrTokenValidation) Error() string {
	return fmt.Sprintf("token validation failed: %s", e.Message)
}

// ErrHTTPRequest represents an HTTP request error
type ErrHTTPRequest struct {
	StatusCode int
	Message    string
}

func (e ErrHTTPRequest) Error() string {
	return fmt.Sprintf("HTTP request failed (status %d): %s", e.StatusCode, e.Message)
}

// ErrRedisOperation represents a Redis operation error
type ErrRedisOperation struct {
	Operation string
	Message   string
}

func (e ErrRedisOperation) Error() string {
	return fmt.Sprintf("Redis %s failed: %s", e.Operation, e.Message)
}

// ErrJWKSFetch represents a JWKS fetching error
type ErrJWKSFetch struct {
	Message string
}

func (e ErrJWKSFetch) Error() string {
	return fmt.Sprintf("JWKS fetch failed: %s", e.Message)
}
