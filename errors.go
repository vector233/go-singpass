// Package singpass provides error types for the Singpass authentication client.
// This file re-exports error types from internal/errors for backward compatibility.
package singpass

import "github.com/vector233/go-singpass/internal/errors"

// Re-export error types for backward compatibility
type (
	// ErrInvalidConfig represents configuration validation errors
	ErrInvalidConfig = errors.ErrInvalidConfig

	// ErrInvalidState represents OAuth state validation errors
	ErrInvalidState = errors.ErrInvalidState

	// ErrTokenValidation represents JWT token validation errors
	ErrTokenValidation = errors.ErrTokenValidation

	// ErrHTTPRequest represents HTTP request errors
	ErrHTTPRequest = errors.ErrHTTPRequest

	// ErrRedisOperation represents Redis operation errors
	ErrRedisOperation = errors.ErrRedisOperation

	// ErrJWKSFetch represents JWKS fetching errors
	ErrJWKSFetch = errors.ErrJWKSFetch
)
