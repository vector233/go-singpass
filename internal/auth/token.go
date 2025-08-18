// Package auth provides token validation and processing functionality.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/vector233/go-singpass/internal/errors"
)

// TokenValidator handles JWT token validation
type TokenValidator struct {
	jwksCache *jwk.Cache
	jwksURL   string
	issuer    string
	clientID  string
}

// NewTokenValidator creates a new token validator
func NewTokenValidator(jwksCache *jwk.Cache, jwksURL, issuer, clientID string) *TokenValidator {
	return &TokenValidator{
		jwksCache: jwksCache,
		jwksURL:   jwksURL,
		issuer:    issuer,
		clientID:  clientID,
	}
}

// ValidateIDToken validates the ID token and extracts claims
func (tv *TokenValidator) ValidateIDToken(ctx context.Context, idToken, expectedNonce string) (map[string]interface{}, error) {
	// Parse and validate token
	claims, err := tv.parseAndValidateToken(ctx, idToken)
	if err != nil {
		return nil, err
	}

	// Validate token claims
	if err := tv.validateTokenClaims(claims, expectedNonce); err != nil {
		return nil, err
	}

	return claims, nil
}

// parseAndValidateToken parses and validates the JWT token
func (tv *TokenValidator) parseAndValidateToken(ctx context.Context, idToken string) (map[string]interface{}, error) {
	// Get JWKS
	jwks, err := tv.getJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Verify the JWS token with algorithm inference
	buf, err := jws.Verify([]byte(idToken), jws.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		return nil, errors.ErrTokenValidation{Message: err.Error()}
	}

	// Parse claims from verified payload
	var claims map[string]interface{}
	if err := json.Unmarshal(buf, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	return claims, nil
}

// validateTokenClaims validates the token claims
func (tv *TokenValidator) validateTokenClaims(claims map[string]interface{}, expectedNonce string) error {
	// Validate issuer
	issuer, ok := claims["iss"].(string)
	if !ok || issuer != tv.issuer {
		return errors.ErrTokenValidation{Message: "invalid issuer"}
	}

	// Validate audience
	audience, ok := claims["aud"].(string)
	if !ok || audience != tv.clientID {
		return errors.ErrTokenValidation{Message: "invalid audience"}
	}

	// Validate expiration
	exp, ok := claims["exp"].(float64)
	if !ok || float64(time.Now().Unix()) >= exp {
		return errors.ErrTokenValidation{Message: "token has expired"}
	}

	// Validate issued at
	iat, ok := claims["iat"].(float64)
	if !ok || float64(time.Now().Unix()) < iat {
		return errors.ErrTokenValidation{Message: "token issued in the future"}
	}

	// Validate nonce
	tokenNonce, ok := claims["nonce"].(string)
	if !ok || tokenNonce != expectedNonce {
		return errors.ErrTokenValidation{Message: "invalid nonce"}
	}

	return nil
}

// getJWKS retrieves the JWKS from cache or fetches it
func (tv *TokenValidator) getJWKS(ctx context.Context) (jwk.Set, error) {
	jwks, err := tv.jwksCache.Lookup(ctx, tv.jwksURL)
	if err != nil {
		return nil, errors.ErrJWKSFetch{Message: err.Error()}
	}
	return jwks, nil
}