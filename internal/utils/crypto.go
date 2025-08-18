// Package utils provides utility functions for cryptographic operations.
package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/google/uuid"
)

// GenerateRandomBase64 generates a base64 encoded random string
func GenerateRandomBase64(byteLength int) (string, error) {
	bytes := make([]byte, byteLength)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateState generates a unique state parameter
func GenerateState() string {
	return uuid.New().String()
}

// GenerateNonce generates a random nonce
func GenerateNonce() (string, error) {
	return GenerateRandomBase64(16)
}

// GenerateCodeChallenge generates PKCE code challenge from verifier
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	encoded := base64.URLEncoding.EncodeToString(hash[:])
	return strings.TrimRight(encoded, "=")
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}