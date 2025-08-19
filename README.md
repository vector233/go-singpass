# Go Singpass

A comprehensive Go library for integrating with Singapore's Singpass OpenID Connect (OIDC) authentication system, implementing the official Singpass Authentication API with full support for the Redirect Authentication Flow.

## Features

- **Official Singpass API Compliance**: Implements the complete Singpass Authentication API specification with Redirect Authentication Flow
- **PKCE Support**: Implements Proof Key for Code Exchange (RFC 7636) for enhanced security as required by Singpass
- **Client Authentication**: Supports private_key_jwt client authentication method with ES256 algorithm
- **JWT/JWE Token Handling**: Secure JWT token parsing, JWE decryption, and validation with JWKS support
- **Flexible State Management**: Support for both Redis and in-memory state storage for CSRF protection
- **Environment Support**: Built-in support for Singpass sandbox and production environments
- **Comprehensive User Data**: Extract complete user information including personal details, address, and contact info
- **Type Safety**: Strongly typed data structures matching official Singpass API responses
- **Configurable**: Flexible configuration with sensible defaults and validation

## Installation

```bash
go get github.com/vector233/go-singpass
```

## Singpass Authentication Flow

This library implements the official Singpass Redirect Authentication Flow as specified in the [Singpass Authentication API documentation](https://docs.developer.singpass.gov.sg/docs/technical-specifications/singpass-authentication-api). The flow consists of:

1. **Authorization Request**: Generate authorization URL with PKCE parameters
2. **User Authentication**: User authenticates with Singpass
3. **Authorization Code**: Singpass redirects back with authorization code
4. **Token Exchange**: Exchange code for ID token using client authentication
5. **User Information**: Extract user data from validated tokens

## Quick Start

### Basic Setup

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/vector233/go-singpass"
)

func main() {
    // Create configuration with required private keys
    config := &singpass.Config{
        ClientID:          "your-client-id",
        RedirectURI:       "https://your-app.com/callback",
        Environment:       "sandbox", // or "production"
        SigPrivateKeyPath: "/path/to/signing-key.pem",    // ES256 private key for client authentication
        EncPrivateKeyPath: "/path/to/encryption-key.pem", // RSA private key for JWE decryption
        UseRedis:          true,       // Set to false for in-memory storage
        RedisAddr:         "localhost:6379",
        RedisDB:           0,
    }
    
    // Initialize client
    client, err := singpass.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    // Step 1: Generate authentication URL (with PKCE)
    authURL, err := client.GenerateAuthURL(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Redirect user to: %s\n", authURL)
}
```

### Handle Callback

```go
func handleCallback(client *singpass.Client, code, state string) {
    ctx := context.Background()
    
    // Step 4: Exchange authorization code for tokens and user information
    // This performs:
    // - Client authentication using private_key_jwt method
    // - PKCE code verification
    // - JWT signature validation with JWKS
    // - JWE decryption of user data
    userInfo, err := client.ExchangeCodeForUserInfo(ctx, code, state)
    if err != nil {
        log.Printf("Callback error: %v", err)
        return
    }
    
    // Access validated user information
    fmt.Printf("User: %s\n", userInfo.GetName())
    fmt.Printf("NRIC: %s\n", userInfo.GetUINFIN())
    fmt.Printf("Address: %s\n", userInfo.GetAddress())
}

// Alternative: Separate token exchange and user info retrieval
func handleCallbackSeparate(client *singpass.Client, code, state string) {
    ctx := context.Background()
    
    // Step 4a: Exchange code for tokens only
    tokens, err := client.ExchangeCodeForTokens(ctx, code, state)
    if err != nil {
        log.Printf("Token exchange error: %v", err)
        return
    }
    
    // Step 4b: Get user information using access token
    userInfo, err := client.GetUserInfo(ctx, tokens.AccessToken)
    if err != nil {
        log.Printf("User info error: %v", err)
        return
    }
    
    fmt.Printf("User: %s\n", userInfo.GetName())
}
```

## Configuration

### Environment-Specific Configurations

```go
// Sandbox configuration
config := singpass.SandboxConfig()
config.ClientID = "your-sandbox-client-id"
config.RedirectURI = "https://your-app.com/callback"
config.UseRedis = true // Enable Redis for state storage
config.RedisAddr = "localhost:6379"

// Production configuration
config := singpass.ProductionConfig()
config.ClientID = "your-production-client-id"
config.RedirectURI = "https://your-app.com/callback"
config.UseRedis = true // Enable Redis for state storage
config.RedisAddr = "localhost:6379"
```

### Manual Configuration

```go
config := &singpass.Config{
    // OAuth2 Configuration
    ClientID:    "your-client-id",
    RedirectURI: "https://your-app.com/callback",
    Scope:       "openid profile",
    
    // Singpass Endpoints
    AuthURL:     "https://stg-id.singpass.gov.sg/auth",
    TokenURL:    "https://stg-id.singpass.gov.sg/token",
    UserInfoURL: "https://stg-id.singpass.gov.sg/userinfo",
    JWKSURL:     "https://stg-id.singpass.gov.sg/.well-known/keys",
    
    // Cryptographic Keys
    SigPrivateKeyPath: "/path/to/signing-key.pem",
    EncPrivateKeyPath: "/path/to/encryption-key.pem",
    
    // State Storage Configuration (Redis is optional)
    UseRedis:      true, // Set to false to use in-memory storage
    RedisAddr:     "localhost:6379",
    RedisPassword: "",
    RedisDB:       0,
    
    // Timeouts and Expiration
    StateExpiration: 10 * time.Minute,
    NonceExpiration: 10 * time.Minute,
    HTTPTimeout:     30 * time.Second,
    
    // Environment
    Environment: "sandbox", // or "production"
}
```

## User Information

The library provides comprehensive access to Singpass user data:

```go
// Personal Information
name := userInfo.GetName()           // Full name
uinfin := userInfo.GetUINFIN()       // NRIC/FIN
sex := userInfo.Sex.Code             // Gender code
dob := userInfo.DOB.Value            // Date of birth
nationality := userInfo.Nationality.Code // Nationality code

// Contact Information
mobile := userInfo.MobileNo.Number.Value // Mobile number
email := userInfo.Email.Value             // Email address

// Address Information
address := userInfo.GetAddress()     // Formatted address string
block := userInfo.RegAdd.Block.Value // HDB block number
unit := userInfo.RegAdd.Unit.Value   // Unit number
postal := userInfo.RegAdd.Postal.Value // Postal code

// JWT Claims
issuer := userInfo.Iss    // Token issuer
subject := userInfo.Sub   // Subject (user ID)
audience := userInfo.Aud  // Intended audience
issuedAt := userInfo.Iat  // Issued at timestamp
expiry := userInfo.Exp    // Expiration timestamp
```

## Error Handling

```go
userInfo, err := client.ExchangeCodeForUserInfo(ctx, code, state)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "invalid state"):
        // Handle invalid state parameter
    case strings.Contains(err.Error(), "token validation failed"):
        // Handle token validation errors
    case strings.Contains(err.Error(), "failed to fetch JWKS"):
        // Handle JWKS retrieval errors
    default:
        // Handle other errors
    }
}
```

## Testing

Run the test suite:

```bash
go test -v
```

The library includes comprehensive tests for:
- Configuration validation
- PKCE code generation
- State management
- User info parsing
- Environment-specific configurations

## Requirements

- **Go 1.23 or later** - Required for modern cryptographic support
- **Redis server** - Optional for state management (can use in-memory storage)
- **Singpass Client Registration** - Valid client credentials from Singpass
- **ES256 Private Key** - For client authentication (PEM format)
- **RSA Private Key** - For JWE decryption (PEM format, minimum 2048-bit)
- **HTTPS Endpoint** - For redirect URI in production environment

## Technical Specifications

### Supported Standards
- **OpenID Connect 1.0** - Core specification compliance
- **OAuth 2.0** - Authorization framework (RFC 6749)
- **PKCE** - Proof Key for Code Exchange (RFC 7636)
- **JWT** - JSON Web Tokens (RFC 7519)
- **JWE** - JSON Web Encryption (RFC 7516)
- **JWS** - JSON Web Signature (RFC 7515)
- **JWKS** - JSON Web Key Set (RFC 7517)

### Cryptographic Algorithms
- **ES256** - ECDSA using P-256 and SHA-256 (for client authentication)
- **RSA-OAEP** - RSA Optimal Asymmetric Encryption Padding (for JWE decryption)
- **A256GCM** - AES-256 Galois/Counter Mode (for JWE content encryption)

### Client Authentication
- **private_key_jwt** - JWT-based client authentication as required by Singpass
- **ES256 signatures** - Elliptic Curve Digital Signature Algorithm

## Dependencies

- `github.com/lestrrat-go/jwx/v3` - Comprehensive JWT/JWE/JWS/JWKS handling
- `github.com/redis/go-redis/v9` - Redis client for state storage
- `github.com/google/uuid` - UUID generation for state and nonce parameters

## Security Considerations

- **Private Key Security**: Store ES256 private keys securely and never commit them to version control
- **HTTPS Required**: Use HTTPS for all redirect URIs in production as mandated by Singpass
- **Client Authentication**: Implements private_key_jwt authentication method as required by Singpass API
- **State Management**: CSRF protection through secure state parameter validation
- **Token Validation**: Full JWT signature verification and JWE decryption with JWKS key rotation support
- **Session Management**: Implement proper session management in your application
- **Input Validation**: Validate all user inputs and sanitize data before storage
- **Production Storage**: For production environments, prefer Redis over in-memory storage for better scalability and persistence
- **Redis Security**: Use appropriate Redis security configurations when Redis is enabled

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check the Singpass developer documentation
- Review the test cases for usage examples