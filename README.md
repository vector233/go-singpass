# Go Singpass

A comprehensive Go library for integrating with Singapore's Singpass OpenID Connect (OIDC) authentication system.

## Features

- **Complete OIDC Integration**: Full support for Singpass OpenID Connect authentication flow
- **PKCE Support**: Implements Proof Key for Code Exchange for enhanced security
- **JWT Token Handling**: Secure JWT token parsing, validation, and user info extraction
- **Redis State Management**: Robust state and nonce management using Redis
- **Environment Support**: Built-in support for sandbox and production environments
- **Comprehensive User Data**: Extract complete user information including personal details, address, and contact info
- **Type Safety**: Strongly typed data structures matching Singpass API responses
- **Configurable**: Flexible configuration with sensible defaults

## Installation

```bash
go get github.com/vector233/go-singpass
```

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
    // Create configuration
    config := &singpass.Config{
        ClientID:    "your-client-id",
        RedirectURI: "https://your-app.com/callback",
        Environment: singpass.EnvironmentSandbox, // or EnvironmentProduction
        RedisAddr:   "localhost:6379",
        RedisDB:     0,
    }
    
    // Initialize client
    client, err := singpass.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    // Generate authentication URL
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
    
    // Exchange code for user information
    userInfo, err := client.HandleCallback(ctx, code, state)
    if err != nil {
        log.Printf("Callback error: %v", err)
        return
    }
    
    // Access user information
    fmt.Printf("User: %s\n", userInfo.GetName())
    fmt.Printf("NRIC: %s\n", userInfo.GetUINFIN())
    fmt.Printf("Address: %s\n", userInfo.GetAddress())
}
```

## Configuration

### Environment-Specific Configurations

```go
// Sandbox configuration
config := singpass.SandboxConfig()
config.ClientID = "your-sandbox-client-id"
config.RedirectURI = "https://your-app.com/callback"
config.RedisAddr = "localhost:6379"

// Production configuration
config := singpass.ProductionConfig()
config.ClientID = "your-production-client-id"
config.RedirectURI = "https://your-app.com/callback"
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
    JWKSURL:     "https://stg-id.singpass.gov.sg/.well-known/jwks",
    
    // Cryptographic Keys
    SigPrivateKeyPath: "/path/to/signing-key.pem",
    EncPrivateKeyPath: "/path/to/encryption-key.pem",
    
    // Redis Configuration
    RedisAddr:     "localhost:6379",
    RedisPassword: "",
    RedisDB:       0,
    
    // Timeouts and Expiration
    StateExpiration: 10 * time.Minute,
    NonceExpiration: 10 * time.Minute,
    JWKSCacheTTL:    24 * time.Hour,
    HTTPTimeout:     30 * time.Second,
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
userInfo, err := client.HandleCallback(ctx, code, state)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "invalid state"):
        // Handle invalid state parameter
    case strings.Contains(err.Error(), "token validation failed"):
        // Handle token validation errors
    case strings.Contains(err.Error(), "JWKS fetch failed"):
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

- Go 1.23 or later
- Redis server for state management
- Valid Singpass client credentials
- Private keys for JWT signing and encryption

## Dependencies

- `github.com/lestrrat-go/jwx/v2` - JWT handling
- `github.com/redis/go-redis/v9` - Redis client
- `github.com/google/uuid` - UUID generation

## Security Considerations

- Store private keys securely and never commit them to version control
- Use HTTPS for all redirect URIs in production
- Implement proper session management in your application
- Validate all user inputs and sanitize data before storage
- Use appropriate Redis security configurations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check the Singpass developer documentation
- Review the test cases for usage examples