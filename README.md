# Go Singpass

A Go library for integrating with Singapore's Singpass authentication system using OpenID Connect 1.0.

## Features

- OpenID Connect 1.0 Authorization Code Flow with PKCE
- JWT/JWE token handling and validation
- JWKS caching for token verification
- State and nonce management for CSRF protection
- Configurable Redis backend for session management
- Comprehensive error handling

## Installation

```bash
go get github.com/your-username/go-singpass
```

## Quick Start

```go
package main

import (
    "context"
    "log"
    
    "github.com/your-username/go-singpass"
)

func main() {
    config := singpass.Config{
        ClientID:     "your-client-id",
        RedirectURI:  "https://your-app.com/callback",
        AuthURL:      "https://stg-id.singpass.gov.sg/auth",
        TokenURL:     "https://stg-id.singpass.gov.sg/token",
        UserInfoURL:  "https://stg-id.singpass.gov.sg/userinfo",
        JWKSURL:      "https://stg-id.singpass.gov.sg/.well-known/keys",
        Scope:        "openid profile",
        // Redis configuration for state management
        RedisAddr:    "localhost:6379",
        RedisDB:      0,
    }
    
    client, err := singpass.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Generate authorization URL
    authURL, err := client.GenerateAuthURL(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Visit: %s", authURL)
}
```

## Documentation

For detailed documentation and examples, see the [docs](./docs) directory.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.