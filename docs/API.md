# API Documentation

## Overview

The Go Singpass library provides a simple and secure way to integrate with Singapore's Singpass authentication system using OpenID Connect 1.0.

## Configuration

### Config Structure

```go
type Config struct {
    // OAuth2/OIDC Configuration
    ClientID     string `json:"client_id"`
    Scope        string `json:"scope"`
    Issuer       string `json:"issuer"`
    RedirectURI  string `json:"redirect_uri"`
    AuthURL      string `json:"auth_url"`
    TokenURL     string `json:"token_url"`
    UserInfoURL  string `json:"userinfo_url"`
    JWKSURL      string `json:"jwks_url"`

    // Cryptographic Keys (Optional)
    SigPrivateKeyPath string `json:"sig_private_key_path,omitempty"`
    EncPrivateKeyPath string `json:"enc_private_key_path,omitempty"`

    // Redis Configuration for state management
    RedisAddr     string `json:"redis_addr"`
    RedisPassword string `json:"redis_password,omitempty"`
    RedisDB       int    `json:"redis_db"`

    // Timeouts and Expiration
    StateExpiration time.Duration `json:"state_expiration,omitempty"`
    NonceExpiration time.Duration `json:"nonce_expiration,omitempty"`
    JWKSCacheTTL    time.Duration `json:"jwks_cache_ttl,omitempty"`
    HTTPTimeout     time.Duration `json:"http_timeout,omitempty"`
}
```

### Environment-specific Endpoints

#### Staging Environment
```go
config := singpass.Config{
    AuthURL:     "https://stg-id.singpass.gov.sg/auth",
    TokenURL:    "https://stg-id.singpass.gov.sg/token",
    UserInfoURL: "https://stg-id.singpass.gov.sg/userinfo",
    JWKSURL:     "https://stg-id.singpass.gov.sg/.well-known/keys",
    Issuer:      "https://stg-id.singpass.gov.sg",
}
```

#### Production Environment
```go
config := singpass.Config{
    AuthURL:     "https://id.singpass.gov.sg/auth",
    TokenURL:    "https://id.singpass.gov.sg/token",
    UserInfoURL: "https://id.singpass.gov.sg/userinfo",
    JWKSURL:     "https://id.singpass.gov.sg/.well-known/keys",
    Issuer:      "https://id.singpass.gov.sg",
}
```

## Client Methods

### NewClient

Creates a new Singpass client with the given configuration.

```go
func NewClient(config Config) (*Client, error)
```

**Parameters:**
- `config`: Configuration object containing all necessary settings

**Returns:**
- `*Client`: Initialized client instance
- `error`: Error if configuration is invalid or initialization fails

**Example:**
```go
client, err := singpass.NewClient(config)
if err != nil {
    log.Fatal("Failed to create client:", err)
}
defer client.Close()
```

### GenerateAuthURL

Generates the authorization URL for Singpass login with PKCE support.

```go
func (c *Client) GenerateAuthURL(ctx context.Context) (string, error)
```

**Parameters:**
- `ctx`: Context for the operation

**Returns:**
- `string`: Authorization URL to redirect users to
- `error`: Error if URL generation fails

**Example:**
```go
authURL, err := client.GenerateAuthURL(context.Background())
if err != nil {
    return err
}
// Redirect user to authURL
```

### HandleCallback

Handles the OAuth2 callback and returns user information.

```go
func (c *Client) HandleCallback(ctx context.Context, code, state string) (*UserInfo, error)
```

**Parameters:**
- `ctx`: Context for the operation
- `code`: Authorization code from callback
- `state`: State parameter from callback

**Returns:**
- `*UserInfo`: User information extracted from ID token
- `error`: Error if callback handling fails

**Example:**
```go
code := r.URL.Query().Get("code")
state := r.URL.Query().Get("state")

userInfo, err := client.HandleCallback(r.Context(), code, state)
if err != nil {
    return err
}
```

### Close

Closes the client and cleans up resources.

```go
func (c *Client) Close() error
```

**Returns:**
- `error`: Error if cleanup fails

## Data Models

### UserInfo

Contains user information returned by Singpass.

```go
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
```

#### UserInfo Methods

- `GetFullName() string`: Returns the full name
- `GetIDNumber() string`: Returns the UINFIN
- `GetFormattedAddress() string`: Returns formatted address string
- `IsTokenExpired() bool`: Checks if the token is expired

### Address

Represents the registered address information.

```go
type Address struct {
    Type        string `json:"type"`
    Country     string `json:"country"`
    Unit        string `json:"unit,omitempty"`
    Floor       string `json:"floor,omitempty"`
    Block       string `json:"block,omitempty"`
    Building    string `json:"building,omitempty"`
    Street      string `json:"street,omitempty"`
    PostalCode  string `json:"postal,omitempty"`
}
```

#### Address Methods

- `Format() string`: Returns a formatted address string

## Error Handling

The library defines several custom error types:

### ErrInvalidConfig

Returned when configuration validation fails.

```go
type ErrInvalidConfig struct {
    Field string
}
```

### ErrInvalidState

Returned when state parameter validation fails.

```go
type ErrInvalidState struct {
    Message string
}
```

### ErrTokenValidation

Returned when token validation fails.

```go
type ErrTokenValidation struct {
    Message string
}
```

### ErrHTTPRequest

Returned when HTTP requests fail.

```go
type ErrHTTPRequest struct {
    StatusCode int
    Message    string
}
```

### ErrRedisOperation

Returned when Redis operations fail.

```go
type ErrRedisOperation struct {
    Operation string
    Message   string
}
```

### ErrJWKSFetch

Returned when JWKS fetching fails.

```go
type ErrJWKSFetch struct {
    Message string
}
```

## Security Considerations

1. **PKCE Support**: The library implements PKCE (Proof Key for Code Exchange) for enhanced security
2. **State Management**: Uses cryptographically secure random state and nonce generation
3. **Token Validation**: Validates JWT signatures using JWKS from Singpass
4. **Redis Security**: Store sensitive state information in Redis with expiration
5. **HTTPS Only**: All communication with Singpass endpoints uses HTTPS

## Best Practices

1. **Environment Variables**: Store sensitive configuration in environment variables
2. **Error Handling**: Always check and handle errors appropriately
3. **Context Usage**: Use context for timeout and cancellation control
4. **Resource Cleanup**: Always call `client.Close()` when done
5. **Redis Security**: Use Redis AUTH and secure network configuration
6. **Logging**: Implement proper logging for debugging and monitoring

## Rate Limiting

Singpass has rate limiting in place. Ensure your application:

1. Implements proper retry logic with exponential backoff
2. Caches JWKS appropriately (default: 24 hours)
3. Doesn't make unnecessary requests to Singpass endpoints

## Testing

The library includes comprehensive tests. To run tests:

```bash
go test -v
```

Note: Integration tests require a running Redis instance on `localhost:6379`.