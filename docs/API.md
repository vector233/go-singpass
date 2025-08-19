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

    // State Storage Configuration
    UseRedis      bool   `json:"use_redis"`
    RedisAddr     string `json:"redis_addr,omitempty"`
    RedisPassword string `json:"redis_password,omitempty"`
    RedisDB       int    `json:"redis_db,omitempty"`

    // Environment and Timeouts
    Environment     string        `json:"environment,omitempty"`
    StateExpiration time.Duration `json:"state_expiration,omitempty"`
    NonceExpiration time.Duration `json:"nonce_expiration,omitempty"`
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

### ExchangeCodeForUserInfo

Handles the OAuth2 callback and returns user information.

```go
func (c *Client) ExchangeCodeForUserInfo(ctx context.Context, code, state string) (*UserInfo, error)
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

userInfo, err := client.ExchangeCodeForUserInfo(r.Context(), code, state)
if err != nil {
    return err
}
```

### ExchangeCodeForTokens

Handles the OAuth2 callback and returns validated tokens without extracting user info.

```go
func (c *Client) ExchangeCodeForTokens(ctx context.Context, code, state string) (*TokenResponse, error)
```

**Parameters:**
- `ctx`: Context for the operation
- `code`: Authorization code from callback
- `state`: State parameter from callback

**Returns:**
- `*TokenResponse`: Token response containing access token, ID token, etc.
- `error`: Error if callback handling fails

**Example:**
```go
code := r.URL.Query().Get("code")
state := r.URL.Query().Get("state")

tokens, err := client.ExchangeCodeForTokens(r.Context(), code, state)
if err != nil {
    return err
}
```

### GetUserInfo

Retrieves additional user information using an access token.

```go
func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error)
```

**Parameters:**
- `ctx`: Context for the operation
- `accessToken`: Valid access token

**Returns:**
- `*UserInfo`: User information from userinfo endpoint
- `error`: Error if request fails

**Example:**
```go
userInfo, err := client.GetUserInfo(r.Context(), tokens.AccessToken)
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

Contains user information returned by Singpass. This structure matches the actual Singpass API response format.

```go
type UserInfo struct {
    // Personal Information (Singpass format)
    Name        ValueField `json:"name"`        // User's full legal name
    UINFIN      ValueField `json:"uinfin"`      // Singapore NRIC or FIN number
    Sex         CodedField `json:"sex"`         // Gender code (M/F)
    DOB         ValueField `json:"dob"`         // Date of birth in YYYY-MM-DD format
    Nationality CodedField `json:"nationality"` // Nationality code (e.g., "SG" for Singapore)

    // Address Information
    RegAdd RegisteredAddress `json:"regadd"` // Complete registered address

    // Contact Information
    MobileNo PhoneField `json:"mobileno"` // Mobile phone number
    Email    ValueField `json:"email"`    // Email address

    // Housing Information
    Housingtype CodedField `json:"housingtype"` // Housing type code

    // Standard OIDC claims as defined in OpenID Connect specification
    Iss string `json:"iss"`           // Issuer - identifies the Singpass OIDC provider
    Sub string `json:"sub"`           // Subject - unique identifier for the user
    Aud string `json:"aud"`           // Audience - client ID that this token is intended for
    Iat int64  `json:"iat"`           // Issued At - timestamp when the token was issued
    Exp int64  `json:"exp,omitempty"` // Expiration Time - timestamp when the token expires
}
```

#### UserInfo Methods

```go
// GetName returns the user's full name from the Name field
func (u *UserInfo) GetName() string

// GetUINFIN returns the user's NRIC/FIN number from the UINFIN field
func (u *UserInfo) GetUINFIN() string

// GetAddress returns a formatted address string from the RegAdd field
func (u *UserInfo) GetAddress() string

// IsExpired checks if the JWT token is expired based on exp claim
func (u *UserInfo) IsExpired() bool
```

### Nested Information Types

Singpass returns structured information in nested objects with value and classification fields:

```go
// ValueField represents a Singpass field containing a simple string value with metadata
type ValueField struct {
    LastUpdated    string `json:"lastupdated"`    // Timestamp when this field was last updated
    Source         string `json:"source"`         // Data source identifier
    Classification string `json:"classification"` // Data classification level
    Value          string `json:"value"`          // The actual field value
}

// CodedField represents a Singpass field containing a coded value with metadata
type CodedField struct {
    LastUpdated    string `json:"lastupdated"`    // Timestamp when this field was last updated
    Source         string `json:"source"`         // Data source identifier
    Classification string `json:"classification"` // Data classification level
    Code           string `json:"code"`           // Machine-readable code
    Desc           string `json:"desc"`           // Human-readable description
}

// PhoneField represents a Singpass phone number with structured format and metadata
type PhoneField struct {
    LastUpdated    string       `json:"lastupdated"`    // Timestamp when this field was last updated
    Source         string       `json:"source"`         // Data source identifier
    Classification string       `json:"classification"` // Data classification level
    AreaCode       ValueWrapper `json:"areacode"`       // Country/area code
    Prefix         ValueWrapper `json:"prefix"`         // Phone number prefix
    Number         ValueWrapper `json:"nbr"`            // Phone number
}

// RegisteredAddress represents a complete registered address structure with metadata
type RegisteredAddress struct {
    LastUpdated    string       `json:"lastupdated"`    // Timestamp when this field was last updated
    Source         string       `json:"source"`         // Data source identifier
    Classification string       `json:"classification"` // Data classification level
    Country        CodeDesc     `json:"country"`        // Country code and description
    Unit           ValueWrapper `json:"unit"`           // Unit number
    Street         ValueWrapper `json:"street"`         // Street name
    Block          ValueWrapper `json:"block"`          // Block number
    Postal         ValueWrapper `json:"postal"`         // Postal code
    Floor          ValueWrapper `json:"floor"`          // Floor number
    Building       ValueWrapper `json:"building"`       // Building name
    Type           string       `json:"type"`           // Address type (e.g., "SG")
}

// CodeDesc represents a field with both code and human-readable description
type CodeDesc struct {
    Code string `json:"code"` // Machine-readable code
    Desc string `json:"desc"` // Human-readable description
}

// ValueWrapper represents a simple value wrapped in a standard structure
type ValueWrapper struct {
    Value string `json:"value"` // The wrapped value
}
```

### TokenResponse

Contains OAuth2 token response from Singpass.

```go
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    RefreshToken string `json:"refresh_token,omitempty"`
    IDToken      string `json:"id_token"`
    Scope        string `json:"scope,omitempty"`
}
```

#### TokenResponse Methods

- `GetAccessToken() string`: Returns the access token
- `GetIDToken() string`: Returns the ID token
- `IsExpired() bool`: Checks if the token is expired based on ExpiresIn

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
4. **State Storage**: Supports both Redis and in-memory storage; Redis recommended for production
5. **HTTPS Only**: All communication with Singpass endpoints uses HTTPS
6. **Key Management**: Private keys for client assertion are loaded securely from file paths

## Best Practices

1. **Environment Variables**: Store sensitive configuration in environment variables
2. **Error Handling**: Always check and handle errors appropriately
3. **Context Usage**: Use context for timeout and cancellation control
4. **Resource Cleanup**: Always call `client.Close()` when done
5. **State Storage**: Use Redis for production environments for better scalability and persistence
6. **Redis Security**: When using Redis, configure AUTH and secure network settings
7. **Logging**: Implement proper logging for debugging and monitoring

## Rate Limiting

Singpass has rate limiting in place. Ensure your application:

1. Implements proper retry logic with exponential backoff
2. Fetches JWKS only when needed (keys are cached during token validation)
3. Doesn't make unnecessary requests to Singpass endpoints

## Testing

The library includes comprehensive tests. To run tests:

```bash
go test -v
```

Note: Integration tests require a running Redis instance on `localhost:6379`.