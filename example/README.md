# Singpass Go SDK Example

This example demonstrates how to use the Singpass Go SDK for authentication.

## Prerequisites

1. **Redis Server**: Make sure Redis is running on `localhost:6379`
   ```bash
   # Install Redis (macOS)
   brew install redis
   
   # Start Redis
   brew services start redis
   ```

2. **Singpass Keys**: You need to obtain the following from Singpass:
   - Client ID
   - Signing private key (JWK format)
   - Encryption private key (JWK format)

3. **Key Files**: Place your key files in the `keys/` directory:
   ```
   keys/
   ├── test-singpass-jwk-sig-priv.json
   └── test-singpass-jwk-enc-priv.json
   ```

## Configuration

Before running the example, update the configuration in `main.go`:

```go
config.ClientID = "your-actual-client-id"  // Replace with your Singpass client ID
```

## Running the Example

1. Install dependencies:
   ```bash
   go mod tidy
   ```

2. Run the server:
   ```bash
   go run main.go
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:8080
   ```

4. Click "Login with Singpass" to start the authentication flow.

## How It Works

1. **Home Page** (`/`): Shows a simple login button
2. **Login** (`/login`): Generates the Singpass authentication URL and redirects the user
3. **Callback** (`/callback`): Handles the OAuth callback from Singpass and displays user information

## Environment Configuration

The example uses sandbox configuration by default. For production, change:

```go
// For sandbox (default)
config := singpass.SandboxConfig()

// For production
config := singpass.ProductionConfig()
```

## Troubleshooting

- **Redis Connection Error**: Ensure Redis is running and accessible
- **Key File Errors**: Verify that your JWK files are in the correct format and location
- **Client ID Error**: Make sure you're using the correct client ID for your environment
- **Redirect URI Mismatch**: Ensure your redirect URI is registered with Singpass

## Security Notes

- Never commit your actual client ID or private keys to version control
- Use environment variables for sensitive configuration in production
- Ensure your redirect URI uses HTTPS in production