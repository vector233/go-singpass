# Troubleshooting Guide

## Common Issues

### JWT Signing Error: "failed to retrieve rsa.PrivateKey out of *jwk.ecdsaPrivateKey"

**Error Message:**
```
failed to sign JWT: failed to serialize token at step #2: failed to generate signature for signer #0 (alg=RS256): failed to sign payload: failed to retrieve rsa.PrivateKey out of *jwk.ecdsaPrivateKey: keyconv: failed to produce rsa.PrivateKey from *jwk.ecdsaPrivateKey: argument to AssignIfCompatible() must be compatible with *ecdsa.PrivateKey (was *rsa.PrivateKey)
```

**Root Cause:**
This error occurs when your JWK signing private key file has the wrong algorithm (`alg`) field. The error indicates that:
1. Your private key is an ECDSA key (correct for Singpass)
2. But the `alg` field in your JWK file is set to `RS256` (incorrect)
3. The library tries to use RS256 algorithm with an ECDSA key, which fails

**Solution:**
Check your signing private key JWK file (specified in `SigPrivateKeyPath`) and ensure:

1. **For ECDSA P-256 keys (required by Singpass):**
   ```json
   {
     "kty": "EC",
     "use": "sig",
     "alg": "ES256",  // ← This should be ES256, NOT RS256
     "crv": "P-256",
     "x": "your-x-coordinate",
     "y": "your-y-coordinate",
     "d": "your-private-key"
   }
   ```

2. **Key points:**
   - `kty` must be `"EC"` for ECDSA keys
   - `alg` must be `"ES256"` for ECDSA P-256 keys
   - `crv` must be `"P-256"` for the P-256 curve
   - Never use `"RS256"` with ECDSA keys

**How to Fix:**
1. Open your signing private key JWK file
2. Change `"alg": "RS256"` to `"alg": "ES256"`
3. Ensure `"kty": "EC"` and `"crv": "P-256"`
4. Save the file and retry

### Key Generation

If you need to generate new keys for testing:

**ECDSA P-256 Key (for signing):**
```bash
# Generate private key
openssl ecparam -genkey -name prime256v1 -noout -out ec-private.pem

# Convert to JWK format (you'll need a tool like jose or custom script)
# Make sure the resulting JWK has "alg": "ES256"
```

**RSA Key (for encryption):**
```bash
# Generate private key
openssl genrsa -out rsa-private.pem 2048

# Convert to JWK format
# Make sure the resulting JWK has "alg": "RSA-OAEP"
```

### Environment-Specific Issues

**Sandbox vs Production:**
- Ensure you're using the correct environment configuration
- Sandbox and production may require different key formats or algorithms
- Check Singpass documentation for environment-specific requirements

**Redis Connection Issues:**
```
failed to connect to Redis: dial tcp [::1]:6379: connect: connection refused
```

**Solution:**
1. Start Redis server: `redis-server`
2. Or disable Redis: set `UseRedis: false` in config
3. Check Redis address and port in configuration

### Configuration Validation Errors

**Missing Required Fields:**
```
config validation failed: ClientID is required
```

**Solution:**
Ensure all required configuration fields are set:
- `ClientID`
- `RedirectURI`
- `SigPrivateKeyPath` (for client authentication)
- `EncPrivateKeyPath` (for JWE decryption)

### Network and Timeout Issues

**HTTP Request Timeouts:**
```
HTTP request failed: context deadline exceeded
```

**Solution:**
1. Increase `HTTPTimeout` in configuration
2. Check network connectivity to Singpass endpoints
3. Verify firewall settings

**JWKS Fetch Errors:**
```
failed to fetch JWKS: HTTP request failed
```

**Solution:**
1. Check internet connectivity
2. Verify JWKS URL is correct for your environment
3. Check if corporate firewall blocks the request

## Debug Tips

1. **Enable Verbose Logging:**
   Add logging to see detailed error information

2. **Validate JWK Files:**
   Use online JWK validators to check your key files

3. **Test with Minimal Config:**
   Start with basic configuration and add features incrementally

4. **Check Singpass Documentation:**
   Ensure your implementation matches the latest Singpass API requirements

## Getting Help

If you continue to experience issues:
1. Check the error message carefully
2. Verify your JWK file formats
3. Ensure all required configuration is set
4. Test with the provided example application
5. Check Singpass developer documentation for updates