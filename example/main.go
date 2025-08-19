package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/vector233/go-singpass"
)

func main() {
	// Initialize Singpass client using the sandbox configuration helper
	config := singpass.SandboxConfig()
	config.ClientID = "test" // Set your Singpass client ID here
	config.RedirectURI = "http://localhost:8080/callback"
	config.Scope = "openid name uinfin sex dob nationality regadd mobileno email housingtype"
	config.RedisAddr = "localhost:6379"
	config.RedisDB = 0
	config.SigPrivateKeyPath = "keys/test-singpass-jwk-sig-priv.json"
	config.EncPrivateKeyPath = "keys/test-singpass-jwk-enc-priv.json"

	client, err := singpass.NewClient(config)
	if err != nil {
		log.Fatal("Failed to create Singpass client:", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("Failed to close client: %v", err)
		}
	}()

	// Setup HTTP handlers
	http.HandleFunc("/login", handleLogin(client))
	http.HandleFunc("/callback", handleCallback(client))
	http.HandleFunc("/", handleHome)

	// Start server
	log.Println("Starting server on :8080")
	log.Println("Visit http://localhost:8080 to start authentication")
	log.Println("Make sure to:")
	log.Println("1. Set your ClientID in the config")
	log.Println("2. Place your JWK key files in the keys/ directory")
	log.Println("3. Ensure Redis is running on localhost:6379")

	// Create server with timeouts for security
	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Singpass Authentication Demo</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 40px; 
            text-align: center; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container { 
            max-width: 600px; 
            background: rgba(255,255,255,0.1);
            padding: 40px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        button { 
            background: #ff6b6b; 
            color: white; 
            padding: 15px 30px; 
            border: none; 
            border-radius: 25px; 
            cursor: pointer; 
            font-size: 16px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(255,107,107,0.3);
        }
        button:hover { 
            background: #ff5252; 
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(255,107,107,0.4);
        }
        .warning {
            background: rgba(255,193,7,0.2);
            border: 1px solid rgba(255,193,7,0.5);
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🇸🇬 Singpass Authentication Demo</h1>
        <p>This demo shows how to integrate with Singpass using the Go SDK</p>
        
        <div class="warning">
            ⚠️ <strong>Setup Required:</strong><br>
            Before testing, make sure to configure your Client ID and place your JWK key files in the keys/ directory.
        </div>
        
        <a href="/login"><button>🔐 Login with Singpass</button></a>
        
        <div style="margin-top: 30px; font-size: 12px; opacity: 0.8;">
            <p>This is a demonstration of the Singpass Go SDK</p>
            <p>For production use, ensure proper security measures are in place</p>
        </div>
    </div>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	if _, err := w.Write([]byte(html)); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleLogin(client *singpass.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authURL, err := client.GenerateAuthURL(r.Context())
		if err != nil {
			// Show error page instead of plain text
			errorHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Configuration Error</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
        .error { background: #ffebee; color: #c62828; padding: 20px; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="error">
        <h2>❌ Configuration Error</h2>
        <p>Failed to generate authentication URL: %s</p>
        <p>Please check your configuration and ensure:</p>
        <ul style="text-align: left; display: inline-block;">
            <li>Client ID is set</li>
            <li>JWK key files are present</li>
            <li>Redis is running</li>
        </ul>
        <a href="/"><button>← Back to Home</button></a>
    </div>
</body>
</html>`, err.Error())

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte(errorHTML)); err != nil {
				log.Printf("Failed to write error response: %v", err)
			}
			return
		}

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func handleCallback(client *singpass.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" || state == "" {
			errorHTML := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Callback Error</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
        .error { background: #ffebee; color: #c62828; padding: 20px; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="error">
        <h2>❌ Callback Error</h2>
        <p>Missing required parameters (code or state)</p>
        <a href="/"><button>← Back to Home</button></a>
    </div>
</body>
</html>`
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte(errorHTML)); err != nil {
				log.Printf("Failed to write error response: %v", err)
			}
			return
		}

		// Exchange authorization code for user information
		userInfo, err := client.ExchangeCodeForUserInfo(r.Context(), code, state)
		if err != nil {
			log.Printf("Failed to exchange code for user info: %v", err)
			errorHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Authentication Error</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
        .error { background: #ffebee; color: #c62828; padding: 20px; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="error">
        <h2>❌ Authentication Error</h2>
        <p>Failed to complete authentication: %s</p>
        <a href="/"><button>← Back to Home</button></a>
    </div>
</body>
</html>`, err.Error())

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte(errorHTML)); err != nil {
				log.Printf("Failed to write error response: %v", err)
			}
			return
		}

		// Display user information
		successHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Authentication Success</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 40px; 
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            color: white;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container { 
            max-width: 800px; 
            background: rgba(255,255,255,0.1);
            padding: 40px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            text-align: center;
        }
        .user-info {
            background: rgba(0,0,0,0.2);
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            text-align: left;
        }
        .info-row {
            margin: 10px 0;
            padding: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
        }
        button { 
            background: rgba(255,255,255,0.2); 
            color: white; 
            padding: 10px 20px; 
            border: 1px solid rgba(255,255,255,0.3); 
            border-radius: 5px; 
            cursor: pointer; 
        }
        button:hover { background: rgba(255,255,255,0.3); }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ Authentication Successful!</h1>
        <p>Welcome! Here's your information from Singpass:</p>
        
        <div class="user-info">
            <div class="info-row"><strong>Name:</strong> %s</div>
            <div class="info-row"><strong>NRIC/FIN:</strong> %s</div>
            <div class="info-row"><strong>Gender:</strong> %s (%s)</div>
            <div class="info-row"><strong>Date of Birth:</strong> %s</div>
            <div class="info-row"><strong>Nationality:</strong> %s (%s)</div>
            <div class="info-row"><strong>Address:</strong> %s</div>
            <div class="info-row"><strong>Mobile:</strong> %s</div>
            <div class="info-row"><strong>Email:</strong> %s</div>
        </div>
        
        <a href="/"><button>🏠 Back to Home</button></a>
    </div>
</body>
</html>`,
			userInfo.GetName(),
			userInfo.GetUINFIN(),
			userInfo.Sex.Desc, userInfo.Sex.Code,
			userInfo.DOB.Value,
			userInfo.Nationality.Desc, userInfo.Nationality.Code,
			userInfo.GetAddress(),
			userInfo.MobileNo.Number.Value,
			userInfo.Email.Value)

		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(successHTML)); err != nil {
			log.Printf("Failed to write success response: %v", err)
		}
	}
}
