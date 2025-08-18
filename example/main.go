package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/vector233/go-singpass"
)

func main() {
	// Initialize Singpass client with sandbox configuration
	config := singpass.SandboxConfig()
	config.ClientID = "" // 设置环境变量 SINGPASS_CLIENT_ID
	config.RedirectURI = ""
	config.Scope = "openid name uinfin sex dob nationality regadd mobileno email housingtype"
	config.RedisAddr = "localhost:6379"
	config.RedisDB = 0
	config.SigPrivateKeyPath = "keys/test-singpass-jwk-sig-priv.json"
	config.EncPrivateKeyPath = "keys/test-singpass-jwk-enc-priv.json"

	client, err := singpass.NewClient(config)
	if err != nil {
		log.Fatal("Failed to create Singpass client:", err)
	}
	// Setup HTTP handlers
	http.HandleFunc("/login", handleLogin(client))
	http.HandleFunc("/callback", handleCallback(client))
	http.HandleFunc("/", handleHome)

	fmt.Println("Server starting on :8080")
	fmt.Println("Visit http://localhost:8080 to start")
	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Singpass Demo</title>
</head>
<body>
    <h1>Singpass Authentication Demo</h1>
    <p>Click the button below to login with Singpass:</p>
    <a href="/login"><button>Login with Singpass</button></a>
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
			http.Error(w, "Failed to generate auth URL: "+err.Error(), http.StatusInternalServerError)
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
			http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
			return
		}

		userInfo, err := client.HandleCallback(r.Context(), code, state)
		if err != nil {
			http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Display user information
		html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Success</title>
</head>
<body>
    <h1>Authentication Successful!</h1>
    <h2>User Information:</h2>
    <ul>
        <li><strong>Name:</strong> %s</li>
        <li><strong>UINFIN:</strong> %s</li>
        <li><strong>Sex:</strong> %s</li>
        <li><strong>Date of Birth:</strong> %s</li>
        <li><strong>Nationality:</strong> %s</li>
        <li><strong>Mobile:</strong> %s</li>
        <li><strong>Email:</strong> %s</li>
        <li><strong>Address:</strong> %s</li>
    </ul>
    <a href="/"><button>Back to Home</button></a>
</body>
</html>
`, userInfo.GetName(), userInfo.GetUINFIN(), userInfo.Sex.Code, userInfo.DOB.Value,
			userInfo.Nationality.Code, userInfo.MobileNo.Number.Value, userInfo.Email.Value, userInfo.GetAddress())

		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(html)); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}
