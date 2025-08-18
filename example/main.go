package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/your-username/go-singpass"
)

func main() {
	// Initialize Singpass client
	config := singpass.Config{
		ClientID:    os.Getenv("SINGPASS_CLIENT_ID"),
		RedirectURI: "http://localhost:8080/callback",
		AuthURL:     "https://stg-id.singpass.gov.sg/auth",
		TokenURL:    "https://stg-id.singpass.gov.sg/token",
		UserInfoURL: "https://stg-id.singpass.gov.sg/userinfo",
		JWKSURL:     "https://stg-id.singpass.gov.sg/.well-known/keys",
		Issuer:      "https://stg-id.singpass.gov.sg",
		Scope:       "openid profile",
		RedisAddr:   "localhost:6379",
		RedisDB:     0,
	}

	client, err := singpass.NewClient(config)
	if err != nil {
		log.Fatal("Failed to create Singpass client:", err)
	}
	defer client.Close()

	// Setup HTTP handlers
	http.HandleFunc("/login", handleLogin(client))
	http.HandleFunc("/callback", handleCallback(client))
	http.HandleFunc("/", handleHome)

	fmt.Println("Server starting on :8080")
	fmt.Println("Visit http://localhost:8080 to start")
	log.Fatal(http.ListenAndServe(":8080", nil))
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
	w.Write([]byte(html))
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
`, userInfo.Name, userInfo.UINFIN, userInfo.Sex, userInfo.DateOfBirth,
			userInfo.Nationality, userInfo.MobileNumber, userInfo.Email, userInfo.GetFormattedAddress())

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}
}
