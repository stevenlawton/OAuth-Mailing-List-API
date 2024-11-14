package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/mailgun/mailgun-go/v4"
	"github.com/rs/cors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type OAuthRequest struct {
	Token string `json:"token"`
}

type SignupRequest struct {
	Email string `json:"email"`
}

type OAuthResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture struct {
		Data struct {
			Url string `json:"url"`
		} `json:"data"`
	} `json:"picture"`
}

var (
	mailgunAPIKey      string
	mailgunDomain      string
	mailgunListAddress string
	mailgunListAPIKey  string

	secretKey string
)

func setup() {
	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current directory: %v", err)
	}
	log.Printf("Current Directory: %s", currentDir)

	// Load environment variables from .env file
	if err := godotenv.Load(currentDir + "/.env"); err != nil {
		log.Fatalf("No .env file found")
	} else {
		log.Println(".env file loaded successfully")
	}

	mailgunAPIKey = os.Getenv("MAILGUN_MAILING_LIST_API_KEY")
	if mailgunAPIKey == "" {
		log.Printf("Mailgun API key not set")
	}

	mailgunListAPIKey = os.Getenv("MAILGUN_MAILING_LIST_API_KEY")
	if mailgunListAPIKey == "" {
		log.Printf("Mailgun list API key not set")
	}

	mailgunDomain = os.Getenv("MAILGUN_DOMAIN")
	if mailgunDomain == "" {
		log.Printf("Mailgun domain not set")
	}

	mailgunListAddress = os.Getenv("MAILGUN_LIST_ADDRESS")
	if mailgunListAddress == "" {
		log.Printf("Mailgun list address not set")
	}

	secretKey = os.Getenv("SECRET_KEY")
	if secretKey == "" {
		log.Printf("Secret key not set")
	}

}

func main() {
	setup()

	http.HandleFunc("/api/signup", handleSignup)
	http.HandleFunc("/api/oauth/google", handleOAuthGoogle)
	http.HandleFunc("/api/oauth/facebook", handleOAuthFacebook)
	http.HandleFunc("/api/verify", handleSignupVerify)

	// Set up CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"}, // Allow all origins for simplicity, adjust as needed
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000" // Default port if not specified
	}

	handler := c.Handler(http.DefaultServeMux)

	log.Printf("Server starting on port %s...", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func handleSignupVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	email := r.URL.Query().Get("email")

	if token == calculateToken(email) {
		subject := "Welcome to the list"
		text := "Welcome to our mailing list! Here is your link to the pattern library: http://example.com/pattern-library"
		sendEmail(r.Context(), email, subject, text)
		addToMailingList(r.Context(), email, "")
	}

	w.Write([]byte(`{"status":"ok"}`))
}

func calculateToken(email string) string {
	_, we := time.Now().ISOWeek()
	week := strconv.Itoa(we)
	hash := sha256.Sum256([]byte(secretKey + email + week))
	return hex.EncodeToString(hash[:])
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var signupReq SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&signupReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received signup request for email: %s", signupReq.Email)

	// Send verification email
	subject := "Verify your email address"
	text := fmt.Sprintf("Please verify your email by clicking the link: http://localhost:3000/verify?token=%s&email=%s", calculateToken(signupReq.Email), signupReq.Email)
	sendEmail(r.Context(), signupReq.Email, subject, text)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Signup successful. Please check your email to verify your address."))
}

func handleOAuthGoogle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Println("Invalid request method")
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var oauthReq OAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&oauthReq); err != nil {
		log.Println("Invalid request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received Google OAuth token: %s", oauthReq.Token)

	// Use Google OAuth token to fetch user profile information
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token="+oauthReq.Token, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to fetch Google user info", http.StatusUnauthorized)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	if email, ok := userInfo["email"].(string); ok {
		// Handle the case where email is missing
		if email == "" {
			log.Printf("Warning: Email not provided by Google for user: %s", userInfo["name"].(string))
			http.Error(w, `{"error":"Email is required but was not provided by Google. Please ensure email permission is granted."}`, http.StatusBadRequest)
			return
		}

		doMailingListSignUp(req.Context(), email, userInfo["name"].(string))
	}

	log.Printf("User Info: %v", userInfo)

	json.NewEncoder(w).Encode(userInfo)
}

func handleOAuthFacebook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var oauthReq OAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&oauthReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received Facebook OAuth token: %s", oauthReq.Token)

	// Use Facebook OAuth token to fetch user profile information
	client := &http.Client{}
	url := fmt.Sprintf("https://graph.facebook.com/me?fields=id,name,email,picture&access_token=%s", oauthReq.Token)

	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to fetch Facebook user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	var userInfo OAuthResponse
	if err := json.Unmarshal(body, &userInfo); err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	// Handle the case where email is missing
	if userInfo.Email == "" {
		log.Printf("Warning: Email not provided by Facebook for user: %s", userInfo.Name)
		http.Error(w, `{"error":"Email is required but was not provided by Facebook. Please ensure email permission is granted."}`, http.StatusBadRequest)
		return
	}

	doMailingListSignUp(r.Context(), userInfo.Email, userInfo.Name)

	log.Printf("User Info: %+v", userInfo)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userInfo)
}

func doMailingListSignUp(ctx context.Context, email string, name string) {
	if !isOnMailingList(ctx, email) {

		subject := "Welcome to the list"
		text := "Welcome to our mailing list! Here is your link to the pattern library: http://example.com/pattern-library"
		sendEmail(ctx, email, subject, text)
		addToMailingList(ctx, email, name)
	}
}

func sendEmail(ctx context.Context, to string, subject string, text string) {
	mailgunURL := fmt.Sprintf("https://api.mailgun.net/v3/%s/messages", mailgunDomain)

	from := fmt.Sprintf("stevenlawton.com <mailinglist@%s>", mailgunDomain)
	subject = fmt.Sprintf("stevenlawton.com: %s", subject)
	data := url.Values{}
	data.Set("from", from)
	data.Set("to", to)
	data.Set("subject", subject)
	data.Set("text", text)

	req, err := http.NewRequest("POST", mailgunURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}
	req.SetBasicAuth("api", mailgunAPIKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		all, _ := io.ReadAll(resp.Body)

		log.Printf("Failed to send email: %v, %s", err, string(all))
		return
	}

	log.Printf("Email sent successfully to %s", to)
}

func isOnMailingList(ctx context.Context, email string) bool {
	mg := mailgun.NewMailgun(mailgunDomain, mailgunListAPIKey)
	member, err := mg.GetMember(ctx, email, mailgunListAddress)
	if err != nil {
		return false
	}
	log.Printf("Got member: %v", member)
	return true
}

func addToMailingList(ctx context.Context, email string, name string) {
	mailgunListAPIKey := os.Getenv("MAILGUN_MAILING_LIST_API_KEY")
	if mailgunListAPIKey == "" {
		log.Printf("Mailgun API key not set")
		return
	}

	mailgunListAddress := "mailinglist@mail.stevenlawton.com"
	mailgunURL := fmt.Sprintf("https://api.mailgun.net/v3/lists/%s/members", mailgunListAddress)

	data := url.Values{}
	data.Set("address", email)
	data.Set("name", name)
	data.Set("subscribed", "true")
	data.Set("upsert", "true")

	req, err := http.NewRequest("POST", mailgunURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("Failed to create request to add member to mailing list: %v", err)
		return
	}
	req.SetBasicAuth("api", mailgunListAPIKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Printf("Failed to add member to mailing list: %v", err)
		return
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)

	log.Printf("Successfully added %s to the mailing list %s", email, string(b))
}
