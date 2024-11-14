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
	mailgunAPIKey        string
	mailgunDomain        string
	mailgunListAddress   string
	mailgunListAPIKey    string
	mailgunSender        string
	mailgunSubjectPrefix string

	validationEmailTemplateName    string
	validationEmailTemplateSubject string
	welcomeEmailTemplateName       string
	welcomeEmailTemplateSubject    string

	secretKey  string
	baseURL    string
	port       string
	corsOrigin string
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

	mailgunSender = os.Getenv("MAILGUN_SENDER")
	if mailgunSender == "" {
		log.Printf("Mailgun sender not set")
	}

	mailgunSubjectPrefix = os.Getenv("MAILGUN_SUBJECT_PREFIX")
	if mailgunSubjectPrefix == "" {
		log.Printf("Mailgun subject prefix not set")
	}

	validationEmailTemplateName = os.Getenv("VALIDATION_EMAIL_TEMPLATE")
	if validationEmailTemplateName == "" {
		log.Printf("Validation email template name not set")
	}

	validationEmailTemplateSubject = os.Getenv("VALIDATION_EMAIL_TEMPLATE_SUBJECT")
	if validationEmailTemplateName == "" {
		log.Printf("Validation email template subject not set")
	}

	welcomeEmailTemplateName = os.Getenv("WELCOME_EMAIL_TEMPLATE")
	if welcomeEmailTemplateName == "" {
		log.Printf("Welcome email template name not set")
	}

	welcomeEmailTemplateSubject = os.Getenv("WELCOME_EMAIL_TEMPLATE_SUBJECT")
	if welcomeEmailTemplateSubject == "" {
		log.Printf("Welcome email template subject not set")
	}

	secretKey = os.Getenv("SECRET_KEY")
	if secretKey == "" {
		log.Printf("Secret key not set")
	}

	baseURL = os.Getenv("BASE_URL")
	if baseURL == "" {
		log.Printf("Base URL not set")
	}

	port = os.Getenv("PORT")
	if port == "" {
		log.Printf("port not set (defaulting to 3000)")
		port = "3000"
	}

	corsOrigin = os.Getenv("CORS_ORIGIN")
	if corsOrigin == "" {
		log.Printf("cors Origin not set (defaulting to 3000)")
		corsOrigin = "*"
	}

}

func main() {
	setup()

	http.HandleFunc("/api/signup", handleSignup)
	http.HandleFunc("/api/verify", handleSignupVerify)
	http.HandleFunc("/api/oauth/google", handleOAuthGoogle)
	http.HandleFunc("/api/oauth/facebook", handleOAuthFacebook)

	c := cors.New(cors.Options{
		AllowedOrigins: []string{corsOrigin},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	})

	handler := c.Handler(http.DefaultServeMux)

	log.Printf("Server starting on port %s...", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
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
	if !isOnMailingList(r.Context(), signupReq.Email) {
		value := fmt.Sprintf(`%s/verify?token=%s&email=%s`, baseURL, calculateToken(signupReq.Email), signupReq.Email)
		params := map[string]string{
			"validation_email_link": value,
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		err := sendTemplateEmail(ctx, validationEmailTemplateName, validationEmailTemplateSubject, signupReq.Email, params)
		if err != nil {
			http.Error(w, "send Template Email error", http.StatusBadRequest)
			return
		}
	}
	_, err := w.Write([]byte(`{"status":"ok"}`))
	if err != nil {
		return
	}
}

func handleSignupVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	email := r.URL.Query().Get("email")

	if token == calculateToken(email) {
		err := doMailingListSignUp(r.Context(), email, "")
		if err != nil {
			http.Error(w, "send Mailing List Email error", http.StatusBadRequest)
			return
		}
	}
	_, err := w.Write([]byte(`{"status":"ok"}`))
	if err != nil {
		return
	}
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

	data, err := getGoogleData(oauthReq)
	if err != nil {
		return
	}

	err = doMailingListSignUp(r.Context(), data.Email, data.Name)
	if err != nil {
		http.Error(w, "send Mailing List Email error", http.StatusBadRequest)
		return
	}

	_, err = w.Write([]byte(`{"status":"ok"}`))
	if err != nil {
		return
	}
}

func getGoogleData(oauthReq OAuthRequest) (OAuthResponse, error) {
	// Use Google OAuth token to fetch user profile information
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token="+oauthReq.Token, nil)
	if err != nil {
		return OAuthResponse{}, err
	}

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return OAuthResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return OAuthResponse{}, err
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return OAuthResponse{}, err
	}

	// Assuming userInfo is a map[string]interface{}
	email, ok := userInfo["email"].(string)
	if !ok {
		return OAuthResponse{}, fmt.Errorf("could not parse email from user info")
	}

	name, ok := userInfo["name"].(string)
	if !ok {
		return OAuthResponse{}, fmt.Errorf("could not parse name from user info")
	}

	pictureUrl, ok := userInfo["picture"].(string)
	if !ok {
		return OAuthResponse{}, fmt.Errorf("could not parse picture URL from user info")
	}

	// Construct the OAuthResponse with validated data
	return OAuthResponse{
		ID:    email,
		Name:  name,
		Email: email,
		Picture: struct {
			Data struct {
				Url string `json:"url"`
			} `json:"data"`
		}{
			Data: struct {
				Url string `json:"url"`
			}{
				Url: pictureUrl,
			},
		},
	}, nil
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

	userInfo, err := getFBData(oauthReq)
	if err != nil {
		log.Printf("error getting FB data : %v", err)
		http.Error(w, "error getting FB data", http.StatusInternalServerError)
		return
	}

	err = doMailingListSignUp(r.Context(), userInfo.Email, userInfo.Name)
	if err != nil {
		log.Printf("send Mailing List Email error for %s : %v", userInfo.Email, err)
		http.Error(w, "send Mailing List Email error", http.StatusBadRequest)
		return
	}

	_, err = w.Write([]byte(`{"status":"ok"}`))
	if err != nil {
		return
	}
}

func getFBData(oauthReq OAuthRequest) (OAuthResponse, error) {
	// Use Facebook OAuth token to fetch user profile information
	client := &http.Client{}
	oAuthURL := fmt.Sprintf("https://graph.facebook.com/me?fields=id,name,email,picture&access_token=%s", oauthReq.Token)

	resp, err := client.Get(oAuthURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return OAuthResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return OAuthResponse{}, err
	}

	var userInfo OAuthResponse
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return OAuthResponse{}, err
	}
	return userInfo, nil
}

func doMailingListSignUp(ctx context.Context, email string, name string) error {
	if email == "" {
		return fmt.Errorf("email is empty")
	}
	if !isOnMailingList(ctx, email) {
		err := sendTemplateEmail(ctx, welcomeEmailTemplateName, welcomeEmailTemplateSubject, email, nil)
		if err != nil {
			return fmt.Errorf("sending '%s' to %s <%s> failed: %v", welcomeEmailTemplateName, name, email, err)
		}
		err = addToMailingList(ctx, email, name)
		if err != nil {
			return fmt.Errorf("addding %s <%s> to mailing list failed: %v", name, email, err)
		}
	} else {
		return fmt.Errorf("email is already on the list : %s", email)
	}
	return nil
}

func sendTemplateEmail(ctx context.Context, template string, subject string, to string, variables map[string]string) error {
	mg := mailgun.NewMailgun(mailgunDomain, mailgunListAPIKey)
	t, err := mg.GetTemplate(ctx, template)
	if err != nil {
		return err
	}

	message := mailgun.NewMessage(mailgunSender, mailgunSubjectPrefix+subject, "", to)
	message.SetTemplate(t.Name)
	if variables != nil {
		for key, val := range variables {
			err := message.AddTemplateVariable(key, val)
			if err != nil {
				return err
			}
		}
	}

	msg, id, err := mg.Send(ctx, message)
	if err != nil {
		return err
	}
	log.Printf("%s -> msg: %s", id, msg)
	return nil
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

func addToMailingList(ctx context.Context, email string, name string) error {
	mailgunURL := fmt.Sprintf("https://api.mailgun.net/v3/lists/%s/members", mailgunListAddress)

	data := url.Values{}
	data.Set("address", email)
	data.Set("name", name)
	data.Set("subscribed", "true")
	data.Set("upsert", "true")

	req, err := http.NewRequest("POST", mailgunURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("Failed to create request to add member to mailing list: %v", err)
		return err
	}
	req.SetBasicAuth("api", mailgunListAPIKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Printf("Failed to add member to mailing list: %v", err)
		return err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)

	log.Printf("Successfully added %s to the mailing list %s", email, string(b))
	return nil
}
