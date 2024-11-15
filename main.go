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
	"github.com/stevenlawton/go-telegram-alert"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
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

	loggingBotToken string
	loggingBotChat  int64

	secretKey  string
	baseURL    string
	port       string
	corsOrigin string
)

func setup() {
	currentDir, err := os.Getwd()

	if err := godotenv.Load(currentDir + "/.env"); err != nil {
		log.Println("INFO: No .env file found")
	} else {
		log.Println("INFO: .env file loaded successfully")
	}

	mailgunAPIKey = os.Getenv("MAILGUN_MAILING_LIST_API_KEY")
	if mailgunAPIKey == "" {
		log.Fatalf("Mailgun API key not set")
	}

	mailgunListAPIKey = os.Getenv("MAILGUN_MAILING_LIST_API_KEY")
	if mailgunListAPIKey == "" {
		log.Fatalf("FATAL: Mailgun list API key not set")
	}

	mailgunDomain = os.Getenv("MAILGUN_DOMAIN")
	if mailgunDomain == "" {
		log.Fatalf("FATAL: Mailgun domain not set")
	}

	mailgunListAddress = os.Getenv("MAILGUN_LIST_ADDRESS")
	if mailgunListAddress == "" {
		log.Fatalf("FATAL: Mailgun list address not set")
	}

	mailgunSender = os.Getenv("MAILGUN_SENDER")
	if mailgunSender == "" {
		log.Fatalf("FATAL: Mailgun sender not set")
	}

	mailgunSubjectPrefix = os.Getenv("MAILGUN_SUBJECT_PREFIX")
	if mailgunSubjectPrefix == "" {
		log.Fatalf("FATAL: Mailgun subject prefix not set")
	}

	validationEmailTemplateName = os.Getenv("VALIDATION_EMAIL_TEMPLATE")
	if validationEmailTemplateName == "" {
		log.Fatalf("FATAL: Validation email template name not set")
	}

	validationEmailTemplateSubject = os.Getenv("VALIDATION_EMAIL_TEMPLATE_SUBJECT")
	if validationEmailTemplateName == "" {
		log.Fatalf("FATAL: Validation email template subject not set")
	}

	welcomeEmailTemplateName = os.Getenv("WELCOME_EMAIL_TEMPLATE")
	if welcomeEmailTemplateName == "" {
		log.Fatalf("FATAL: Welcome email template name not set")
	}

	welcomeEmailTemplateSubject = os.Getenv("WELCOME_EMAIL_TEMPLATE_SUBJECT")
	if welcomeEmailTemplateSubject == "" {
		log.Fatalf("FATAL: Welcome email template subject not set")
	}

	loggingBotToken = os.Getenv("LOGGING_BOT_TOKEN")
	if loggingBotToken == "" {
		log.Fatalf("FATAL: Logging bot token not set")
	}

	loggingBotChatStr := os.Getenv("LOGGING_BOT_CHAT")
	if loggingBotChatStr == "" {
		log.Printf("INFO: Logging bot chat not set")
	} else {
		loggingBotChat, err = strconv.ParseInt(loggingBotChatStr, 10, 64)
		if err != nil {
			log.Printf("INFO: Logging bot chat not valid")
		}
	}

	secretKey = os.Getenv("SECRET_KEY")
	if secretKey == "" {
		log.Fatalf("FATAL: Secret key not set")
	}

	baseURL = os.Getenv("BASE_URL")
	if baseURL == "" {
		log.Fatalf("FATAL: Base URL not set")
	}

	port = os.Getenv("PORT")
	if port == "" {
		port = "3000"
		log.Fatalf("FATAL: port not set (defaulting to 3000)")
	}

	corsOrigin = os.Getenv("CORS_ORIGIN")
	if corsOrigin == "" {
		log.Printf("INFO: cors Origin not set (defaulting to 3000)")
		corsOrigin = "*"
	}

}

func main() {
	setup()

	err := gotelalert.NewTeleLogger(loggingBotToken, loggingBotChat)
	if err != nil {
		log.Fatalf("FATAL: Failed to create TeleLogger: %v", err)
	}

	http.HandleFunc("/mail/api/signup", handleSignup)
	http.HandleFunc("/mail/api/verify", handleSignupVerify)
	http.HandleFunc("/mail/api/oauth/google", handleOAuthGoogle)
	http.HandleFunc("/mail/api/oauth/facebook", handleOAuthFacebook)

	c := cors.New(cors.Options{
		AllowedOrigins: []string{corsOrigin},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	})

	handler := c.Handler(http.DefaultServeMux)

	log.Printf("INFO: Server starting on port %s...", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("FATAL: Failed to start server: %v", err)
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
	log.Printf("INFO: Received signup request for email: %s", signupReq.Email)
	if !isOnMailingList(r.Context(), signupReq.Email) {
		value := fmt.Sprintf(`%s:%s/api/verify?token=%s&email=%s`, baseURL, port, calculateToken(signupReq.Email), signupReq.Email)
		params := map[string]string{
			"validation_email_link": value,
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		err := sendTemplateEmail(ctx, validationEmailTemplateName, validationEmailTemplateSubject, signupReq.Email, params)
		if err != nil {
			log.Printf("ERROR: failed to send template email: %s to %s [%v] :: %v", validationEmailTemplateName, signupReq.Email, params, err)
			http.Error(w, "send Template Email error", http.StatusBadRequest)
			return
		}
	}
	log.Printf("INFO: Email verification started request for email: %s", signupReq.Email)
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
			log.Printf("ERROR: failed to send email to %s :: %v", email, err)
			http.Error(w, "send Mailing List Email error", http.StatusBadRequest)
			return
		}

		log.Printf("INFO: Email verification completed request for email: %s", email)
		_, err = w.Write([]byte(`{"status":"ok"}`))
		if err != nil {
			return
		}
		return
	}
	http.Error(w, "Invalid request", http.StatusBadRequest)
}

func handleOAuthGoogle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	var oauthReq OAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&oauthReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	data, err := getGoogleData(oauthReq)
	if err != nil {
		http.Error(w, "failed to get google data", http.StatusBadRequest)
		return
	}
	err = doMailingListSignUp(r.Context(), data.Email, data.Name)
	if err != nil {
		log.Printf("ERROR: (google) failed to send email to %s :: %v", data.Email, err)
		http.Error(w, "send Mailing List Email error", http.StatusBadRequest)
		return
	}
	log.Printf("INFO: (google) email added: %s", data.Email)
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
		http.Error(w, "error getting FB data", http.StatusInternalServerError)
		return
	}
	err = doMailingListSignUp(r.Context(), userInfo.Email, userInfo.Name)
	if err != nil {
		log.Printf("ERROR: (fb) failed to send email to %s :: %v", userInfo.Email, err)
		http.Error(w, "send Mailing List Email error", http.StatusBadRequest)
		return
	}
	log.Printf("INFO: (FB) email added: %s", userInfo.Email)
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
	_, _, err = mg.Send(ctx, message)
	if err != nil {
		return err
	}
	return nil
}

func isOnMailingList(ctx context.Context, email string) bool {
	mg := mailgun.NewMailgun(mailgunDomain, mailgunListAPIKey)
	_, err := mg.GetMember(ctx, email, mailgunListAddress)
	if err != nil {
		return false
	}
	return true
}

func addToMailingList(ctx context.Context, email string, name string) error {
	mg := mailgun.NewMailgun(mailgunDomain, mailgunListAPIKey)
	err := mg.CreateMember(ctx, true, mailgunListAddress,
		mailgun.Member{
			Address:    email,
			Name:       name,
			Subscribed: mailgun.Subscribed,
		})
	if err != nil {
		return err
	}
	log.Printf("INFO: Successfully added %s to the mailing list %s", email, mailgunListAddress)
	return nil
}
