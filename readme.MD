# Golang OAuth Mailing List API

This project is a Go-based web application that allows users to sign up for a mailing list through Google and Facebook OAuth authentication or by submitting their email addresses directly. The application then sends a verification email, and if validated, adds the user to a mailing list powered by Mailgun.

## Features
- **Google and Facebook OAuth Integration**: Allows users to sign up using Google or Facebook authentication.
- **Email Verification**: Generates a token and sends a verification link to ensure email validity before adding users to the mailing list.
- **Mailgun Integration**: Uses Mailgun for sending verification emails and managing mailing lists.
- **CORS Support**: Supports Cross-Origin Resource Sharing (CORS) for API access from different domains.
- **Dockerized Workflow**: Uses a multi-stage Dockerfile for building, testing, and running the application efficiently.

## Prerequisites
- **Go**: Ensure you have Go installed (version 1.17 or above).
- **Mailgun Account**: You need an account and API key from Mailgun for email sending functionality.
- - 2 templates setup welcome email and validation email 
- **Facebook and Google OAuth Credentials**: Set up applications on Facebook and Google Developer Consoles to obtain API credentials.
- **Environment Variables**: Use a `.env` file or environment variables for sensitive information like API keys and OAuth credentials.

### Required Environment Variables
- `MAILGUN_API_KEY`: Your Mailgun API key for sending emails.
- `MAILGUN_LIST_ADDRESS`: The mailing list address for adding members.
- `SECRET_KEY`: Secret key for generating email verification tokens.
- `MAILGUN_MAILING_LIST_API_KEY`: API key specifically for managing the mailing list.
- `MAILGUN_DOMAIN`: Domain name for Mailgun.
- `PORT`: Port number for running the server (optional, defaults to 3000).

### Example `.env` file
```env
MAILGUN_API_KEY=1234
MAILGUN_MAILING_LIST_API_KEY=1234

MAILGUN_DOMAIN=mail.example.com
MAILGUN_LIST_ADDRESS=mailinglist@mail.example.com
MAILGUN_SENDER='example.com <mailinglist@mail.example.com>'
MAILGUN_SUBJECT_PREFIX='example.com: '

VALIDATION_EMAIL_TEMPLATE='email validation'
VALIDATION_EMAIL_TEMPLATE_SUBJECT='Email Signup Validation'

WELCOME_EMAIL_TEMPLATE='welcome email'
WELCOME_EMAIL_TEMPLATE_SUBJECT='Welcome to Our Community'

BASE_URL=http://localhost
PORT=3000
CORS_ORIGIN=*

LOGGING_BOT_TOKEN=1234
LOGGING_BOT_CHAT=-1

SECRET_KEY=12345
```

## Running the Project

### Install Dependencies
To run this project, first make sure all dependencies are installed. Use Go modules to install dependencies such as `github.com/joho/godotenv` for loading environment variables and `github.com/rs/cors` for handling CORS.

```sh
go mod tidy
```

### Start the Server
Run the following command to start the server:

```sh
go run main.go
```

The server should start on the port defined in your `.env` file (default: 3000).

### Running with Docker
You can build, test, and run the application using Docker.

1. **Build and Test**: The provided Dockerfile has a multi-stage setup to build, test, and finally package the application.

   ```sh
   docker build -t mailing-list-backend .
   ```

2. **Run**: After building, you can run the application in a minimal container.

   ```sh
   docker run -p 3000:3000 mailing-list-backend
   ```

## API Endpoints

### 1. `/api/signup` (POST)
Handles direct email signup.
- **Request Body**: JSON object with `email` field.
- **Response**: Sends a verification email to the user.

### 2. `/api/oauth/google` (POST)
Handles Google OAuth sign-up.
- **Request Body**: JSON object with `token` field containing the Google OAuth token.
- **Response**: Adds the user to the mailing list and sends a welcome email.

### 3. `/api/oauth/facebook` (POST)
Handles Facebook OAuth sign-up.
- **Request Body**: JSON object with `token` field containing the Facebook OAuth token.
- **Response**: Adds the user to the mailing list and sends a welcome email.

### 4. `/api/verify` (GET)
Verifies user email using a token.
- **Query Parameters**:
  - `token`: The verification token.
  - `email`: The email address to verify.
- **Response**: Adds the user to the mailing list if the token is valid.

## Code Overview

### Main Functions
- **`main()`**: Loads environment variables, sets up HTTP handlers, and starts the server.
- **`handleSignup()`**: Generates and sends a verification email with a link that contains a token.
- **`handleOAuthGoogle()`** and **`handleOAuthFacebook()`**: Accept OAuth tokens, validate them with Google/Facebook, and add the user to the mailing list.
- **`handleSignupVerify()`**: Verifies the user's email using a token.

### Helper Functions
- **`sendTemplateEmail()`**: Uses Mailgun to send emails based on a template.
- **`addToMailingList()`**: Adds a verified user to the Mailgun mailing list.
- **`calculateToken()`**: Generates a verification token based on a secret key, email, and the current week.
- **`isOnMailingList()`**: Checks whether the user is already on the mailing list.

## Development Notes
- **Testing OAuth Handlers**: When testing OAuth endpoints, ensure you provide valid Google and Facebook tokens to get meaningful responses.
- **Mailgun**: Ensure you have the correct permissions for the API keys to access the necessary Mailgun features.
- **Unit Testing**: The project includes unit tests for key handlers such as `handleSignup()`, `handleSignupVerify()`, and `handleOAuthGoogle()`. Run tests using the following command:

  ```sh
  go test -v ./...
  ```

## Example Usage
To sign up with an email, make a `POST` request to `/api/signup`:

```sh
curl -X POST http://localhost:3000/api/signup -H "Content-Type: application/json" -d '{"email":"example@example.com"}'
```

To verify the signup, the user needs to click the link sent to their email which directs them to `/api/verify`.

## Troubleshooting
- **Environment Variables Missing**: Ensure all required variables are set in the `.env` file.
- **CORS Issues**: If CORS issues arise, consider adding allowed origins explicitly.
- **Mailgun Authorization**: Check if your Mailgun API keys are correct and authorized for your domain.
- **OAuth Token Validation**: Ensure that the tokens provided are valid and that you have permissions set up on your Google and Facebook apps.

## License
This project is licensed under the MIT License.

