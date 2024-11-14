package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleSignup(t *testing.T) {
	setup() // Set up environment variables

	// Test Cases
	tests := []struct {
		name         string
		method       string
		requestBody  SignupRequest
		expectedCode int
	}{
		{
			name:         "Valid Signup Request",
			method:       http.MethodPost,
			requestBody:  SignupRequest{Email: "valid@example.com"},
			expectedCode: http.StatusOK,
		},
		{
			name:         "Invalid HTTP Method",
			method:       http.MethodGet,
			requestBody:  SignupRequest{},
			expectedCode: http.StatusMethodNotAllowed,
		},
		{
			name:         "Invalid Request Body",
			method:       http.MethodPost,
			requestBody:  SignupRequest{},
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare request
			requestBodyBytes, _ := json.Marshal(tt.requestBody)
			req, err := http.NewRequest(tt.method, "/api/signup", bytes.NewReader(requestBodyBytes))
			if err != nil {
				t.Fatalf("could not create request: %v", err)
			}

			req.Header.Set("Content-Type", "application/json")
			// Record Response
			rec := httptest.NewRecorder()
			http.HandlerFunc(handleSignup).ServeHTTP(rec, req)

			// Assert Response
			if rec.Code != tt.expectedCode {
				t.Errorf("expected status %d; got %d", tt.expectedCode, rec.Code)
			}
		})
	}
}

func TestHandleSignupVerify(t *testing.T) {
	setup() // Set up environment variables

	// Test Cases
	tests := []struct {
		name         string
		queryParams  string
		expectedCode int
	}{
		{
			name:         "Valid Verification",
			queryParams:  "?token=" + calculateToken("valid@example.com") + "&email=valid@example.com",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Invalid Token",
			queryParams:  "?token=invalidtoken&email=valid@example.com",
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare request
			req, err := http.NewRequest(http.MethodGet, "/api/verify"+tt.queryParams, nil)
			if err != nil {
				t.Fatalf("could not create request: %v", err)
			}

			// Record Response
			rec := httptest.NewRecorder()
			http.HandlerFunc(handleSignupVerify).ServeHTTP(rec, req)

			// Assert Response
			if rec.Code != tt.expectedCode {
				t.Errorf("expected status %d; got %d", tt.expectedCode, rec.Code)
			}
		})
	}
}

func TestHandleOAuthGoogle(t *testing.T) {
	setup() // Set up environment variables

	// Test Cases
	tests := []struct {
		name         string
		method       string
		requestBody  OAuthRequest
		expectedCode int
	}{
		{
			name:         "Valid OAuthRequest - bad token",
			method:       http.MethodPost,
			requestBody:  OAuthRequest{Token: "invalid-token"},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "Invalid HTTP Method",
			method:       http.MethodGet,
			expectedCode: http.StatusMethodNotAllowed,
		},
		{
			name:         "Invalid Request Body",
			method:       http.MethodPost,
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare request
			requestBodyBytes, _ := json.Marshal(tt.requestBody)
			req, err := http.NewRequest(tt.method, "/api/oauth/google", bytes.NewReader(requestBodyBytes))
			if err != nil {
				t.Fatalf("could not create request: %v", err)
			}

			req.Header.Set("Content-Type", "application/json")
			// Record Response
			rec := httptest.NewRecorder()
			http.HandlerFunc(handleOAuthGoogle).ServeHTTP(rec, req)

			// Assert Response
			if rec.Code != tt.expectedCode {
				t.Errorf("expected status %d; got %d", tt.expectedCode, rec.Code)
			}
		})
	}
}
