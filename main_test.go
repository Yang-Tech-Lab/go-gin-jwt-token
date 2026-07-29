package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"go-gin-jwt-token/auth"
)

func TestLoginAndProtectedRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config := auth.Config{Secret: []byte("test-secret"), Issuer: "test", TokenTTL: time.Hour}
	router := newRouter(config)

	login := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":"demo","password":"demo-password"}`))
	login.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	router.ServeHTTP(loginResponse, login)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", loginResponse.Code, loginResponse.Body.String())
	}

	var loginBody struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(loginResponse.Body.Bytes(), &loginBody); err != nil {
		t.Fatal(err)
	}
	if loginBody.Token == "" {
		t.Fatal("login response did not contain a token")
	}
	profile := httptest.NewRequest(http.MethodGet, "/profile", nil)
	profile.Header.Set("Authorization", "Bearer "+loginBody.Token)
	profileResponse := httptest.NewRecorder()
	router.ServeHTTP(profileResponse, profile)
	if profileResponse.Code != http.StatusOK {
		t.Fatalf("profile status = %d, body = %s", profileResponse.Code, profileResponse.Body.String())
	}
}

func TestProtectedRouteRejectsMissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := newRouter(auth.Config{Secret: []byte("test-secret"), Issuer: "test", TokenTTL: time.Hour})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/profile", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}
