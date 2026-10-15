package auth

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func testConfig() Config {
	return Config{
		Secret:   []byte("test-secret"),
		Issuer:   "test",
		TokenTTL: time.Hour,
		Logger:   log.New(io.Discard, "", 0),
	}
}

func protectedRouter(config Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	group := router.Group("/")
	group.Use(Middleware(config))
	group.GET("/profile", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"username": ClaimsFrom(c).Username})
	})
	return router
}

func get(router *gin.Engine, header string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/profile", nil)
	if header != "" {
		request.Header.Set("Authorization", header)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"Bearer abc", "abc"},
		{"bearer abc", "abc"},
		{"BEARER  abc", "abc"},
	}
	for _, tc := range cases {
		got, err := bearerToken(tc.header)
		if err != nil || got != tc.want {
			t.Errorf("bearerToken(%q) = %q, %v; want %q, nil", tc.header, got, err, tc.want)
		}
	}

	bad := []string{"", "Bearer", "Bearer ", "Basic abc", "Token abc def"}
	for _, header := range bad {
		if _, err := bearerToken(header); err == nil {
			t.Errorf("bearerToken(%q): expected error", header)
		}
	}
}

func TestMiddlewareAcceptsValidToken(t *testing.T) {
	config := testConfig()
	token, err := NewToken("alice", config)
	if err != nil {
		t.Fatal(err)
	}

	response := get(protectedRouter(config), "Bearer "+token)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(`"alice"`)) {
		t.Errorf("body = %s, want username alice", response.Body)
	}
}

func TestMiddlewareRejectsExpiredToken(t *testing.T) {
	config := testConfig()
	config.TokenTTL = -time.Minute // already expired
	token, err := NewToken("alice", config)
	if err != nil {
		t.Fatal(err)
	}

	response := get(protectedRouter(testConfig()), "Bearer "+token)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestMiddlewareRejectsTokenWithoutExpiry(t *testing.T) {
	config := testConfig()
	// Craft a correctly signed token that omits exp entirely.
	claims := Claims{Username: "mallory", RegisteredClaims: jwt.RegisteredClaims{Issuer: config.Issuer}}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(config.Secret)
	if err != nil {
		t.Fatal(err)
	}

	response := get(protectedRouter(config), "Bearer "+token)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for token without exp", response.Code)
	}
}

func TestMiddlewareRejectsWrongIssuer(t *testing.T) {
	config := testConfig()
	other := config
	other.Issuer = "someone-else"
	token, err := NewToken("alice", other)
	if err != nil {
		t.Fatal(err)
	}

	response := get(protectedRouter(config), "Bearer "+token)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestMiddlewareRejectsWrongSecret(t *testing.T) {
	config := testConfig()
	other := config
	other.Secret = []byte("different-secret")
	token, err := NewToken("alice", other)
	if err != nil {
		t.Fatal(err)
	}

	response := get(protectedRouter(config), "Bearer "+token)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestMiddlewareRejectsAlgNone(t *testing.T) {
	config := testConfig()
	// Unsigned "alg: none" token — classic JWT attack.
	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, Claims{
		Username: "mallory",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	token, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}

	response := get(protectedRouter(config), "Bearer "+token)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for alg=none token", response.Code)
	}
}

type staticRevocation struct{ jti string }

func (s staticRevocation) IsRevoked(jti string) bool { return jti == s.jti }

func TestMiddlewareHonorsRevocationList(t *testing.T) {
	config := testConfig()
	token, err := NewToken("alice", config)
	if err != nil {
		t.Fatal(err)
	}
	parsed := new(Claims)
	if _, _, err := new(jwt.Parser).ParseUnverified(token, parsed); err != nil {
		t.Fatal(err)
	}
	jti := parsed.ID
	if jti == "" {
		t.Fatal("issued token has no jti")
	}

	config.Revocation = staticRevocation{jti: jti}
	response := get(protectedRouter(config), "Bearer "+token)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for revoked token", response.Code)
	}
}

func TestErrorToClientIsOpaque(t *testing.T) {
	config := testConfig()
	var logs bytes.Buffer
	config.Logger = log.New(&logs, "", 0)

	response := get(protectedRouter(config), "Bearer not.a.jwt")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
	if got, want := response.Body.String(), `{"error":"invalid or expired token"}`; !strings.Contains(got, want) {
		t.Errorf("client body = %s, want opaque error %q", got, want)
	}
	if logs.Len() == 0 {
		t.Error("expected validation failure to be logged server-side")
	}
}
