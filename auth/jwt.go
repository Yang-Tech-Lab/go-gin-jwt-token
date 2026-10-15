// Package auth issues and validates JWT bearer tokens for Gin handlers.
package auth

import (
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// ClaimsContextKey is the Gin context key under which validated *Claims are stored.
const ClaimsContextKey = "jwtClaims"

// ErrRevoked is returned when a token's jti has been revoked.
var ErrRevoked = errors.New("token revoked")

// RevocationList abstracts a store of revoked token IDs (e.g. Redis SET, DB table).
// A nil implementation means revocation is not enabled.
type RevocationList interface {
	IsRevoked(jti string) bool
}

// Config contains the settings used to issue and validate JWTs.
type Config struct {
	Secret     []byte
	Issuer     string
	TokenTTL   time.Duration
	Audience   string        // optional; validated when non-empty
	ClockSkew  time.Duration // tolerance for exp/iat clock drift; default 60s
	Revocation RevocationList
	Logger     *log.Logger // where validation failures are logged; defaults to log.Default()
}

func (c Config) withDefaults() Config {
	if c.ClockSkew <= 0 {
		c.ClockSkew = 60 * time.Second
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
	return c
}

// Claims are the application-specific JWT claims.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// NewToken signs a token for username with a unique jti so it can be revoked later.
func NewToken(username string, config Config) (string, error) {
	config = config.withDefaults()
	now := time.Now()
	claims := Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   username,
			ID:        newJTI(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(config.TokenTTL)),
		},
	}
	if config.Audience != "" {
		claims.Audience = jwt.ClaimStrings{config.Audience}
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(config.Secret)
}

// Middleware validates a Bearer token and stores its claims in the Gin context.
// Clients always receive the same opaque error; details go to the logger only.
func Middleware(config Config) gin.HandlerFunc {
	config = config.withDefaults()
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(config.Issuer),
		jwt.WithExpirationRequired(), // reject tokens that omit exp entirely
		jwt.WithLeeway(config.ClockSkew),
	)
	if config.Audience != "" {
		parser = jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithIssuer(config.Issuer),
			jwt.WithAudience(config.Audience),
			jwt.WithExpirationRequired(),
			jwt.WithLeeway(config.ClockSkew),
		)
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// WithValidMethods already enforces the algorithm; this is defense in depth.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return config.Secret, nil
	}

	return func(c *gin.Context) {
		tokenString, err := bearerToken(c.GetHeader("Authorization"))
		if err != nil {
			reject(c, config.Logger, err)
			return
		}

		claims := new(Claims)
		token, err := parser.ParseWithClaims(tokenString, claims, keyFunc)
		if err != nil || !token.Valid {
			reject(c, config.Logger, err)
			return
		}

		if config.Revocation != nil && config.Revocation.IsRevoked(claims.ID) {
			reject(c, config.Logger, ErrRevoked)
			return
		}

		c.Set(ClaimsContextKey, claims)
		c.Next()
	}
}

// ClaimsFrom retrieves the validated claims injected by Middleware.
// It panics only if the route was not protected by Middleware — a programming error.
func ClaimsFrom(c *gin.Context) *Claims {
	value, ok := c.Get(ClaimsContextKey)
	if !ok {
		panic("auth: claims missing from context; is the route behind auth.Middleware?")
	}
	claims, ok := value.(*Claims)
	if !ok {
		panic("auth: context value is not *auth.Claims")
	}
	return claims
}

func bearerToken(header string) (string, error) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", errors.New("authorization header must use Bearer token")
	}
	return parts[1], nil
}

func reject(c *gin.Context, logger *log.Logger, err error) {
	logger.Printf("auth: rejected request %s %s: %v", c.Request.Method, c.Request.URL.Path, err)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
}

// ConstantTimeCompare exposes a timing-safe credential comparison for login handlers.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
