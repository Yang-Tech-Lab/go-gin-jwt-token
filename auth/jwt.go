package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Config contains the settings used to issue and validate JWTs.
type Config struct {
	Secret   []byte
	Issuer   string
	TokenTTL time.Duration
}

// Claims are the application-specific JWT claims.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// NewToken signs a token for username.
func NewToken(username string, config Config) (string, error) {
	now := time.Now()
	claims := Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(config.TokenTTL)),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(config.Secret)
}

// Middleware validates a Bearer token and stores its claims in the Gin context.
func Middleware(config Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := bearerToken(c.GetHeader("Authorization"))
		if err != nil {
			unauthorized(c, err.Error())
			return
		}

		claims := new(Claims)
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}
			return config.Secret, nil
		}, jwt.WithIssuer(config.Issuer), jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
		if err != nil || !token.Valid {
			unauthorized(c, "invalid or expired token")
			return
		}

		c.Set("jwtClaims", claims)
		c.Next()
	}
}

func bearerToken(header string) (string, error) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", errors.New("authorization header must use Bearer token")
	}
	return parts[1], nil
}

func unauthorized(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": message})
}
