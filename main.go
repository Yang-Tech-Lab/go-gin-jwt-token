package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"go-gin-jwt-token/auth"
)

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func main() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET must be set")
	}

	config := auth.Config{
		Secret:   []byte(secret),
		Issuer:   "go-gin-jwt-token",
		TokenTTL: 24 * time.Hour,
	}

	router := newRouter(config)
	if err := router.Run(); err != nil {
		log.Fatal(err)
	}
}

func newRouter(jwtConfig auth.Config) *gin.Engine {
	router := gin.Default()
	router.POST("/login", loginHandler(jwtConfig))

	protected := router.Group("/")
	protected.Use(auth.Middleware(jwtConfig))
	protected.GET("/profile", func(c *gin.Context) {
		claims := c.MustGet("jwtClaims").(*auth.Claims)
		c.JSON(http.StatusOK, gin.H{"username": claims.Username})
	})

	return router
}

func loginHandler(jwtConfig auth.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request loginRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
			return
		}

		// Replace this demonstration check with your database/password-hash verification.
		if request.Username != "demo" || request.Password != "demo-password" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		token, err := auth.NewToken(request.Username, jwtConfig)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": token, "token_type": "Bearer", "expires_in": int(jwtConfig.TokenTTL.Seconds())})
	}
}
