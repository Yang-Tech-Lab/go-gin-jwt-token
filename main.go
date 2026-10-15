package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"go-gin-jwt-token/auth"
)

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func main() {
	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmsgprefix)

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		logger.Fatal("JWT_SECRET must be set")
	}

	config, err := loadConfig(secret, logger)
	if err != nil {
		logger.Fatal(err)
	}

	router := newRouter(config)
	server := &http.Server{
		Addr:              envDefault("LISTEN_ADDR", ":8080"),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second, // Slowloris protection
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Printf("graceful shutdown failed: %v", err)
		}
	}()

	logger.Printf("listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatal(err)
	}
	<-shutdownDone
}

func loadConfig(secret string, logger *log.Logger) (auth.Config, error) {
	ttlMinutes, err := strconv.Atoi(envDefault("JWT_TTL_MINUTES", "15"))
	if err != nil || ttlMinutes <= 0 {
		return auth.Config{}, errors.New("JWT_TTL_MINUTES must be a positive integer")
	}
	skewSeconds, err := strconv.Atoi(envDefault("JWT_CLOCK_SKEW_SECONDS", "60"))
	if err != nil || skewSeconds < 0 {
		return auth.Config{}, errors.New("JWT_CLOCK_SKEW_SECONDS must be a non-negative integer")
	}

	return auth.Config{
		Secret:    []byte(secret),
		Issuer:    envDefault("JWT_ISSUER", "go-gin-jwt-token"),
		Audience:  os.Getenv("JWT_AUDIENCE"),
		TokenTTL:  time.Duration(ttlMinutes) * time.Minute,
		ClockSkew: time.Duration(skewSeconds) * time.Second,
		Logger:    logger,
	}, nil
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func newRouter(jwtConfig auth.Config) *gin.Engine {
	router := gin.Default()
	router.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	router.POST("/login", loginHandler(jwtConfig))

	protected := router.Group("/")
	protected.Use(auth.Middleware(jwtConfig))
	protected.GET("/profile", func(c *gin.Context) {
		claims := auth.ClaimsFrom(c)
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

		// Demonstration credentials only — replace with a database lookup that
		// verifies a bcrypt/argon2 hash of the stored password.
		if !auth.ConstantTimeCompare(request.Username, "demo") ||
			!auth.ConstantTimeCompare(request.Password, "demo-password") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		token, err := auth.NewToken(request.Username, jwtConfig)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"token":      token,
			"token_type": "Bearer",
			"expires_in": int(jwtConfig.TokenTTL.Seconds()),
		})
	}
}
