package app

import (
	"fmt"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

var (
	secretKey                 = []byte(Env("SECRET_KEY", "secret"))
	accessTokenExpireDuration = 24 * time.Hour
)

func generateAPIKey() string {
	return uuid.New().String()
}

func Env(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func createAccessToken(email, apiKey string) (string, error) {
	claims := jwt.MapClaims{
		"sub":     email,
		"api_key": apiKey,
		"exp":     time.Now().Add(accessTokenExpireDuration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func decodeAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return token.Claims.(jwt.MapClaims), nil
}