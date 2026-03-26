package auth

import (
	"errors"
	"fmt"
	"net/http"
	"pkie/db"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	secretKey = []byte("supersecretkey") // In production, use env vars or secure vaults
)

func ValidateAuthentication(r *http.Request) bool {
	_, ok := GetAuthenticatedUsername(r)
	return ok
}

func GetAuthenticatedUsername(r *http.Request) (string, bool) {
	token, err := r.Cookie("Authentication")
	if err != nil || token.Value == "" {
		return "", false
	}

	parsedToken, err := jwt.ParseWithClaims(token.Value, &jwt.RegisteredClaims{}, validateKey)
	if err != nil || !parsedToken.Valid {
		return "", false
	}

	claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	if !ok || claims.Subject == "" {
		return "", false
	}

	return claims.Subject, true
}

func validateKey(parsedToken *jwt.Token) (interface{}, error) {
	if _, ok := parsedToken.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, jwt.ErrSignatureInvalid
	}
	return secretKey, nil
}

func GenerateToken(username string) (string, error) {
	if username == "" {
		return "", errors.New("username cannot be empty")
	}

	claims := jwt.RegisteredClaims{
		Subject:   username,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	if !validateCredentials(username, password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := GenerateToken(username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Set-Cookie", fmt.Sprintf("Authentication=%s; HttpOnly; Path=/; Max-Age=86400", token))
	w.Header().Set("Location", "/")
	w.WriteHeader(302)
}

func validateCredentials(username, password string) bool {
	dbPassword, err := db.GetAdminUser(username)
	if err != nil {
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
	return err == nil
}
