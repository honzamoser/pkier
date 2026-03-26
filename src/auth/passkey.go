package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"pkie/db"

	"github.com/go-webauthn/webauthn/webauthn"
)

const signVerificationTTL = 90 * time.Second

type PassKeyUser struct {
	ID          []byte
	Username    string
	Credentials []webauthn.Credential
}

func (u *PassKeyUser) WebAuthnID() []byte { return u.ID }

func (u *PassKeyUser) WebAuthnName() string { return u.Username }

func (u *PassKeyUser) WebAuthnDisplayName() string { return u.Username }

func (u *PassKeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

var (
	registrationSessions sync.Map
	assertionSessions    sync.Map
	signingVerifications sync.Map
)

func BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, wa, username, err := getCurrentPasskeyUserAndWebAuthn(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	options, session, err := wa.BeginRegistration(user)
	if err != nil {
		http.Error(w, "Failed to begin passkey registration", http.StatusInternalServerError)
		return
	}

	registrationSessions.Store(username, *session)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

func FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, wa, username, err := getCurrentPasskeyUserAndWebAuthn(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	rawSession, ok := registrationSessions.Load(username)
	if !ok {
		http.Error(w, "Registration session not found", http.StatusBadRequest)
		return
	}
	defer registrationSessions.Delete(username)

	session, ok := rawSession.(webauthn.SessionData)
	if !ok {
		http.Error(w, "Invalid registration session", http.StatusBadRequest)
		return
	}

	credential, err := wa.FinishRegistration(user, session, r)
	if err != nil {
		http.Error(w, "Passkey registration failed", http.StatusBadRequest)
		return
	}

	if err := db.SaveAdminWebAuthnCredential(username, credential); err != nil {
		http.Error(w, "Failed to store passkey credential", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func BeginPasskeyAssertion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, wa, username, err := getCurrentPasskeyUserAndWebAuthn(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if len(user.Credentials) == 0 {
		http.Error(w, "No passkeys registered for admin", http.StatusBadRequest)
		return
	}

	options, session, err := wa.BeginLogin(user)
	if err != nil {
		http.Error(w, "Failed to begin passkey verification", http.StatusInternalServerError)
		return
	}

	assertionSessions.Store(username, *session)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

func FinishPasskeyAssertion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, wa, username, err := getCurrentPasskeyUserAndWebAuthn(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	rawSession, ok := assertionSessions.Load(username)
	if !ok {
		http.Error(w, "Assertion session not found", http.StatusBadRequest)
		return
	}
	defer assertionSessions.Delete(username)

	session, ok := rawSession.(webauthn.SessionData)
	if !ok {
		http.Error(w, "Invalid assertion session", http.StatusBadRequest)
		return
	}

	if _, err := wa.FinishLogin(user, session, r); err != nil {
		http.Error(w, "Passkey verification failed", http.StatusUnauthorized)
		return
	}

	signingVerifications.Store(username, time.Now().Add(signVerificationTTL))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func VerifyPasskeyForRequest(r *http.Request) error {
	username, ok := GetAuthenticatedUsername(r)
	if !ok {
		return errors.New("unauthorized")
	}

	verificationDeadline, ok := signingVerifications.Load(username)
	if !ok {
		return errors.New("passkey verification required")
	}

	expiresAt, ok := verificationDeadline.(time.Time)
	if !ok || time.Now().After(expiresAt) {
		signingVerifications.Delete(username)
		return errors.New("passkey verification expired")
	}

	// Require fresh assertion for each sign request.
	signingVerifications.Delete(username)

	return nil
}

func getCurrentPasskeyUserAndWebAuthn(r *http.Request) (*PassKeyUser, *webauthn.WebAuthn, string, error) {
	username, ok := GetAuthenticatedUsername(r)
	if !ok {
		return nil, nil, "", errors.New("unauthorized")
	}

	adminID, err := db.GetAdminID(username)
	if err != nil {
		return nil, nil, "", errors.New("unknown admin")
	}

	credentials, err := db.GetAdminWebAuthnCredentials(username)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to load passkeys")
	}

	user := &PassKeyUser{
		ID:          []byte(fmt.Sprintf("admin-%d", adminID)),
		Username:    username,
		Credentials: credentials,
	}

	wa, err := webauthnForRequest(r)
	if err != nil {
		return nil, nil, "", errors.New("failed to initialize webauthn")
	}

	return user, wa, username, nil
}

func webauthnForRequest(r *http.Request) (*webauthn.WebAuthn, error) {
	host := r.Host
	rpID := host
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		rpID = parsedHost
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	origin := fmt.Sprintf("%s://%s", scheme, host)

	return webauthn.New(&webauthn.Config{
		RPDisplayName: "PKI Manager",
		RPID:          rpID,
		RPOrigins:     []string{origin},
	})
}
