package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"pkie/auth"
	"pkie/db"
)

// RequireAuth middleware checks FIDO2/JWT auth state
func RequireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.ValidateAuthentication(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// StartServer starts the HTTP listeners
func StartServer() {
	http.HandleFunc("/api/certs", RequireAuth(handleListCerts))
	http.HandleFunc("/api/dashboard", RequireAuth(handleDashboardJSON))

	// Serve SPA and static assets
	http.HandleFunc("/", serveSPA)

	fmt.Println("🚀 CA Manager running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// RegisterHandler allows main to register ad-hoc routes
func RegisterHandler(path string, handlerFunc http.HandlerFunc) {
	http.HandleFunc(path, handlerFunc)
}

func handleListCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := db.GetValidCertificates()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certs)
}

func handleDashboardJSON(w http.ResponseWriter, r *http.Request) {
	metrics := db.GetDashboardMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func serveSPA(w http.ResponseWriter, r *http.Request) {
	publicDir := "./public"
	path := filepath.Join(publicDir, r.URL.Path)

	// Prevent directory traversal
	if strings.Contains(path, "..") {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// If file exists, serve it
	info, err := os.Stat(path)
	if err == nil && !info.IsDir() {
		http.ServeFile(w, r, path)
		return
	}

	// Otherwise, serve index.html for SPA routing
	http.ServeFile(w, r, filepath.Join(publicDir, "index.html"))
}
