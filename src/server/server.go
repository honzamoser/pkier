package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"pkie/auth"
	"pkie/db"
)

func StartServer() {
	// 3. Setup HTTP Routes

	http.Handle("/", http.FileServer(http.Dir("./public")))

	http.HandleFunc("/api/certs", handleListCerts)

	fmt.Println("🚀 CA Manager running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

}

func RegisterHandler(path string, handlerFunc http.HandlerFunc) {
	http.HandleFunc(path, handlerFunc)
}

func handleListCerts(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateAuthentication(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	certs, err := db.GetValidCertificates()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certs)
}
