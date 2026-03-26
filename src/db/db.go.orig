package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/bcrypt"
)

var Db *sql.DB

type CertRecord struct {
	Serial  string `json:"serial"`
	Subject string `json:"subject"`
	Status  string `json:"status"`
	Expiry  string `json:"expiry"`
}

func InitalizeDB() {

	var err error
	// 1. Init Database
	Db, err = sql.Open("sqlite3", "./light_pki.db")
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}

	defaultPasswordHash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)

	if err != nil {
		log.Printf("Password hash error: %v", err)
		return
	}

	query := `CREATE TABLE IF NOT EXISTS certificates (
		serial_number TEXT PRIMARY KEY,
		subject TEXT NOT NULL,
		status TEXT NOT NULL,
		issue_date DATETIME NOT NULL,
		expiry_date DATETIME NOT NULL,
		pem_data TEXT NOT NULL
	);
	
	CREATE TABLE IF NOT EXISTS admins (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL
	);
	
	CREATE TABLE IF NOT EXISTS passkeys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		admin_id INTEGER NOT NULL UNIQUE,
		FOREIGN KEY (admin_id) REFERENCES admins(id)
	);

	CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		credential_id BLOB NOT NULL UNIQUE,
		credential_json TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		admin_id INTEGER NOT NULL,
		FOREIGN KEY (admin_id) REFERENCES admins(id)
	);
	
	INSERT OR IGNORE INTO admins (username, password_hash) VALUES ('admin', ?);`
	if _, err := Db.Exec(query, defaultPasswordHash); err != nil {
		log.Printf("DB setup error: %v", err)
	}
}

func SaveSignedSignature(
	serialNumber string,
	subject string,
	status string,
	issueDate string,
	expiryDate string,
	pemData string,
) {
	Db.Exec(`INSERT INTO certificates (serial_number, subject, status, issue_date, expiry_date, pem_data) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		serialNumber, subject, status, issueDate, expiryDate, pemData)
}

func GetValidCertificates() ([]CertRecord, error) {
	rows, err := Db.Query("SELECT serial_number, subject, status, expiry_date FROM certificates ORDER BY issue_date DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certs := []CertRecord{}
	for rows.Next() {
		var c CertRecord
		var exp string
		rows.Scan(&c.Serial, &c.Subject, &c.Status, &exp)
		c.Expiry = exp
		certs = append(certs, c)
	}

	return certs, nil
}

func GetAdminUser(username string) (string, error) {
	var passwordHash string
	err := Db.QueryRow("SELECT password_hash FROM admins WHERE username = ?", username).Scan(&passwordHash)
	if err != nil {
		return "", err
	}
	return passwordHash, nil
}

func SaveAdminPasskey(username, passkey string) error {
	if username == "" || passkey == "" {
		return errors.New("username and passkey are required")
	}

	var adminID int
	if err := Db.QueryRow("SELECT id FROM admins WHERE username = ?", username).Scan(&adminID); err != nil {
		return err
	}

	passkeyHash, err := bcrypt.GenerateFromPassword([]byte(passkey), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = Db.Exec(`
		INSERT INTO passkeys (key, created_at, admin_id)
		VALUES (?, datetime('now'), ?)
		ON CONFLICT(admin_id) DO UPDATE SET
			key=excluded.key,
			created_at=datetime('now')
	`, string(passkeyHash), adminID)

	return err
}

func VerifyAdminPasskey(username, passkey string) (bool, error) {
	if username == "" || passkey == "" {
		return false, errors.New("username and passkey are required")
	}

	var passkeyHash string
	err := Db.QueryRow(`
		SELECT p.key
		FROM passkeys p
		JOIN admins a ON a.id = p.admin_id
		WHERE a.username = ?
	`, username).Scan(&passkeyHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passkeyHash), []byte(passkey)); err != nil {
		return false, nil
	}

	return true, nil
}

func GetAdminID(username string) (int, error) {
	if username == "" {
		return 0, errors.New("username is required")
	}

	var adminID int
	err := Db.QueryRow("SELECT id FROM admins WHERE username = ?", username).Scan(&adminID)
	if err != nil {
		return 0, err
	}

	return adminID, nil
}

func SaveAdminWebAuthnCredential(username string, credential *webauthn.Credential) error {
	if username == "" || credential == nil || len(credential.ID) == 0 {
		return errors.New("invalid credential input")
	}

	adminID, err := GetAdminID(username)
	if err != nil {
		return err
	}

	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		return err
	}

	_, err = Db.Exec(`
		INSERT INTO webauthn_credentials (credential_id, credential_json, created_at, admin_id)
		VALUES (?, ?, datetime('now'), ?)
		ON CONFLICT(credential_id) DO UPDATE SET
			credential_json = excluded.credential_json,
			created_at = datetime('now'),
			admin_id = excluded.admin_id
	`, credential.ID, string(credentialJSON), adminID)

	return err
}

func GetAdminWebAuthnCredentials(username string) ([]webauthn.Credential, error) {
	adminID, err := GetAdminID(username)
	if err != nil {
		return nil, err
	}

	rows, err := Db.Query(`
		SELECT credential_json
		FROM webauthn_credentials
		WHERE admin_id = ?
		ORDER BY created_at DESC
	`, adminID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	credentials := make([]webauthn.Credential, 0)
	for rows.Next() {
		var rawJSON string
		if err := rows.Scan(&rawJSON); err != nil {
			return nil, err
		}

		var credential webauthn.Credential
		if err := json.Unmarshal([]byte(rawJSON), &credential); err != nil {
			continue
		}
		credentials = append(credentials, credential)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return credentials, nil
}
