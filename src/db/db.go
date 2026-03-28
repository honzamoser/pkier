package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"pkie/config"
	"time"

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

// CertificateRequest represents an incoming CSR waiting for approval.
type CertificateRequest struct {
	ID             int64
	RawCSRPEM      string
	Subject        string
	RequestedSANs  []string // We will marshal/unmarshal this to JSON
	Status         string   // PENDING, APPROVED, REJECTED
	RequestedAt    time.Time
	ResolvedAt     *time.Time // Pointer because it can be NULL
	ResolvedByUser *int64     // Pointer because it can be NULL
}

// Certificate represents a finalized, signed X.509 certificate.
type Certificate struct {
	SerialNumber     string // 160-bit int stored as hex string
	RequestID        int64
	AuthorityID      int64
	Type             string // SERVER, CLIENT, BOTH
	Subject          string
	SANs             []string
	ValidNotBefore   time.Time
	ValidNotAfter    time.Time
	Status           string // ACTIVE, REVOKED, EXPIRED
	RevokedAt        *time.Time
	RevocationReason *string
	CreatedAt        time.Time
}

// PKIDAO handles all database operations for the CA pipeline.
type PKIDAO struct {
	db *sql.DB
}

// NewPKIDAO initializes a new DAO.
// Note: Ensure your DSN includes "?parseTime=true" when opening the sqlite3 DB!
func NewPKIDAO(db *sql.DB) *PKIDAO {
	return &PKIDAO{db: db}
}

// ==========================================
// Certificate Request Operations
// ==========================================

// InsertRequest saves a new CSR submitted by a device.
func (dao *PKIDAO) InsertRequest(ctx context.Context, req *CertificateRequest) (int64, error) {
	query := `
		INSERT INTO certificate_requests (raw_csr_pem, subject, requested_sans_json, status)
		VALUES (?, ?, ?, 'PENDING')
	`

	sansJSON, err := json.Marshal(req.RequestedSANs)
	if err != nil {
		return 0, err
	}

	result, err := dao.db.ExecContext(ctx, query, req.RawCSRPEM, req.Subject, string(sansJSON))
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// GetPendingRequests fetches all unapproved CSRs for the admin dashboard.
func (dao *PKIDAO) GetPendingRequests(ctx context.Context) ([]*CertificateRequest, error) {
	query := `
		SELECT id, raw_csr_pem, subject, requested_sans_json, status, requested_at 
		FROM certificate_requests 
		WHERE status = 'PENDING' 
		ORDER BY requested_at ASC
	`
	rows, err := dao.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []*CertificateRequest
	for rows.Next() {
		var req CertificateRequest
		var sansJSON string

		err := rows.Scan(
			&req.ID, &req.RawCSRPEM, &req.Subject,
			&sansJSON, &req.Status, &req.RequestedAt,
		)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(sansJSON), &req.RequestedSANs); err != nil {
			return nil, err
		}

		requests = append(requests, &req)
	}

	return requests, rows.Err()
}

// ResolveRequest is called when you click "Approve" or "Reject" in the dashboard.
func (dao *PKIDAO) ResolveRequest(ctx context.Context, requestID int64, status string, userID int64) error {
	query := `
		UPDATE certificate_requests 
		SET status = ?, resolved_at = CURRENT_TIMESTAMP, resolved_by_user_id = ?
		WHERE id = ? AND status = 'PENDING'
	`
	_, err := dao.db.ExecContext(ctx, query, status, userID, requestID)
	return err
}

// ==========================================
// Certificate Operations
// ==========================================

// InsertCertificate saves the finalized certificate after signing.
// Ideally, you would call this inside a database transaction alongside ResolveRequest.
func (dao *PKIDAO) InsertCertificate(ctx context.Context, cert *Certificate) error {
	query := `
		INSERT INTO certificates (
			serial_number, request_id, authority_id, type, subject, 
			sans_json, valid_not_before, valid_not_after, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
	`

	sansJSON, err := json.Marshal(cert.SANs)
	if err != nil {
		return err
	}

	_, err = dao.db.ExecContext(ctx, query,
		cert.SerialNumber, cert.RequestID, cert.AuthorityID, cert.Type,
		cert.Subject, string(sansJSON), cert.ValidNotBefore, cert.ValidNotAfter,
	)

	return err
}

// RevokeCertificate marks a certificate as revoked so it can be added to the next CRL.
func (dao *PKIDAO) RevokeCertificate(ctx context.Context, serialNumber string, reason string) error {
	query := `
		UPDATE certificates 
		SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP, revocation_reason = ?
		WHERE serial_number = ? AND status = 'ACTIVE'
	`
	_, err := dao.db.ExecContext(ctx, query, reason, serialNumber)
	return err
}

func InitalizeDB(cfg *config.Config) {

	var err error
	// 1. Init Database
	Db, err = sql.Open(cfg.Database.Driver, cfg.Database.DSN+"?parseTime=true")
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}

	defaultPasswordHash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)

	if err != nil {
		log.Printf("Password hash error: %v", err)
		return
	}

	query := `CREATE TABLE certificate_requests (
    	id INTEGER PRIMARY KEY AUTOINCREMENT,
    	raw_csr_pem TEXT NOT NULL,
    	subject TEXT NOT NULL,
	
    	-- Store parsed SANs as a JSON array: '["homelab.local", "192.168.1.50"]'
    	requested_sans_json TEXT, 
	
    	status TEXT NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'APPROVED', 'REJECTED'
	
    	-- Audit trail
    	requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    	resolved_at DATETIME,
    	resolved_by_user_id INTEGER,
    	FOREIGN KEY(resolved_by_user_id) REFERENCES users(id)
	);
	
	CREATE TABLE certificates (
	    -- The PK is the 160-bit serial number stored as a string
	    serial_number TEXT PRIMARY KEY, 
	
	    request_id INTEGER NOT NULL,
	    authority_id INTEGER NOT NULL, -- Which Intermediate CA signed this?
	
	    type TEXT NOT NULL, -- 'SERVER', 'CLIENT', or 'BOTH'
	    subject TEXT NOT NULL,
	    sans_json TEXT,
	
	    valid_not_before DATETIME NOT NULL,
	    valid_not_after DATETIME NOT NULL,
	
	    status TEXT NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'REVOKED', 'EXPIRED'
	    revoked_at DATETIME,
	    revocation_reason TEXT,
	
	    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	
	    FOREIGN KEY(request_id) REFERENCES certificate_requests(id),
	    FOREIGN KEY(authority_id) REFERENCES authorities(id)
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

	CREATE TABLE authorities (
    	id INTEGER PRIMARY KEY AUTOINCREMENT,
    	name TEXT NOT NULL,
    	type TEXT NOT NULL, -- 'ROOT' or 'INTERMEDIATE'
    	parent_authority_id INTEGER, -- NULL if Root
    	serial_number TEXT UNIQUE NOT NULL,
    	subject TEXT NOT NULL,
    	valid_not_before DATETIME NOT NULL,
    	valid_not_after DATETIME NOT NULL,
    	status TEXT NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'REVOKED', 'EXPIRED'
    	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    	FOREIGN KEY(parent_authority_id) REFERENCES authorities(id)
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
