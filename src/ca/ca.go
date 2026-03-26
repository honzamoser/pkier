package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"pkie/auth"
	"pkie/config"
	"pkie/db"
	"strconv"
	"strings"
	"time"
)

var KEY_DIR = "./keys"

var (
	caRegistry = make(map[int]*CAEntry)
	rootCAPrivKey *ecdsa.PrivateKey
	rootCACert    *x509.Certificate
)

type CAEntry struct {
	ID      int
	Name    string
	CAType  string
	PrivKey *ecdsa.PrivateKey
	Cert    *x509.Certificate
	CertPEM string
}


func checkExists(fileName string) bool {
	_, err := os.Stat(fileName)
	return !errors.Is(err, os.ErrNotExist)
}

func clearKeyDir() {
	files, _ := os.ReadDir(KEY_DIR)
	for _, f := range files {
		os.Remove(KEY_DIR + "/" + f.Name())
	}
}

func createKeyFiles() (*os.File, *os.File) {
	keyFile, _ := os.Create(KEY_DIR + "/ca_key.pem")
	certFile, _ := os.Create(KEY_DIR + "/ca_cert.pem")
	return keyFile, certFile
}
	func InitCA() {
	caKeyExists := checkExists(KEY_DIR + "/ca_key.pem")
	caCertExists := checkExists(KEY_DIR + "/ca_cert.pem")

	if !caCertExists || !caKeyExists {
		fmt.Println("No existing CA found, generating new one...")

		rootCAPrivKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTemplate := x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Lightweight Root CA"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		caBytes, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &rootCAPrivKey.PublicKey, rootCAPrivKey)
		rootCACert, _ = x509.ParseCertificate(caBytes)
		fmt.Println("✅ Root CA Initialized")

		// Save to PEM files
		os.MkdirAll(KEY_DIR, 0700)
		clearKeyDir()
		keyFile, certFile := createKeyFiles()

		var pemMarshalled, _ = x509.MarshalECPrivateKey(rootCAPrivKey)

		pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: pemMarshalled})
		pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	} else {
		fmt.Println("Existing CA found, loading from files...")
		keyData, _ := os.ReadFile(KEY_DIR + "/ca_key.pem")
		certData, _ := os.ReadFile(KEY_DIR + "/ca_cert.pem")

		block, _ := pem.Decode(keyData)
		rootCAPrivKey, _ = x509.ParseECPrivateKey(block.Bytes)

		block, _ = pem.Decode(certData)
		rootCACert, _ = x509.ParseCertificate(block.Bytes)
		fmt.Println("✅ Root CA Loaded")
	}

	certPEMData, _ := os.ReadFile(KEY_DIR + "/ca_cert.pem")

	caRegistry[0] = &CAEntry{
		ID:      0,
		Name:    "Root CA",
		CAType:  "root",
		PrivKey: rootCAPrivKey,
		Cert:    rootCACert,
		CertPEM: string(certPEMData),
	}

	cas, err := db.GetCAs()
	if err == nil {
		for _, c := range cas {
			cb, _ := pem.Decode([]byte(c.CertPEM))
			kb, _ := pem.Decode([]byte(c.KeyPEM))
			var priv *ecdsa.PrivateKey
			if kb != nil {
				priv, _ = x509.ParseECPrivateKey(kb.Bytes)
				if priv == nil {
					keyAny, _ := x509.ParsePKCS8PrivateKey(kb.Bytes)
					if keyAny != nil {
					     priv = keyAny.(*ecdsa.PrivateKey)
					}
				}
			}
			var cert *x509.Certificate
			if cb != nil {
				cert, _ = x509.ParseCertificate(cb.Bytes)
			}
			caRegistry[c.ID] = &CAEntry{
				ID:      c.ID,
				Name:    c.Name,
				CAType:  c.CAType,
				PrivKey: priv,
				Cert:    cert,
				CertPEM: c.CertPEM,
			}
		}
	}
}

func generateCA(name, caType string, signingCAID int) (certPEM, keyPEM string, err error) {
	// Get signing CA (default to root CA if not specified or not found)
	signingCA, ok := caRegistry[signingCAID]
	if !ok || signingCA.PrivKey == nil {
		signingCA = caRegistry[0] // Use root CA
	}

	// Generate new private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Set certificate validity based on type
	notBefore := time.Now()
	var notAfter time.Time
	var isCA bool
	if caType == "intermediate" {
		notAfter = notBefore.AddDate(5, 0, 0) // 5 years for intermediate CA
		isCA = true
	} else {
		notAfter = notBefore.AddDate(3, 0, 0) // 3 years for leaf CA
		isCA = true
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, signingCA.Cert, &privKey.PublicKey, signingCA.PrivKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))

	return certPEM, keyPEM, nil
}

func HandleListCAs(w http.ResponseWriter, r *http.Request) {
    if !auth.ValidateAuthentication(r) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    type caResp struct {
        ID int `json:"id"`
        Name string `json:"name"`
        CAType string `json:"ca_type"`
        CertPEM string `json:"cert_pem"`
    }

    var resp []caResp
    for _, ca := range caRegistry {
        resp = append(resp, caResp{
            ID: ca.ID,
            Name: ca.Name,
            CAType: ca.CAType,
            CertPEM: ca.CertPEM,
        })
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

func HandleAddCA(w http.ResponseWriter, r *http.Request) {
    if !auth.ValidateAuthentication(r) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    if r.Method != http.MethodPost {
        http.Error(w, "Method format invalid", http.StatusMethodNotAllowed)
        return
    }

    var req struct {
        Name          string `json:"name"`
        CAType        string `json:"ca_type"`
        CertPEM       string `json:"cert_pem"`
        KeyPEM        string `json:"key_pem"`
        AutoGenerate  bool   `json:"auto_generate"`
        SigningCAID   int    `json:"signing_ca_id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid Request", http.StatusBadRequest)
        return
    }

    var certPEM, keyPEM string
    var err error

    // If auto_generate is true, generate the certificate and key
    if req.AutoGenerate {
        certPEM, keyPEM, err = generateCA(req.Name, req.CAType, req.SigningCAID)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to generate CA: %v", err), http.StatusInternalServerError)
            return
        }
    } else {
        // Use provided certificate and key
        if req.CertPEM == "" || req.KeyPEM == "" {
            http.Error(w, "Certificate and key are required when not auto-generating", http.StatusBadRequest)
            return
        }
        certPEM = req.CertPEM
        keyPEM = req.KeyPEM
    }

    if err := db.InsertCA(req.Name, req.CAType, certPEM, keyPEM); err != nil {
        http.Error(w, "DB Insert Error", http.StatusInternalServerError)
        return
    }

    InitCA()

    // Return the generated certificate and key if auto-generated
    if req.AutoGenerate {
        response := map[string]string{
            "cert_pem": certPEM,
            "key_pem":  keyPEM,
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    } else {
        w.Write([]byte("OK"))
    }
}

func HandleDeleteCA(w http.ResponseWriter, r *http.Request) {
    if !auth.ValidateAuthentication(r) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    if r.Method != http.MethodPost {
        http.Error(w, "Method format invalid", http.StatusMethodNotAllowed)
        return
    }
    
    idStr := r.URL.Query().Get("id")
    id, _ := strconv.Atoi(idStr)
    if id == 0 {
         http.Error(w, "Cannot delete root", http.StatusBadRequest)
         return
    }
    
    if err := db.DeleteCA(id); err != nil {
        http.Error(w, "DB Delete Error", http.StatusInternalServerError)
        return
    }
    
    delete(caRegistry, id)
    w.Write([]byte("OK"))
}


func HandleSignCSR(w http.ResponseWriter, r *http.Request) {

	if !auth.ValidateAuthentication(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := auth.VerifyPasskeyForRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	config := config.GetConfig()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	fmt.Println(string(body))
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "Invalid PEM encoded CSR", http.StatusBadRequest)
		return
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "Failed to parse CSR", http.StatusBadRequest)
		return
	}

	if err := validateCSRPolicySANs(csr, config.Policy.DefaultSANs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create new certificate template based on CSR
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0) // 1 year validity

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Sign the certificate using our Root CA
	caIdStr := r.URL.Query().Get("ca_id")
	caId, _ := strconv.Atoi(caIdStr)
	selectedCA, ok := caRegistry[caId]
	if !ok || selectedCA.PrivKey == nil {
		http.Error(w, "CA not found or missing private key", http.StatusBadRequest)
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, selectedCA.Cert, csr.PublicKey, selectedCA.PrivKey)
	if err != nil {
		http.Error(w, "Failed to sign certificate", http.StatusInternalServerError)
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// Save to SQLite
	db.SaveSignedSignature(
		serialNumber.String(),
		csr.Subject.CommonName,
		"Valid",
		notBefore.Format("2006-01-02 15:04"),
		notAfter.Format("2006-01-02 15:04"),
		string(certPEM),
	)

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(certPEM)
}

func validateCSRPolicySANs(csr *x509.CertificateRequest, policySANs config.DefaultSANsConfig) error {
	hasDNS := len(csr.DNSNames) > 0
	hasIPs := len(csr.IPAddresses) > 0
	if !hasDNS && !hasIPs {
		return fmt.Errorf("CSR must include at least one SAN entry (DNS or IP)")
	}

	allowedDNS := make(map[string]struct{}, len(policySANs.DNS))
	for _, d := range policySANs.DNS {
		allowedDNS[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}

	allowedIPs := make(map[string]struct{}, len(policySANs.IPs))
	for _, ip := range policySANs.IPs {
		parsed := net.ParseIP(strings.TrimSpace(ip))
		if parsed == nil {
			continue
		}
		allowedIPs[parsed.String()] = struct{}{}
	}

	for _, dns := range csr.DNSNames {
		if !isAllowedDNSName(dns, allowedDNS) {
			return fmt.Errorf("CSR contains disallowed DNS SAN: %s", dns)
		}
	}

	for _, ip := range csr.IPAddresses {
		if _, ok := allowedIPs[ip.String()]; !ok {
			return fmt.Errorf("CSR contains disallowed IP SAN: %s", ip.String())
		}
	}

	return nil
}

func isAllowedDNSName(candidate string, allowedDNS map[string]struct{}) bool {
	normalized := strings.ToLower(strings.TrimSpace(candidate))
	if _, ok := allowedDNS[normalized]; ok {
		return true
	}

	for pattern := range allowedDNS {
		if !strings.HasPrefix(pattern, "*.") {
			continue
		}
		suffix := pattern[1:]
		if strings.HasSuffix(normalized, suffix) {
			prefix := strings.TrimSuffix(normalized, suffix)
			if prefix != "" && !strings.Contains(prefix, ".") {
				return true
			}
		}
	}

	return false
}
