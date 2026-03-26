package main

import (
	"crypto/ecdsa"
	"crypto/x509"

	"pkie/auth"
	"pkie/ca"
	"pkie/config"
	"pkie/db"
	"pkie/server"

	_ "github.com/mattn/go-sqlite3"
	"software.sslmate.com/src/go-pkcs12"
)

var KEY_DIR = "./keys"

var (
	caPrivKey     *ecdsa.PrivateKey
	caCert        *x509.Certificate
	pkcs12Encoder *pkcs12.Encoder
)

type CertRecord struct {
	Serial  string `json:"serial"`
	Subject string `json:"subject"`
	Status  string `json:"status"`
	Expiry  string `json:"expiry"`
}

func main() {
	config.GetConfig()
	db.InitalizeDB()
	ca.InitCA()

	server.RegisterHandler("/api/sign", ca.HandleSignCSR)
	server.RegisterHandler("/api/auth", auth.SignIn)
	server.RegisterHandler("/api/passkey/register/begin", auth.BeginPasskeyRegistration)
	server.RegisterHandler("/api/passkey/register/finish", auth.FinishPasskeyRegistration)
	server.RegisterHandler("/api/passkey/assertion/begin", auth.BeginPasskeyAssertion)
	server.RegisterHandler("/api/passkey/assertion/finish", auth.FinishPasskeyAssertion)

	server.StartServer()

}
