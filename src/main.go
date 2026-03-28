package main

import (
	"pkie/auth"
	"pkie/ca"
	"pkie/config"
	"pkie/db"
	"pkie/server"

	_ "github.com/mattn/go-sqlite3"
)

var KEY_DIR = "./keys"

func main() {
	defaultConfig, err := config.Load("./config.toml")
	if err != nil {
		panic(err)
	}
	db.InitalizeDB(defaultConfig)
	ca.InitCA(defaultConfig)

	server.RegisterHandler("/api/sign", ca.HandleSignCSR)
	server.RegisterHandler("/api/auth", auth.SignIn)
	server.RegisterHandler("/api/passkey/register/begin", auth.BeginPasskeyRegistration)
	server.RegisterHandler("/api/passkey/register/finish", auth.FinishPasskeyRegistration)
	server.RegisterHandler("/api/passkey/assertion/begin", auth.BeginPasskeyAssertion)
	server.RegisterHandler("/api/passkey/assertion/finish", auth.FinishPasskeyAssertion)

	server.StartServer()

}
