package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"os"

	"github.com/albertobregliano/passderiver"

	"github.com/atotto/clipboard"
)

func main() {

	username := flag.String("u", "", "username")
	site := flag.String("s", "", "website")
	num := flag.Int("n", 1, "number")
	length := flag.Int("l", 12, "length of the password")
	flag.Parse()

	// Store the mastersecret in a local variable.
	secret := os.Getenv("passderiversecret")
	if secret == "" {
		log.Fatal("passderiver secret not found")
	}

	var userSecret = hashify(*username + secret)

	// Customize the salt used in the scrypt.
	passderiver.Salt = []byte("passderiveriscool")

	derivedPwd := string(passderiver.Derive(userSecret, *site, *num, *length))

	// The password is copied in the clipboard and not printed.
	err := clipboard.WriteAll(derivedPwd)
	if err != nil {
		log.Fatal(err)
	}
}

func hashify(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
