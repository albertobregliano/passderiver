package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/albertobregliano/passderiver"

	"github.com/atotto/clipboard"
)

func main() {

	username := flag.String("u", "", "username")
	site := flag.String("s", "", "website")
	num := flag.Int("n", 1, "number")
	length := flag.Int("l", 12, "length of the password")
	print := flag.Bool("p", false, "print password on screen")
	flag.Parse()

	// Store the mastersecret in a local variable.
	secret := os.Getenv("passderiversecret")
	if secret == "" {
		log.Fatal("passderiver secret not found")
	}

	if *username == "" {
		*username = os.Getenv("passderiveruser")
		fmt.Println("username: ", *username)
	}

	var userSecret = hashify(*username + secret)

	// Customize the salt used in the scrypt.
	passderiver.Salt = []byte("passderiveriscool")

	host := getDomain(*site)
	fmt.Println("site: ", host)

	derivedPwd := string(passderiver.Derive(userSecret, host, *num, *length))

	if *print {
		fmt.Println(derivedPwd)
	} else {
		// The password is copied in the clipboard and not printed.
		err := clipboard.WriteAll(derivedPwd)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func hashify(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func getDomain(u string) string {

	uri, _ := url.Parse(u)

	return uri.Host
}
