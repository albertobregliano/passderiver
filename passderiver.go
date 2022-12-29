// Packet passderiver derives passwords instead of storing them.
// The password will always contain at least a digit a lowercase and an
// uppercase alpha rune and a symbol. All characters are utf8.
// Password length can be chosen from 8 to 21 characters.
// Renewing passwords for the same website can be done chosing a different num.
package passderiver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Derive returns the coded password.
func Derive(userkey []byte, site string, num, length int) string {
	if num <= 0 {
		num = 1
	}
	if length < 8 {
		length = 8
	}
	if length > 21 {
		length = 21
	}
	mac := hmac.New(sha256.New, userkey)
	mac.Write([]byte(site + strconv.Itoa(num)))
	hs := base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
	var hss []rune
	for index, r := range hs {
		if index%2 == 0 {
			hss = append(hss, r)
		}
		if len(hss) == length {
			break
		}
	}
	var seed = 1
	for _, r := range hss {
		seed *= int(r)
	}
	randomizer := rand.New(rand.NewSource(int64(seed * num * length)))
	for index := range hss {
		if index == 4 {
			n := randomElement(LOWER, randomizer)
			hss = append(hss, rune(n))
		}
		if index == 5 {
			n := randomElement(UPPER, randomizer)
			hss = append(hss, rune(n))
		}
		if index == 6 {
			n := randomElement(DIGIT, randomizer)
			hss = append(hss, rune(n))
		}
		if index%7 == 0 {
			n := randomElement(SYMBOL, randomizer)
			hss = append(hss, rune(n))
		}
	}
	pass := hss[len(hss)-length:]
	randomizer.Shuffle(len(pass), func(i, j int) {
		pass[i], pass[j] = pass[j], pass[i]
	})
	if !utf8.Valid([]byte(string(pass))) {
		panic(fmt.Errorf("not utf8"))
	}
	if !checkRequirements(string(pass)) {
		panic(fmt.Errorf("requirements not met"))
	}
	return string(pass)
}

func randomElement(e randomelement, randomizer *rand.Rand) int {
	var n int
LOOP:
	for {
		n = randomizer.Intn(128)
		switch e {
		case DIGIT:
			if unicode.IsDigit(rune(n)) {
				break LOOP
			}
		case UPPER:
			if unicode.IsUpper(rune(n)) {
				break LOOP
			}
		case LOWER:
			if unicode.IsLower(rune(n)) {
				break LOOP
			}
		case SYMBOL:
			if strings.ContainsRune(SYMBOLS, rune(n)) {
				break LOOP
			}
		}
	}
	return n
}

const SYMBOLS string = "#$%&()+,-./:;<=>?@[]^_{}"

func checkRequirements(s string) bool {
	var hasDigit, hasUpper, hasLower, hasSymbol bool
	for _, r := range s {
		if unicode.IsDigit(r) {
			hasDigit = true
		}
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
		if strings.Contains(SYMBOLS, string(r)) {
			hasSymbol = true
		}
	}
	return hasDigit && hasUpper && hasLower && hasSymbol
}
