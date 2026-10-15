package auth

import (
	"crypto/rand"
	"encoding/hex"
)

// newJTI returns a random 128-bit token ID in hex form.
func newJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("auth: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
