//go:build linux

package internal

import "crypto/rand"

// FillRandom overwrites b with cryptographically secure random bytes.
func FillRandom(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	_, err := rand.Read(b)
	return err
}
