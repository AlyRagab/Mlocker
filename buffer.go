//go:build linux

package mlocker

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/AlyRagab/Mlocker/internal"
)

// SecureBuffer holds encrypted data locked in memory.
type SecureBuffer struct {
	mem        *LockedBuffer
	salt       []byte
	nonce      []byte
	ciphertext []byte
	mac        []byte
	timer      *time.Timer
	destroyed  bool
}

const (
	saltLen  = 16
	nonceLen = 12
	macLen   = 32
)

// EncryptToMemory encrypts data using AES-256-GCM and locks the memory.
// EncryptToMemory encrypts the provided byte slice into a SecureBuffer.
// If ZeroPlaintext is true, the input slice is wiped after encryption.
func EncryptToMemory(data []byte) (SecureBuffer, error) {
	if masterKey == nil {
		if err := Init(); err != nil {
			return SecureBuffer{}, err
		}
	}

	saltBuf, err := AllocateLocked(saltLen)
	if err != nil {
		return SecureBuffer{}, err
	}
	if err = internal.FillRandom(saltBuf.Bytes()); err != nil {
		FreeLocked(saltBuf)
		return SecureBuffer{}, err
	}

	h := hmac.New(sha256.New, masterKeyBytes())
	h.Write(saltBuf.Bytes())
	dkBuf, err := AllocateLocked(32)
	if err != nil {
		FreeLocked(saltBuf)
		return SecureBuffer{}, err
	}
	dk := h.Sum(dkBuf.Bytes()[:0])
	zeroHash(h)
	aead, err := newAEAD(dk)
	if err != nil {
		FreeLocked(saltBuf)
		ZeroLocked(dkBuf)
		FreeLocked(dkBuf)
		return SecureBuffer{}, err
	}

	nonceLenLocal := nonceLen
	ctLen := len(data) + aead.Overhead()
	total := saltLen + nonceLenLocal + ctLen
	if IntegrityCheck {
		total += macLen
	}
	buf, err := AllocateLocked(total)
	if err != nil {
		FreeLocked(saltBuf)
		ZeroLocked(dkBuf)
		FreeLocked(dkBuf)
		return SecureBuffer{}, err
	}

	off := 0
	copy(buf.Bytes()[off:off+saltLen], saltBuf.Bytes())
	ZeroLocked(saltBuf)
	FreeLocked(saltBuf)
	off += saltLen

	nonceSlice := buf.Bytes()[off : off+nonceLenLocal]
	if err = internal.FillRandom(nonceSlice); err != nil {
		FreeLocked(buf)
		ZeroLocked(dkBuf)
		FreeLocked(dkBuf)
		return SecureBuffer{}, err
	}
	off += nonceLenLocal

	ctSlice := buf.Bytes()[off : off+ctLen]
	aead.Seal(ctSlice[:0], nonceSlice, data, nil)
	zeroAEAD(aead)
	if ZeroPlaintext {
		Zero(data)
	}

	var macSlice []byte
	if IntegrityCheck {
		macSlice = buf.Bytes()[off+ctLen : off+ctLen+macLen]
		h2 := hmac.New(sha256.New, dk)
		h2.Write(nonceSlice)
		h2.Write(ctSlice)
		h2.Sum(macSlice[:0])
		zeroHash(h2)
	}
	ZeroLocked(dkBuf)
	FreeLocked(dkBuf)
	sb := SecureBuffer{
		mem:        buf,
		salt:       buf.Bytes()[:saltLen],
		nonce:      nonceSlice,
		ciphertext: ctSlice,
	}
	if IntegrityCheck {
		sb.mac = macSlice
	}
	return sb, nil
}

// EncryptLocked encrypts data stored in a LockedBuffer. This avoids placing the
// plaintext on the Go heap. If ZeroPlaintext is true, the input buffer will be
// zeroed after encryption.
func EncryptLocked(data *LockedBuffer) (SecureBuffer, error) {
	if data == nil {
		return SecureBuffer{}, errors.New("nil input")
	}
	sb, err := EncryptToMemory(data.Bytes())
	if ZeroPlaintext {
		ZeroLocked(data)
	}
	return sb, err
}

// Decrypt decrypts the buffer and returns the plaintext. Caller must zero the plaintext after use.
func (s *SecureBuffer) Decrypt() (*LockedBuffer, error) {
	if s.destroyed {
		return nil, errors.New("buffer destroyed")
	}

	h := hmac.New(sha256.New, masterKeyBytes())
	h.Write(s.salt)
	dkBuf, err := AllocateLocked(32)
	if err != nil {
		return nil, err
	}
	dk := h.Sum(dkBuf.Bytes()[:0])
	zeroHash(h)
	if IntegrityCheck {
		h2 := hmac.New(sha256.New, dk)
		h2.Write(s.nonce)
		h2.Write(s.ciphertext)
		if !hmac.Equal(h2.Sum(nil), s.mac) {
			ZeroLocked(dkBuf)
			FreeLocked(dkBuf)
			zeroHash(h2)
			return nil, errors.New("integrity check failed")
		}
		zeroHash(h2)
	}

	aead, err := newAEAD(dk)
	ZeroLocked(dkBuf)
	FreeLocked(dkBuf)
	if err != nil {
		return nil, err
	}

	ptBuf, err := AllocateLocked(len(s.ciphertext))
	if err != nil {
		return nil, err
	}
	ptSlice := ptBuf.Bytes()
	decrypted, err := aead.Open(ptSlice[:0], s.nonce, s.ciphertext, nil)
	zeroAEAD(aead)
	if err != nil {
		Zero(ptSlice)
		FreeLocked(ptBuf)
		return nil, err
	}
	ptBuf.size = len(decrypted)
	return ptBuf, nil
}

// Use decrypts the buffer and passes the plaintext to the provided function.
// The plaintext is zeroed and freed immediately after the function returns.
func (s *SecureBuffer) Use(fn func([]byte) error) error {
	if fn == nil {
		return errors.New("nil function")
	}
	pt, err := s.Decrypt()
	if err != nil {
		return err
	}
	defer func() {
		ZeroLocked(pt)
		FreeLocked(pt)
	}()
	return fn(pt.Bytes())
}

// DestroyAfter schedules the buffer to be destroyed after the provided duration.
// If called multiple times, any previous timer is stopped.
func (s *SecureBuffer) DestroyAfter(d time.Duration) {
	if s.destroyed {
		return
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(d, func() {
		s.Destroy()
	})
}

// Destroy wipes the buffer and unlocks the memory.
func (s *SecureBuffer) Destroy() error {
	if s.destroyed {
		return nil
	}

	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}

	var integrityErr error
	if IntegrityCheck {
		h := hmac.New(sha256.New, masterKeyBytes())
		h.Write(s.salt)
		dkBuf, err := AllocateLocked(32)
		if err != nil {
			return err
		}
		dk := h.Sum(dkBuf.Bytes()[:0])
		zeroHash(h)
		hmacCheck := hmac.New(sha256.New, dk)
		hmacCheck.Write(s.nonce)
		hmacCheck.Write(s.ciphertext)
		if !hmac.Equal(hmacCheck.Sum(nil), s.mac) {
			integrityErr = errors.New("integrity check failed")
		}
		zeroHash(hmacCheck)
		ZeroLocked(dkBuf)
		FreeLocked(dkBuf)
	}
	ZeroLocked(s.mem)
	errUnlock := FreeLocked(s.mem)
	s.destroyed = true
	s.mem = nil
	s.salt = nil
	s.nonce = nil
	s.ciphertext = nil
	s.mac = nil
	if errUnlock != nil || integrityErr != nil {
		return errors.Join(errUnlock, integrityErr)
	}
	return nil
}
