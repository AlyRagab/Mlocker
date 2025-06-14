//go:build linux

package mlocker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
	"reflect"
	"runtime"
	"unsafe"
)

// allocateToLocked copies the pointed-to struct to locked memory and returns a
// new pointer to the same type backed by the locked buffer. The original object
// is zeroed.
func allocateToLocked(ptr interface{}) (interface{}, *LockedBuffer, error) {
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Pointer {
		return ptr, nil, errors.New("non-pointer type")
	}
	size := int(v.Elem().Type().Size())
	buf, err := AllocateLocked(size)
	if err != nil {
		return nil, nil, err
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(v.Pointer())), size)
	dst := buf.Bytes()
	copy(dst, src)
	zeroBytes(src)
	newPtr := reflect.NewAt(v.Elem().Type(), unsafe.Pointer(&dst[0]))
	runtime.KeepAlive(ptr)
	return newPtr.Interface(), buf, nil
}

type lockedAEAD struct {
	blockBuf *LockedBuffer
	aeadBuf  *LockedBuffer
	aead     cipher.AEAD
}

func (a *lockedAEAD) NonceSize() int { return a.aead.NonceSize() }
func (a *lockedAEAD) Overhead() int  { return a.aead.Overhead() }
func (a *lockedAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return a.aead.Seal(dst, nonce, plaintext, additionalData)
}
func (a *lockedAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return a.aead.Open(dst, nonce, ciphertext, additionalData)
}

func (a *lockedAEAD) Destroy() error {
	zeroAEAD(a.aead)
	err1 := FreeLocked(a.aeadBuf)
	err2 := FreeLocked(a.blockBuf)
	a.aead = nil
	a.aeadBuf = nil
	a.blockBuf = nil
	if err1 != nil || err2 != nil {
		return errors.Join(err1, err2)
	}
	return nil
}

func newAEAD(key []byte) (*lockedAEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Move block state to locked memory
	lbIface, blockBuf, err := allocateToLocked(block)
	if err != nil {
		return nil, err
	}
	block = lbIface.(cipher.Block)

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		FreeLocked(blockBuf)
		return nil, err
	}
	gcmIface, gcmBuf, err := allocateToLocked(gcm)
	if err != nil {
		zeroAEAD(gcm)
		FreeLocked(blockBuf)
		return nil, err
	}

	return &lockedAEAD{
		blockBuf: blockBuf,
		aeadBuf:  gcmBuf,
		aead:     gcmIface.(cipher.AEAD),
	}, nil
}

// zeroAEAD overwrites the internal state of an AEAD implementation.
func zeroAEAD(a cipher.AEAD) {
	if a == nil {
		return
	}
	v := reflect.ValueOf(a)
	if v.Kind() != reflect.Pointer {
		return
	}
	size := int(v.Elem().Type().Size())
	ptr := unsafe.Pointer(v.Pointer())
	zeroBytes(unsafe.Slice((*byte)(ptr), size))
	runtime.KeepAlive(a)
}

// zeroHash overwrites the internal state of a hash.Hash.
func zeroHash(h hash.Hash) {
	if h == nil {
		return
	}
	v := reflect.ValueOf(h)
	if v.Kind() != reflect.Pointer {
		return
	}
	size := int(v.Elem().Type().Size())
	ptr := unsafe.Pointer(v.Pointer())
	zeroBytes(unsafe.Slice((*byte)(ptr), size))
	runtime.KeepAlive(h)
}

type lockedHMAC struct {
	mac      hash.Hash
	macBuf   *LockedBuffer
	innerBuf *LockedBuffer
	outerBuf *LockedBuffer
}

func (h *lockedHMAC) Write(p []byte) (int, error) { return h.mac.Write(p) }
func (h *lockedHMAC) Sum(b []byte) []byte         { return h.mac.Sum(b) }
func (h *lockedHMAC) Reset()                      { h.mac.Reset() }
func (h *lockedHMAC) Size() int                   { return h.mac.Size() }
func (h *lockedHMAC) BlockSize() int              { return h.mac.BlockSize() }

func (h *lockedHMAC) Destroy() error {
	zeroHash(h.mac)
	err1 := FreeLocked(h.macBuf)
	err2 := FreeLocked(h.innerBuf)
	err3 := FreeLocked(h.outerBuf)
	h.mac = nil
	h.macBuf = nil
	h.innerBuf = nil
	h.outerBuf = nil
	if err1 != nil || err2 != nil || err3 != nil {
		return errors.Join(err1, errors.Join(err2, err3))
	}
	return nil
}

func newHMAC(key []byte) (*lockedHMAC, error) {
	m := hmac.New(sha256.New, key)

	mv := reflect.ValueOf(m)
	if mv.Kind() != reflect.Pointer {
		return nil, errors.New("unexpected hmac type")
	}

	// Move inner and outer hash states to locked memory
	innerField := mv.Elem().FieldByName("inner")
	outerField := mv.Elem().FieldByName("outer")
	innerVal := reflect.NewAt(innerField.Type(), unsafe.Pointer(innerField.UnsafeAddr())).Elem()
	outerVal := reflect.NewAt(outerField.Type(), unsafe.Pointer(outerField.UnsafeAddr())).Elem()
	innerHash, innerBuf, err := allocateToLocked(innerVal.Interface())
	if err != nil {
		return nil, err
	}
	outerHash, outerBuf, err := allocateToLocked(outerVal.Interface())
	if err != nil {
		FreeLocked(innerBuf)
		return nil, err
	}
	innerVal.Set(reflect.ValueOf(innerHash))
	outerVal.Set(reflect.ValueOf(outerHash))

	// Now move the HMAC struct itself to locked memory
	hmIface, hmBuf, err := allocateToLocked(m)
	if err != nil {
		FreeLocked(innerBuf)
		FreeLocked(outerBuf)
		return nil, err
	}

	return &lockedHMAC{
		mac:      hmIface.(hash.Hash),
		macBuf:   hmBuf,
		innerBuf: innerBuf,
		outerBuf: outerBuf,
	}, nil
}
