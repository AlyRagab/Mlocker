//go:build linux

package mlocker

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"
	"reflect"
	"runtime"
	"unsafe"
)

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
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
