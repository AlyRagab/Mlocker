//go:build linux

package mlocker

import "testing"

func TestZero(t *testing.T) {
	b := []byte("secret")
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zero", i)
		}
	}
}

func TestAllocateAndFreeLocked(t *testing.T) {
	b, err := AllocateLocked(16)
	if err != nil {
		t.Fatalf("allocate failed: %v", err)
	}
	if b == nil || b.ptr == nil {
		t.Fatalf("allocate returned nil buffer")
	}
	ZeroLocked(b)
	if err := FreeLocked(b); err != nil {
		t.Fatalf("free failed: %v", err)
	}
}

func TestEncryptDestroy(t *testing.T) {
	ZeroPlaintext = true
	data := []byte("password")
	buf, err := EncryptToMemory(data)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("plaintext slice unexpectedly empty")
	}
	for _, v := range data {
		if v != 0 {
			t.Fatalf("plaintext not zeroed")
		}
	}
	if err := buf.Destroy(); err != nil {
		t.Fatalf("destroy failed: %v", err)
	}
}

func TestEncryptWipesPlaintext(t *testing.T) {
	ZeroPlaintext = false
	data := []byte("wipe-me")
	if _, err := EncryptToMemory(data); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	for i, v := range data {
		if v != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
	}
}
