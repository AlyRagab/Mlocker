//go:build linux

package mlocker

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// LockedBuffer represents memory allocated outside of Go's heap and locked to prevent swapping.
type LockedBuffer struct {
	ptr  unsafe.Pointer
	size int
}

// Bytes returns a slice referencing the locked memory.
func (b *LockedBuffer) Bytes() []byte {
	if b == nil || b.ptr == nil {
		return nil
	}
	return unsafe.Slice((*byte)(b.ptr), b.size)
}

func AllocateLocked(size int) (*LockedBuffer, error) {
	return allocateLocked(size)
}

func FreeLocked(b *LockedBuffer) error {
	return freeLocked(b)
}

func ZeroLocked(b *LockedBuffer) {
	if b == nil || b.ptr == nil {
		return
	}
	Zero(b.Bytes())
}

func allocateLocked(size int) (*LockedBuffer, error) {
	if size <= 0 {
		return nil, errors.New("invalid size")
	}
	mem, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, err
	}
	if err := lockMemory(mem); err != nil {
		syscall.Munmap(mem)
		return nil, err
	}
	lb := &LockedBuffer{ptr: unsafe.Pointer(&mem[0]), size: size}
	runtime.KeepAlive(mem)
	return lb, nil
}

func freeLocked(b *LockedBuffer) error {
	if b == nil || b.ptr == nil {
		return nil
	}
	mem := unsafe.Slice((*byte)(b.ptr), b.size)
	Zero(mem)
	if err := unlockMemory(mem); err != nil {
		return err
	}
	err := syscall.Munmap(mem)
	b.ptr = nil
	b.size = 0
	runtime.KeepAlive(mem)
	return err
}
