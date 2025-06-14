//go:build linux

package mlocker

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/AlyRagab/Mlocker/internal"
)

var (
	masterKey      *[32]byte
	masterBuf      *LockedBuffer
	once           sync.Once
	ZeroPlaintext  bool
	IntegrityCheck = true
)

// Init generates a process-local master key.
func Init() error {
	var err error
	once.Do(func() {
		buf, e := AllocateLocked(32)
		if e != nil {
			err = e
			return
		}
		if e = internal.FillRandom(buf.Bytes()); e != nil {
			FreeLocked(buf)
			err = e
			return
		}
		masterBuf = buf
		masterKey = (*[32]byte)(buf.ptr)
	})
	return err
}

// Shutdown wipes the master key and allows reinitialization.
func Shutdown() error {
	if masterBuf == nil {
		return nil
	}
	ZeroLocked(masterBuf)
	err := FreeLocked(masterBuf)
	masterBuf = nil
	masterKey = nil
	once = sync.Once{}
	return err
}

func masterKeyBytes() []byte {
	if masterKey == nil {
		return nil
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(masterKey)), 32)
	runtime.KeepAlive(masterBuf)
	return b
}
