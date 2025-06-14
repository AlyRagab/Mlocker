//go:build linux

package mlocker

import "runtime"

// Zero overwrites the provided byte slice with zeroes.
func Zero(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func zeroBytes(b []byte) {
	Zero(b)
}
