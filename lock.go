//go:build linux

package mlocker

import (
	"runtime"
	"syscall"
	"unsafe"
)

const mlockOnFault = 1

var sysMlock2 uintptr

func init() {
	switch runtime.GOARCH {
	case "amd64":
		sysMlock2 = 325
	case "386":
		sysMlock2 = 376
	case "arm":
		sysMlock2 = 390
	case "arm64", "riscv64", "loong64":
		sysMlock2 = 284
	case "ppc64", "ppc64le", "ppc":
		sysMlock2 = 378
	case "s390x":
		sysMlock2 = 374
	case "mips", "mipsle":
		sysMlock2 = 4359
	case "mips64", "mips64le":
		sysMlock2 = 5319
	case "sparc64":
		sysMlock2 = 356
	}
}

func tryMlock2(b []byte) error {
	if sysMlock2 == 0 {
		return syscall.ENOSYS
	}
	_, _, errno := syscall.Syscall6(sysMlock2, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), mlockOnFault, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func lockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if err := tryMlock2(b); err == nil {
		return nil
	} else if err != syscall.ENOSYS && err != syscall.EINVAL {
		return err
	}
	return syscall.Mlock(b)
}

func unlockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return syscall.Munlock(b)
}
