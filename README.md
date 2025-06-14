# Mlocker
Mlocker is a minimal, high-assurance memory security library for Go. It provides locked, encrypted, and zeroed memory buffers for safely handling secrets like passwords, access tokens, cryptographic keys, and session credentials.

Everything is locked, Encrypted without writing to disk or exposing data to garbage collection or memory dumps.

Design for modern Zero Trust systems, Mlocker ensures secrets live only in a locked memory and are wiped immediately after use.

> **Note**
> The library currently supports **Linux only** at the moment.

---

## Introduction

In secure systems, secrets are often protected at rest and in transit — but rarely **in memory**. Most Go applications keep passwords, tokens, and keys in `[]byte` or `string`, where they are:

- Swappable to disk by the OS
- Vulnerable to memory scraping and heap inspection

**mlocker** fixes this by:
- Allocating and locking memory pages with `mlock`
- Encrypting secrets even while in RAM
- Requiring explicit decryption and zeroization
- Keeping sensitive data completely out of Go’s GC

---

## Problem Statement

Typical secret handling patterns are unsafe:

- `os.Getenv("SECRET_KEY")` stays in GC-managed memory
- `[]byte` values are duplicated or retained unintentionally
- Memory dumps and swap files or OS unauthorized access can leak tokens and provate keys or any other secret data
- No standard Go mechanism exists to keep secrets isolated, locked, and zeroed

---

## Features

- **Memory Locking** Uses `mlock` to keep secrets off disk and out of swap files
- **Heap-Free Allocation** Secrets created with `AllocateLocked` are manually allocated with `mmap` so they avoid Go's heap
- **In-Memory Encryption** Encrypts secrets in RAM with AES-GCM via `EncryptToMemory`
- **Per-Buffer Keys** Each buffer derives its own AES-GCM key from the master key. A compromised master key still allows decrypting all buffers.
- **Integrity Verification** Optional HMAC checks detect tampering on decrypt or destroy
- **Plaintext Zeroing** Set `ZeroPlaintext` to wipe plaintext after encryption
- **GC-Safe Architecture** Buffers created by `mlocker` avoid Go-managed memory; however plaintext provided by the caller may still reside on the heap.
- **Crypto State on Heap** AES-GCM and HMAC objects are instantiated using the standard library, briefly placing derived keys on the Go heap. These objects are wiped immediately after use.
- **No Internal Synchronization** `SecureBuffer` does not guard against concurrent use; callers must serialize access.
- **Secure Destruction** Manual `Destroy()` or `Zero()` wipes secrets from memory after use
- **Minimal API** Simple: `EncryptLocked()`, `EncryptToMemory()`, `Use()`, `Destroy()`

## Example Usage

```go
package main

import (
    "fmt"
    "time"

    "github.com/AlyRagab/Mlocker"
)

func main() {
    // Initialise the master key. Memory pages will be locked on all supported platforms.
    if err := mlocker.Init(); err != nil {
        panic(err)
    }
    defer mlocker.Shutdown() // wipe master key when finished

    // Wipe plaintext after encryption and keep HMAC integrity checks enabled.
    mlocker.ZeroPlaintext = true
    mlocker.IntegrityCheck = true

    // Prepare the plaintext in locked memory to avoid the Go heap.
    secret, err := mlocker.AllocateLocked(len("secret-pass"))
    if err != nil {
        panic(err)
    }
    copy(secret.Bytes(), "secret-pass")

    // Encrypt the secret value into locked memory using a per-buffer key.
    // AES-GCM is used internally by EncryptLocked/EncryptToMemory.
    buf, err := mlocker.EncryptLocked(secret)
    if err != nil {
        panic(err)
    }
    buf.DestroyAfter(5 * time.Second)
    defer buf.Destroy() // secure destruction also verifies integrity
    mlocker.FreeLocked(secret)

    // Encrypt a []byte that may have been allocated on the Go heap.
    heapData := []byte("another secret")
    buf2, err := mlocker.EncryptToMemory(heapData)
    if err != nil {
        panic(err)
    }
    buf2.DestroyAfter(5 * time.Second)
    defer buf2.Destroy()
    mlocker.Zero(heapData)

    // Decrypt when needed; plaintext is wiped immediately after use.
    if err := buf.Use(func(pt []byte) error {
        fmt.Println(string(pt))
        return nil
    }); err != nil {
        panic(err)
    }

}
```

