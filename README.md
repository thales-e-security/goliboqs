# goliboqs
[![GoDoc](https://godoc.org/github.com/thales-e-security/goliboqs?status.svg)](https://godoc.org/github.com/thales-e-security/goliboqs)
[![Build Status](https://travis-ci.com/thales-e-security/goliboqs.svg?branch=master)](https://travis-ci.com/thales-e-security/goliboqs)

goliboqs is a Go wrapper around [liboqs](https://github.com/open-quantum-safe/liboqs), which contains C implementations 
of NIST post-quantum candidate algorithms.  This enables Go applications to use quantum-resistant key encapsulation 
mechanisms (KEMs) on Linux.
  
## Usage
  
Sample usage is shown below. Error handling omitted for brevity.

```go  
// Load the library (don't forget to close)
lib, _ := goliboqs.LoadLib("/path/to/liboqs.so")
defer lib.Close()

// Get a particular KEM (don't forget to close)
kem, _ := lib.GetKem(goliboqs.KemKyber1024)
defer kem.Close()

// Use the kem...
publicKey, secretKey, _ := kem.KeyPair()
sharedSecret, ciphertext, _ := kem.Encaps(publicKey)
recoveredSecret, _ := kem.Decaps(ciphertext, secretKey)
// sharedSecret == recoveredSecret
```

## Running tests

Tests assume liboqs has been installed into `/usr/local/liboqs`.

## Related projects

[go-tls-key-exchange](https://github.com/thales-e-security/go-tls-key-exchange) is a fork of Go that supports
bespoke key exchanges for TLS 1.3. When combined with this project, it enables quantum-resistant TLS in Go.
