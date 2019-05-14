# goliboqs

goliboqs is a Go wrapper for the [liboqs library](https://github.com/open-quantum-safe/liboqs). This enables Go
applications to use post-quantum key encapsulation mechanisms (KEMs).
  
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
