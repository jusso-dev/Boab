package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher suites observed: AES-256-GCM, ChaCha20-Poly1305.
// Curves: ECDSA-P-256 today, target Kyber768 hybrid soon.
// X25519 and Ed25519 remain in use for short-term keys.
const Note = "RC4 must not be used"
