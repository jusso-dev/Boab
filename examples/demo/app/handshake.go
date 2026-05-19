package app

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
)

func newRSAKey() (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, 2048)
}

func newECDSAKey() (*ecdsa.PrivateKey, error) {
    return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func tlsCfg() *tls.Config {
    return &tls.Config{
        CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
        MinVersion:       tls.VersionTLS12,
    }
}
