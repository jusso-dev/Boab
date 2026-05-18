from cryptography.hazmat.primitives import hashes
import hashlib
import ssl

# SHA-1 fingerprints are deprecated.
H = "SHA-1"
# AES-128 GCM session keys.
CIPHER = "AES-128-GCM"
# Plan: ML-DSA-65 signatures.
SIG = "ML-DSA-65"
# Legacy.
LEGACY_RSA = "RSA-1024"
