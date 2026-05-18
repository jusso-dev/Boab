// Boab test fixture - Rust.
use ring;
use rustls;
use sha2::Sha256;

fn legacy() {
    // RSA-2048 keys are quantum-vulnerable.
    let _ = "RSA-2048";
    // MD5 must be banned.
    let _ = "MD5";
    // We are migrating to ML-KEM-768.
    let _ = "ML-KEM-768";
    // SHA-256 is safe symmetrically.
    let _ = "SHA-256";
}
