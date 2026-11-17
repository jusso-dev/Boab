//! Minimal Java KeyStore (JKS and JCEKS) reader.
//!
//! Reads entry aliases, entry types and the DER certificates stored with each
//! entry. Protected private key and secret key blobs are skipped by length and
//! never decoded. The store password is only used to check the keyed SHA-1
//! integrity digest, the same check `keytool -list` performs.

use anyhow::{anyhow, bail, Result};
use sha1::{Digest, Sha1};

const JKS_MAGIC: u32 = 0xFEED_FEED;
const JCEKS_MAGIC: u32 = 0xCECE_CECE;
const TAG_PRIVATE_KEY: u32 = 1;
const TAG_TRUSTED_CERT: u32 = 2;
const TAG_SECRET_KEY: u32 = 3;
const MAX_ENTRIES: u32 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JksEntryType {
    PrivateKey,
    TrustedCertificate,
    SecretKey,
}

impl JksEntryType {
    pub fn as_str(self) -> &'static str {
        match self {
            JksEntryType::PrivateKey => "private_key",
            JksEntryType::TrustedCertificate => "trusted_certificate",
            JksEntryType::SecretKey => "secret_key",
        }
    }
}

#[derive(Debug, Clone)]
pub struct JksEntry {
    pub alias: String,
    pub entry_type: JksEntryType,
    pub created_unix_ms: i64,
    /// DER certificates, leaf first. Empty for secret key entries.
    pub certificates: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct JksStore {
    /// `JKS` or `JCEKS`.
    pub store_type: &'static str,
    pub entries: Vec<JksEntry>,
    /// `Some(true)` when the password matched the integrity digest,
    /// `Some(false)` when it did not, `None` when no password was given.
    pub integrity_verified: Option<bool>,
    /// True when parsing stopped at a JCEKS secret key entry, which is a
    /// serialised Java object Boab does not decode. Later entries are not listed.
    pub truncated: bool,
}

/// True when the bytes start with the JKS or JCEKS magic number.
pub fn is_jks(bytes: &[u8]) -> bool {
    matches!(
        bytes
            .get(..4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
        Some(JKS_MAGIC) | Some(JCEKS_MAGIC)
    )
}

pub fn parse(bytes: &[u8], password: Option<&str>) -> Result<JksStore> {
    let mut r = Reader { buf: bytes, pos: 0 };
    let store_type = match r.u32()? {
        JKS_MAGIC => "JKS",
        JCEKS_MAGIC => "JCEKS",
        _ => bail!("not a JKS or JCEKS keystore"),
    };
    let version = r.u32()?;
    if version != 1 && version != 2 {
        bail!("unsupported keystore version {}", version);
    }
    let count = r.u32()?;
    if count > MAX_ENTRIES {
        bail!("keystore claims {} entries", count);
    }
    let mut entries = Vec::new();
    let mut truncated = false;
    for _ in 0..count {
        let tag = r.u32()?;
        let alias = r.utf()?;
        let created_unix_ms = r.u64()? as i64;
        match tag {
            TAG_PRIVATE_KEY => {
                // Encrypted private key: skip by length, never decode.
                let key_len = r.u32()? as usize;
                r.skip(key_len)?;
                let chain_len = r.u32()?;
                if chain_len > MAX_ENTRIES {
                    bail!("certificate chain too long");
                }
                let mut certificates = Vec::new();
                for _ in 0..chain_len {
                    certificates.push(r.certificate(version)?);
                }
                entries.push(JksEntry {
                    alias,
                    entry_type: JksEntryType::PrivateKey,
                    created_unix_ms,
                    certificates,
                });
            }
            TAG_TRUSTED_CERT => {
                let cert = r.certificate(version)?;
                entries.push(JksEntry {
                    alias,
                    entry_type: JksEntryType::TrustedCertificate,
                    created_unix_ms,
                    certificates: vec![cert],
                });
            }
            TAG_SECRET_KEY if store_type == "JCEKS" => {
                entries.push(JksEntry {
                    alias,
                    entry_type: JksEntryType::SecretKey,
                    created_unix_ms,
                    certificates: Vec::new(),
                });
                truncated = true;
                break;
            }
            other => bail!("unknown keystore entry tag {}", other),
        }
    }

    let integrity_verified = match password {
        Some(pw) if !truncated => {
            let body_end = r.pos;
            let digest = bytes
                .get(body_end..body_end + 20)
                .ok_or_else(|| anyhow!("keystore integrity digest missing"))?;
            Some(keyed_digest(pw, &bytes[..body_end]).as_slice() == digest)
        }
        _ => None,
    };

    Ok(JksStore {
        store_type,
        entries,
        integrity_verified,
        truncated,
    })
}

/// `SHA-1(password as UTF-16BE || "Mighty Aphrodite" || body)`.
fn keyed_digest(password: &str, body: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    for unit in password.encode_utf16() {
        h.update(unit.to_be_bytes());
    }
    h.update(b"Mighty Aphrodite");
    h.update(body);
    h.finalize().to_vec()
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or_else(|| anyhow!("keystore truncated"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// Java `DataOutput.writeUTF`: u16 length then modified UTF-8. Aliases are
    /// ASCII in practice; anything else is decoded lossily.
    fn utf(&mut self) -> Result<String> {
        let n = self.u16()? as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    fn certificate(&mut self, version: u32) -> Result<Vec<u8>> {
        if version == 2 {
            let cert_type = self.utf()?;
            if cert_type != "X.509" {
                bail!("unsupported certificate type {}", cert_type);
            }
        }
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
}

/// Build a JKS file. Test helper only: lets tests create keystores without a
/// JDK. The private key blob is opaque filler bytes, not a real key.
#[cfg(test)]
pub(crate) fn build_for_tests(
    password: &str,
    entries: &[(&str, JksEntryType, Vec<Vec<u8>>)],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(JKS_MAGIC.to_be_bytes());
    out.extend(2u32.to_be_bytes());
    out.extend((entries.len() as u32).to_be_bytes());
    let utf = |out: &mut Vec<u8>, s: &str| {
        out.extend((s.len() as u16).to_be_bytes());
        out.extend(s.as_bytes());
    };
    for (alias, ty, certs) in entries {
        match ty {
            JksEntryType::PrivateKey => {
                out.extend(TAG_PRIVATE_KEY.to_be_bytes());
                utf(&mut out, alias);
                out.extend(1_700_000_000_000u64.to_be_bytes());
                let filler = [0xA5u8; 32];
                out.extend((filler.len() as u32).to_be_bytes());
                out.extend(filler);
                out.extend((certs.len() as u32).to_be_bytes());
            }
            _ => {
                out.extend(TAG_TRUSTED_CERT.to_be_bytes());
                utf(&mut out, alias);
                out.extend(1_700_000_000_000u64.to_be_bytes());
            }
        }
        for c in certs {
            utf(&mut out, "X.509");
            out.extend((c.len() as u32).to_be_bytes());
            out.extend(c);
        }
    }
    let digest = keyed_digest(password, &out);
    out.extend(digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_checks_integrity() {
        let cert = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let bytes = build_for_tests(
            "changeit",
            &[
                ("server", JksEntryType::PrivateKey, vec![cert.clone()]),
                ("root", JksEntryType::TrustedCertificate, vec![cert.clone()]),
            ],
        );
        assert!(is_jks(&bytes));
        let store = parse(&bytes, Some("changeit")).unwrap();
        assert_eq!(store.store_type, "JKS");
        assert_eq!(store.entries.len(), 2);
        assert_eq!(store.entries[0].alias, "server");
        assert_eq!(store.entries[0].entry_type, JksEntryType::PrivateKey);
        assert_eq!(store.entries[0].certificates, vec![cert]);
        assert_eq!(store.integrity_verified, Some(true));
        assert_eq!(
            parse(&bytes, Some("wrong")).unwrap().integrity_verified,
            Some(false)
        );
        assert_eq!(parse(&bytes, None).unwrap().integrity_verified, None);
    }

    #[test]
    fn rejects_truncated_input() {
        let bytes = build_for_tests(
            "x",
            &[("a", JksEntryType::TrustedCertificate, vec![vec![1; 10]])],
        );
        assert!(parse(&bytes[..20], None).is_err());
        assert!(parse(b"not a keystore", None).is_err());
    }
}
