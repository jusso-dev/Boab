//! Minimal Java KeyStore (JKS and JCEKS) reader.
//!
//! Reads entry aliases, entry types and the DER certificates stored with each
//! entry. Protected private key blobs are skipped by length and never decoded.
//! JCEKS secret key entries are Java-serialised `SealedObject`s: Boab walks the
//! serialisation grammar only to find where the entry ends, skips byte-array
//! payloads (the sealed key) by length without copying them, and keeps only the
//! sealing algorithm name. The store password is only used to check the keyed
//! SHA-1 integrity digest, the same check `keytool -list` performs.

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
    /// JCEKS secret keys: the algorithm the key is sealed with (e.g.
    /// `PBEWithMD5AndTripleDES`). This protects the key; it is not the key's
    /// own algorithm, which is inside the sealed bytes and is not read.
    pub seal_algorithm: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JksStore {
    /// `JKS` or `JCEKS`.
    pub store_type: &'static str,
    pub entries: Vec<JksEntry>,
    /// `Some(true)` when the password matched the integrity digest,
    /// `Some(false)` when it did not, `None` when no password was given.
    pub integrity_verified: Option<bool>,
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
                    seal_algorithm: None,
                });
            }
            TAG_TRUSTED_CERT => {
                let cert = r.certificate(version)?;
                entries.push(JksEntry {
                    alias,
                    entry_type: JksEntryType::TrustedCertificate,
                    created_unix_ms,
                    certificates: vec![cert],
                    seal_algorithm: None,
                });
            }
            TAG_SECRET_KEY if store_type == "JCEKS" => {
                let mut walker = JavaStream::new(&mut r);
                walker.stream_header()?;
                walker.content()?;
                entries.push(JksEntry {
                    alias,
                    entry_type: JksEntryType::SecretKey,
                    created_unix_ms,
                    certificates: Vec::new(),
                    seal_algorithm: walker.seal_algorithm(),
                });
            }
            other => bail!("unknown keystore entry tag {}", other),
        }
    }

    let integrity_verified = match password {
        Some(pw) => {
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
    })
}

/// Decode Java modified UTF-8: NUL is `C0 80` and characters outside the BMP
/// are surrogate pairs, each encoded as three bytes. Invalid sequences become
/// U+FFFD.
pub fn decode_modified_utf8(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let cont = |j: usize| {
            bytes
                .get(j)
                .filter(|c| *c & 0xC0 == 0x80)
                .map(|c| (*c & 0x3F) as u16)
        };
        if b < 0x80 {
            units.push(b as u16);
            i += 1;
        } else if b & 0xE0 == 0xC0 {
            match cont(i + 1) {
                Some(c) => {
                    units.push(((b as u16 & 0x1F) << 6) | c);
                    i += 2;
                }
                None => {
                    units.push(0xFFFD);
                    i += 1;
                }
            }
        } else if b & 0xF0 == 0xE0 {
            match (cont(i + 1), cont(i + 2)) {
                (Some(c1), Some(c2)) => {
                    units.push(((b as u16 & 0x0F) << 12) | (c1 << 6) | c2);
                    i += 3;
                }
                _ => {
                    units.push(0xFFFD);
                    i += 1;
                }
            }
        } else {
            units.push(0xFFFD);
            i += 1;
        }
    }
    String::from_utf16_lossy(&units)
}

/// Walks one Java serialisation stream (`java.io.ObjectOutputStream`) to find
/// its end. It records class descriptors so field values can be framed, and
/// keeps string values (class and algorithm names). Primitive arrays, which
/// hold the sealed key bytes, are skipped by length and never copied.
struct JavaStream<'r, 'a> {
    r: &'r mut Reader<'a>,
    /// Handle table: `Some(fields)` for class descriptors, `None` otherwise.
    handles: Vec<Handle>,
    /// String values seen, in stream order.
    strings: Vec<String>,
    depth: usize,
}

#[derive(Clone)]
enum Handle {
    Class(Option<ClassDesc>),
    Other,
}

#[derive(Clone)]
struct ClassDesc {
    flags: u8,
    /// Field type codes, in stream order.
    fields: Vec<u8>,
    /// Element type for array classes (`[B` gives `B`), else 0.
    array_code: u8,
    parent: Option<Box<ClassDesc>>,
}

const TC_NULL: u8 = 0x70;
const TC_REFERENCE: u8 = 0x71;
const TC_CLASSDESC: u8 = 0x72;
const TC_OBJECT: u8 = 0x73;
const TC_STRING: u8 = 0x74;
const TC_ARRAY: u8 = 0x75;
const TC_CLASS: u8 = 0x76;
const TC_BLOCKDATA: u8 = 0x77;
const TC_ENDBLOCKDATA: u8 = 0x78;
const TC_LONGSTRING: u8 = 0x7C;
const TC_PROXYCLASSDESC: u8 = 0x7D;
const TC_ENUM: u8 = 0x7E;
const TC_BLOCKDATALONG: u8 = 0x7A;
const SC_WRITE_METHOD: u8 = 0x01;
const SC_SERIALIZABLE: u8 = 0x02;
const SC_EXTERNALIZABLE: u8 = 0x04;
const BASE_HANDLE: u32 = 0x7E_0000;
const MAX_DEPTH: usize = 64;
const MAX_HANDLES: usize = 10_000;

impl<'r, 'a> JavaStream<'r, 'a> {
    fn new(r: &'r mut Reader<'a>) -> Self {
        Self {
            r,
            handles: Vec::new(),
            strings: Vec::new(),
            depth: 0,
        }
    }

    /// The sealing algorithm of a `javax.crypto.SealedObject`: the last
    /// algorithm-like string in the stream (`sealAlg`).
    fn seal_algorithm(&self) -> Option<String> {
        self.strings
            .iter()
            .rev()
            .find(|s| s.starts_with("PBE") || s.contains("With") || s.starts_with("AES"))
            .cloned()
    }

    fn stream_header(&mut self) -> Result<()> {
        if self.r.u16()? != 0xACED || self.r.u16()? != 5 {
            bail!("JCEKS secret key entry is not a Java serialisation stream");
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.r.take(1)?[0])
    }

    fn new_handle(&mut self, h: Handle) -> Result<usize> {
        if self.handles.len() >= MAX_HANDLES {
            bail!("Java serialisation stream too large");
        }
        self.handles.push(h);
        Ok(self.handles.len() - 1)
    }

    fn reference(&mut self) -> Result<Handle> {
        let h = self.r.u32()?;
        h.checked_sub(BASE_HANDLE)
            .and_then(|i| self.handles.get(i as usize).cloned())
            .ok_or_else(|| anyhow!("bad Java serialisation handle"))
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            bail!("Java serialisation stream nested too deeply");
        }
        Ok(())
    }

    /// One `content` item: an object or a block of data.
    fn content(&mut self) -> Result<()> {
        let tc = self.u8()?;
        match tc {
            TC_BLOCKDATA => {
                let n = self.u8()? as usize;
                self.r.skip(n)
            }
            TC_BLOCKDATALONG => {
                let n = self.r.u32()? as usize;
                self.r.skip(n)
            }
            _ => self.object_tc(tc).map(|_| ()),
        }
    }

    fn object(&mut self) -> Result<Handle> {
        let tc = self.u8()?;
        self.object_tc(tc)
    }

    fn object_tc(&mut self, tc: u8) -> Result<Handle> {
        self.enter()?;
        let out = match tc {
            TC_NULL => Ok(Handle::Other),
            TC_REFERENCE => self.reference(),
            TC_CLASSDESC | TC_PROXYCLASSDESC => Ok(Handle::Class(self.class_desc_tc(tc)?)),
            TC_CLASS => {
                let d = self.class_desc()?;
                self.new_handle(Handle::Class(d))?;
                Ok(Handle::Other)
            }
            TC_STRING | TC_LONGSTRING => {
                let n = if tc == TC_STRING {
                    self.r.u16()? as usize
                } else {
                    usize::try_from(self.r.u64()?).map_err(|_| anyhow!("string too long"))?
                };
                let s = decode_modified_utf8(self.r.take(n)?);
                self.new_handle(Handle::Other)?;
                self.strings.push(s);
                Ok(Handle::Other)
            }
            TC_ENUM => {
                self.class_desc()?;
                let idx = self.new_handle(Handle::Other)?;
                self.object()?;
                Ok(self.handles[idx].clone())
            }
            TC_ARRAY => {
                let code = self.class_desc()?.map(|d| d.array_code).unwrap_or(0);
                self.new_handle(Handle::Other)?;
                let len = self.r.u32()? as usize;
                // Primitive arrays (the sealed key bytes) are skipped unread.
                match code {
                    b'B' | b'Z' => self.r.skip(len)?,
                    b'C' | b'S' => self.r.skip(len.saturating_mul(2))?,
                    b'I' | b'F' => self.r.skip(len.saturating_mul(4))?,
                    b'J' | b'D' => self.r.skip(len.saturating_mul(8))?,
                    b'L' | b'[' => {
                        for _ in 0..len {
                            self.object()?;
                        }
                    }
                    _ => bail!("unsupported Java array type"),
                }
                Ok(Handle::Other)
            }
            TC_OBJECT => {
                let desc = self.class_desc()?;
                let idx = self.new_handle(Handle::Other)?;
                let mut chain = Vec::new();
                let mut d = desc;
                while let Some(c) = d {
                    d = c.parent.as_deref().cloned();
                    chain.push(c);
                }
                // Superclass data comes first.
                for c in chain.iter().rev() {
                    if c.flags & SC_EXTERNALIZABLE != 0 {
                        bail!("externalizable classes are not supported");
                    }
                    if c.flags & SC_SERIALIZABLE != 0 {
                        for code in &c.fields {
                            self.field_value(*code)?;
                        }
                        if c.flags & SC_WRITE_METHOD != 0 {
                            self.annotation()?;
                        }
                    }
                }
                Ok(self.handles[idx].clone())
            }
            other => bail!("unexpected Java serialisation tag {:#x}", other),
        };
        self.depth -= 1;
        out
    }

    fn field_value(&mut self, code: u8) -> Result<()> {
        match code {
            b'B' | b'Z' => self.r.skip(1),
            b'C' | b'S' => self.r.skip(2),
            b'I' | b'F' => self.r.skip(4),
            b'J' | b'D' => self.r.skip(8),
            b'L' | b'[' => self.object().map(|_| ()),
            _ => bail!("unknown Java field type"),
        }
    }

    /// `classAnnotation` / `objectAnnotation`: contents up to TC_ENDBLOCKDATA.
    fn annotation(&mut self) -> Result<()> {
        loop {
            let tc = self.u8()?;
            if tc == TC_ENDBLOCKDATA {
                return Ok(());
            }
            match tc {
                TC_BLOCKDATA => {
                    let n = self.u8()? as usize;
                    self.r.skip(n)?;
                }
                TC_BLOCKDATALONG => {
                    let n = self.r.u32()? as usize;
                    self.r.skip(n)?;
                }
                _ => {
                    self.object_tc(tc)?;
                }
            }
        }
    }

    fn class_desc(&mut self) -> Result<Option<ClassDesc>> {
        let tc = self.u8()?;
        match tc {
            TC_NULL => Ok(None),
            TC_REFERENCE => match self.reference()? {
                Handle::Class(d) => Ok(d),
                _ => bail!("Java handle is not a class descriptor"),
            },
            TC_CLASSDESC | TC_PROXYCLASSDESC => self.class_desc_tc(tc),
            _ => bail!("expected a Java class descriptor"),
        }
    }

    fn class_desc_tc(&mut self, tc: u8) -> Result<Option<ClassDesc>> {
        self.enter()?;
        let idx = self.new_handle(Handle::Class(None))?;
        let desc = if tc == TC_PROXYCLASSDESC {
            let n = self.r.u32()?;
            for _ in 0..n {
                let _ = self.r.utf()?;
            }
            self.annotation()?;
            let parent = self.class_desc()?.map(Box::new);
            ClassDesc {
                flags: 0,
                fields: Vec::new(),
                array_code: 0,
                parent,
            }
        } else {
            let name = self.r.utf()?;
            self.r.skip(8)?; // serialVersionUID
            let flags = self.u8()?;
            let count = self.r.u16()?;
            let mut fields = Vec::new();
            for _ in 0..count {
                let code = self.u8()?;
                let _field_name = self.r.utf()?;
                if code == b'L' || code == b'[' {
                    self.object()?; // className1, a String
                }
                fields.push(code);
            }
            self.annotation()?;
            let parent = self.class_desc()?.map(Box::new);
            ClassDesc {
                flags,
                fields,
                array_code: array_code(&name),
                parent,
            }
        };
        self.handles[idx] = Handle::Class(Some(desc.clone()));
        self.depth -= 1;
        Ok(Some(desc))
    }
}

/// `[B` -> `B`, `[Ljava.lang.String;` -> `L`, anything else -> 0.
fn array_code(class_name: &str) -> u8 {
    let b = class_name.as_bytes();
    if b.first() == Some(&b'[') {
        b.get(1).copied().unwrap_or(0)
    } else {
        0
    }
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

    /// Java `DataOutput.writeUTF`: u16 length then modified UTF-8.
    fn utf(&mut self) -> Result<String> {
        let n = self.u16()? as usize;
        Ok(decode_modified_utf8(self.take(n)?))
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
    fn modified_utf8_keeps_supplementary_characters_distinct() {
        // Java writeUTF encodes U+1F600 as the surrogate pair D83D DE00, each
        // as three bytes.
        let enc = |hi: u16, lo: u16| {
            let mut v = vec![b'a'];
            for u in [hi, lo] {
                v.push(0xE0 | (u >> 12) as u8);
                v.push(0x80 | ((u >> 6) & 0x3F) as u8);
                v.push(0x80 | (u & 0x3F) as u8);
            }
            v
        };
        let a = decode_modified_utf8(&enc(0xD83D, 0xDE00));
        let b = decode_modified_utf8(&enc(0xD83D, 0xDE01));
        assert_eq!(a, "a\u{1F600}");
        assert_eq!(b, "a\u{1F601}");
        assert_ne!(a, b);
        assert_eq!(decode_modified_utf8(&[0xC0, 0x80]), "\u{0}");
    }

    #[test]
    fn jceks_secret_entries_do_not_stop_the_listing() {
        // Built by keytool: two secret keys, then a trusted certificate.
        let bytes = include_bytes!("../../tests/fixtures/jceks/secrets.jceks");
        let store = parse(bytes, Some("changeit")).unwrap();
        assert_eq!(store.store_type, "JCEKS");
        // JCEKS writes entries in hash order; the trusted certificate comes
        // after a secret key entry in this file.
        let mut aliases: Vec<&str> = store.entries.iter().map(|e| e.alias.as_str()).collect();
        let last_secret = store
            .entries
            .iter()
            .position(|e| e.entry_type == JksEntryType::SecretKey)
            .unwrap();
        let cert = store
            .entries
            .iter()
            .position(|e| e.entry_type == JksEntryType::TrustedCertificate)
            .unwrap();
        assert!(cert > last_secret, "certificate must follow a secret key");
        aliases.sort();
        assert_eq!(aliases, vec!["aes-data", "hmac-sig", "zz-partner"]);
        for e in &store.entries {
            if e.entry_type == JksEntryType::SecretKey {
                assert_eq!(e.seal_algorithm.as_deref(), Some("PBEWithMD5AndTripleDES"));
                assert!(e.certificates.is_empty());
            }
        }
        // The walker reached the real end of the body: the digest matches.
        assert_eq!(store.integrity_verified, Some(true));
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
