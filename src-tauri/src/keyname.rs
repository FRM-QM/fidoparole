//! A key's own name, as Keyroost stores it in the key's largeBlob array
//! ("device label", version 1). Read-only: FidoParole never writes a name.
//!
//! The name is not secret. The array is readable without a PIN and the
//! entry is encrypted under a fixed, published key, only so it has the shape
//! of every other largeBlob entry (CTAP 2.1 §6.10.3):
//!
//! ```text
//! K        = SHA-256("FIDO2 large-blob device label v1")
//! P        = CBOR map {1: 1 (version), 2: label (text, 1-64 chars), 3?: writer (text)}
//! entry    = {1: AES-256-GCM(K, nonce, rawDEFLATE(P), aad = "blob" || u64le(origSize)),
//!             2: nonce (12 bytes), 3: origSize}
//! ```
//!
//! Readers take the last entry that decodes as a version-1 name and skip
//! everything else. Spec: keyroost `docs/PROTOCOL-device-label.md`.
//!
//! A name is chosen by whoever holds the key, so it is shown only when it
//! holds no control, zero-width or bidi characters (as keyroost does), and it
//! is never used to tell keys apart.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ciborium::Value;
use flate2::read::DeflateDecoder;
use sha2::{Digest, Sha256};
use std::io::Read;

/// The string hashed to the fixed key every name entry is encrypted under.
const LABEL_KEY_INFO: &[u8] = b"FIDO2 large-blob device label v1";
/// Longest label (and writer tag), in Unicode scalar values.
const MAX_LABEL_CHARS: usize = 64;
/// Ceiling on a name entry's declared plaintext size, checked before
/// anything is inflated. A real one is under 300 bytes.
const MAX_ORIG_SIZE: u64 = 64 * 1024;

/// `K = SHA-256(LABEL_KEY_INFO)`.
fn label_key() -> [u8; 32] {
    Sha256::digest(LABEL_KEY_INFO).into()
}

/// The key's name from its serialized largeBlob array (the CBOR array,
/// without the checksum, as `fido_dev_largeblob_get_array` returns it).
/// `None` when the array holds no valid name, or when the last one would
/// not be safe to display.
pub fn name_from_array(array: &[u8]) -> Option<String> {
    let mut rest = array;
    let Value::Array(items) = ciborium::from_reader::<Value, _>(&mut rest).ok()? else {
        return None;
    };
    let label = items
        .iter()
        .filter_map(entry_fields)
        .filter_map(|(ct, nonce, orig_size)| decode_entry(ct, nonce, orig_size))
        .last()?;
    is_display_safe(&label).then_some(label)
}

/// The fields of a conforming largeBlob entry (§6.10.3): a map whose key 1
/// is a byte string, key 2 a 12-byte byte string and key 3 an unsigned
/// integer, each exactly once. Other keys are allowed. `None` for anything
/// else, which readers skip.
fn entry_fields(item: &Value) -> Option<(&[u8], &[u8; 12], u64)> {
    let Value::Map(pairs) = item else { return None };
    let (mut ciphertext, mut nonce, mut orig_size) = (None, None, None);
    for (k, v) in pairs {
        let taken = match (uint(k), v) {
            (Some(1), Value::Bytes(b)) => ciphertext.replace(b.as_slice()).is_some(),
            (Some(2), Value::Bytes(b)) => nonce.replace(<&[u8; 12]>::try_from(b.as_slice()).ok()?).is_some(),
            (Some(3), _) => orig_size.replace(uint(v)?).is_some(),
            (Some(1 | 2), _) => return None, // a required key with the wrong type
            _ => false,                      // another key: allowed
        };
        if taken {
            return None; // a duplicate required key: ambiguous
        }
    }
    Some((ciphertext?, nonce?, orig_size?))
}

/// The label an entry holds, or `None` when it is not a version-1 name: the
/// tag must verify under [`label_key`], the plaintext must inflate to exactly
/// `orig_size` bytes of one CBOR map with key 1 = 1 and key 2 a text of 1-64
/// characters. Unknown keys are ignored; of duplicate keys the first counts.
fn decode_entry(ciphertext: &[u8], nonce: &[u8; 12], orig_size: u64) -> Option<String> {
    if orig_size == 0 || orig_size > MAX_ORIG_SIZE {
        return None;
    }
    let mut aad = Vec::with_capacity(12);
    aad.extend_from_slice(b"blob");
    aad.extend_from_slice(&orig_size.to_le_bytes());
    let cipher = Aes256Gcm::new_from_slice(&label_key()).ok()?;
    let compressed = cipher.decrypt(&Nonce::from(*nonce), Payload { msg: ciphertext, aad: &aad }).ok()?;

    let mut plain = Vec::new();
    DeflateDecoder::new(compressed.as_slice()).take(orig_size + 1).read_to_end(&mut plain).ok()?;
    if plain.len() as u64 != orig_size {
        return None;
    }

    let mut rest = plain.as_slice();
    let Value::Map(pairs) = ciborium::from_reader::<Value, _>(&mut rest).ok()? else {
        return None;
    };
    if !rest.is_empty() {
        return None;
    }
    let first = |key: u64| pairs.iter().find(|(k, _)| uint(k) == Some(key)).map(|(_, v)| v);
    if uint(first(1)?) != Some(1) {
        return None;
    }
    match first(2)? {
        Value::Text(t) if (1..=MAX_LABEL_CHARS).contains(&t.chars().count()) => Some(t.clone()),
        _ => None,
    }
}

/// `v` as an unsigned integer.
fn uint(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    }
}

/// Whether a name can be shown as is: not blank, and none of the characters
/// that make one text look like another.
fn is_display_safe(s: &str) -> bool {
    !s.trim().is_empty() && !s.chars().any(is_spoofing_char)
}

/// Control, zero-width and bidi characters (the same set keyroost refuses
/// in a name: `keyroost_keyring::is_spoofing_char`).
fn is_spoofing_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}'                // soft hyphen
            | '\u{061C}'              // Arabic letter mark
            | '\u{180E}'              // Mongolian vowel separator
            | '\u{200B}'..='\u{200F}' // zero-width space/joiners, LRM/RLM
            | '\u{2028}'              // line separator
            | '\u{2029}'              // paragraph separator
            | '\u{202A}'..='\u{202E}' // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}'              // BOM / zero-width no-break space
            | '\u{E0000}'..='\u{E007F}' // tag characters
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vectors from keyroost docs/PROTOCOL-device-label.md.
    const V1_ENTRY: &str = "a3015826fa202b3626a9c13b79e236fa5b1288777aa854baa7b9071106da74af6ca22511f5913dab35ed024c000102030405060708090a0b0311";
    const V2_ENTRY: &str = "a3015832fa2c2b3a26a8c13b79e022f9ead0884a6aea5f84b0a5ecf7beaca35fe4c4b10d0234607c0eddb263c942a581932e707b715e024c000102030405060708090a0b03181d";
    const V3_ENTRY: &str = "a301582371eda327a400c713df95d9f1d5fab5675779cad37fb437982c7a5dda50d98d583dc030024ca0a1a2a3a4a5a6a7a8a9aaab0311";
    const NONCE: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// A CBOR array of the given raw elements (fewer than 24).
    fn array(elements: &[&[u8]]) -> Vec<u8> {
        assert!(elements.len() < 24);
        let mut out = vec![0x80 | elements.len() as u8];
        for e in elements {
            out.extend_from_slice(e);
        }
        out
    }

    fn cbor(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    fn int(n: u64) -> Value {
        Value::Integer(n.into())
    }

    fn entry(ciphertext: Vec<u8>, nonce: &[u8], orig_size: u64) -> Vec<u8> {
        cbor(&Value::Map(vec![
            (int(1), Value::Bytes(ciphertext)),
            (int(2), Value::Bytes(nonce.to_vec())),
            (int(3), int(orig_size)),
        ]))
    }

    /// `data` as one final stored DEFLATE block, as writers emit it.
    fn stored_deflate(data: &[u8]) -> Vec<u8> {
        let len = data.len() as u16;
        let mut out = vec![0x01];
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    /// An entry holding `plain` under the name key, declaring `orig_size`.
    fn seal_sized(plain: &[u8], orig_size: u64) -> Vec<u8> {
        let mut aad = b"blob".to_vec();
        aad.extend_from_slice(&orig_size.to_le_bytes());
        let ct = Aes256Gcm::new_from_slice(&label_key())
            .unwrap()
            .encrypt(&Nonce::from(NONCE), Payload { msg: &stored_deflate(plain), aad: &aad })
            .unwrap();
        entry(ct, &NONCE, orig_size)
    }

    fn seal(plain: &[u8]) -> Vec<u8> {
        seal_sized(plain, plain.len() as u64)
    }

    fn seal_map(pairs: Vec<(Value, Value)>) -> Vec<u8> {
        seal(&cbor(&Value::Map(pairs)))
    }

    fn named(label: &str) -> Vec<u8> {
        seal_map(vec![(int(1), int(1)), (int(2), Value::Text(label.into()))])
    }

    /// keyroost's RP entry fixture: a conforming entry with an extra key 4.
    fn rp_entry() -> Vec<u8> {
        let mut b = vec![0xa4, 0x01, 0x54];
        b.extend_from_slice(&[0x11; 20]);
        b.extend_from_slice(&[0x02, 0x4c]);
        b.extend_from_slice(&[0x22; 12]);
        b.extend_from_slice(&[0x03, 0x05, 0x04, 0x61, 0x78]);
        b
    }

    fn name_of(elements: &[&[u8]]) -> Option<String> {
        name_from_array(&array(elements))
    }

    #[test]
    fn label_key_matches_published_constant() {
        assert_eq!(hex::encode(label_key()), "2d90176240c249e3f7aaeabd444093437d2f595dc778bf45d3cc0554f326b639");
    }

    #[test]
    fn known_answer_vectors_decode() {
        assert_eq!(name_of(&[&unhex(V1_ENTRY)]).as_deref(), Some("Work YubiKey"));
        assert_eq!(name_of(&[&unhex(V2_ENTRY)]).as_deref(), Some("Cl\u{e9} de bureau"));
        // V3 is compressed with real DEFLATE, not a stored block.
        assert_eq!(name_of(&[&unhex(V3_ENTRY)]).as_deref(), Some("Work YubiKey"));
    }

    #[test]
    fn last_valid_name_wins() {
        let (v1, v2) = (unhex(V1_ENTRY), unhex(V2_ENTRY));
        assert_eq!(name_of(&[&v1, &v2]).as_deref(), Some("Cl\u{e9} de bureau"));
        assert_eq!(name_of(&[&v2, &v1]).as_deref(), Some("Work YubiKey"));
        // A later entry under the name key that is not a version-1 name
        // (here: version 2) does not hide the valid one before it.
        let v2_format = seal_map(vec![(int(1), int(2)), (int(2), Value::Text("Future".into()))]);
        assert_eq!(name_of(&[&v1, &v2_format]).as_deref(), Some("Work YubiKey"));
    }

    #[test]
    fn other_elements_are_skipped() {
        let short_nonce = entry(vec![0xaa], &[0x22; 11], 1);
        let v1 = unhex(V1_ENTRY);
        let elements: [&[u8]; 6] = [&rp_entry(), &[0x61, 0x78], &[0xc1, 0x01], &v1, &short_nonce, &[0xa0]];
        assert_eq!(name_of(&elements).as_deref(), Some("Work YubiKey"));
        assert_eq!(name_of(&[&rp_entry()]), None);
        // Bytes after the array are read past.
        let mut trailing = array(&[&v1]);
        trailing.push(0x00);
        assert_eq!(name_from_array(&trailing).as_deref(), Some("Work YubiKey"));
    }

    #[test]
    fn bad_entries_are_not_names() {
        let v1 = unhex(V1_ENTRY);
        let mut flipped = v1.clone();
        // a3 01 58 26 <38 bytes: ciphertext + tag> 02 4c <nonce> 03 11
        flipped[4] ^= 0x01; // first ciphertext byte
        let mut tag_flipped = v1.clone();
        tag_flipped[4 + 0x26 - 1] ^= 0x80; // last tag byte
        let p = cbor(&Value::Map(vec![(int(1), int(1)), (int(2), Value::Text("Work YubiKey".into()))]));
        let mut trailing = p.clone();
        trailing.push(0x00);
        let dup_nonce = cbor(&Value::Map(vec![
            (int(1), Value::Bytes(vec![0xaa])),
            (int(2), Value::Bytes(NONCE.to_vec())),
            (int(2), Value::Bytes(NONCE.to_vec())),
            (int(3), int(1)),
        ]));
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("ciphertext bit flipped", flipped),
            ("tag bit flipped", tag_flipped),
            ("origSize off by one", seal_sized(&p, p.len() as u64 + 1)),
            ("origSize zero", seal_sized(&[], 0)),
            ("origSize huge", seal_sized(&p, 2 * 1024 * 1024)),
            ("version 2", seal_map(vec![(int(1), int(2)), (int(2), Value::Text("Work YubiKey".into()))])),
            ("no version", seal_map(vec![(int(2), Value::Text("Work YubiKey".into()))])),
            ("empty label", named("")),
            ("label 65 chars", named(&"\u{e9}".repeat(65))),
            ("label not text", seal_map(vec![(int(1), int(1)), (int(2), Value::Bytes(b"Work".to_vec()))])),
            ("no label", seal_map(vec![(int(1), int(1))])),
            ("not a map", seal(&cbor(&Value::Array(vec![int(1)])))),
            ("trailing byte after the map", seal(&trailing)),
            ("duplicate nonce key", dup_nonce),
        ];
        for (what, e) in cases {
            assert_eq!(name_of(&[&e]), None, "{what}");
        }
        // The 64-character boundary is accepted.
        assert_eq!(name_of(&[&named(&"\u{e9}".repeat(64))]).map(|n| n.chars().count()), Some(64));
    }

    #[test]
    fn unknown_keys_bad_writer_and_duplicates() {
        let e = seal_map(vec![
            (int(1), int(1)),
            (int(2), Value::Text("Work YubiKey".into())),
            (int(2), Value::Text("Other".into())), // duplicate: the first counts
            (int(3), int(7)),                      // a writer that isn't text is ignored
            (int(9), Value::Array(vec![Value::Null, Value::Bool(true)])),
        ]);
        assert_eq!(name_of(&[&e]).as_deref(), Some("Work YubiKey"));
    }

    #[test]
    fn unsafe_names_are_not_shown() {
        let v1 = unhex(V1_ENTRY);
        for bad in ["Work\u{202E}yeK", "Work\u{200B}Key", "Work\nKey", "   "] {
            // The last name counts; an unsafe one hides the earlier valid one.
            assert_eq!(name_of(&[&v1, &named(bad)]), None, "{bad:?}");
        }
        assert_eq!(name_of(&[&named("Cl\u{e9} 'de' bureau #2")]).as_deref(), Some("Cl\u{e9} 'de' bureau #2"));
    }

    #[test]
    fn empty_or_broken_arrays() {
        let cases: [&[u8]; 5] = [&[0x80], &[], &[0xa0], &[0xff, 0x00], &[0x82, 0x01]];
        for bytes in cases {
            assert_eq!(name_from_array(bytes), None, "{bytes:02x?}");
        }
    }
}
