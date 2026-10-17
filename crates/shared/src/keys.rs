//! WireGuard key generation, validation, and public-key derivation.

use base64::Engine as _;

/// Returns true if `s` is a non-zero 32-byte WireGuard key in canonical standard base64.
pub fn is_valid_key(s: &str) -> bool {
    let engine = base64::engine::general_purpose::STANDARD;
    engine.decode(s).is_ok_and(|bytes| {
        bytes.len() == 32 && bytes.iter().any(|b| *b != 0) && engine.encode(&bytes) == s
    })
}

/// Derives the standard base64 X25519 public key for `private`.
pub fn derive_public_key(private: &[u8; 32]) -> String {
    let public = x25519_dalek::x25519(*private, x25519_dalek::X25519_BASEPOINT_BYTES);
    base64::engine::general_purpose::STANDARD.encode(public)
}

/// Base64-encoded X25519 private and public key pair.
pub struct KeyPair {
    pub private: String,
    pub public: String,
}

/// Generates a random WireGuard X25519 key pair using the OS CSPRNG.
pub fn generate_key_pair() -> KeyPair {
    let mut private = [0u8; 32];
    getrandom::fill(&mut private).expect("operating system random source");
    KeyPair {
        public: derive_public_key(&private),
        private: base64::engine::general_purpose::STANDARD.encode(private),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_matches_the_x25519_basepoint_vector() {
        let private: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            derive_public_key(&private),
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
        );
    }

    #[test]
    fn generated_keys_are_valid_and_distinct() {
        let (a, b) = (generate_key_pair(), generate_key_pair());
        assert!(is_valid_key(&a.private));
        assert!(is_valid_key(&a.public));
        assert_ne!(a.private, b.private);
    }

    #[test]
    fn valid_keys_are_canonical_nonzero_32_byte_base64() {
        for (case, key, expected) in [
            ("key", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", true),
            (
                "all zero",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                false,
            ),
            (
                "not canonical",
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ=",
                false,
            ),
            (
                "31 bytes",
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg==",
                false,
            ),
            (
                "URL-safe alphabet",
                "-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_8=",
                false,
            ),
            ("not base64", "not base64", false),
        ] {
            assert_eq!(is_valid_key(key), expected, "{case}");
        }
    }
}
