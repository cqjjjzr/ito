use base64::Engine as _;
use sha2::Digest as _;
use subtle::ConstantTimeEq;

/// Digests `s` with SHA-256, as lowercase hex.
pub fn digest_sha256(s: &str) -> String {
    sha2::Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Generates a 32-byte random secret encoded as unpadded base64url.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("operating system random source");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Returns true if `s` is a canonical 32-byte unpadded base64url string as produced by
/// [`generate_secret`].
pub fn is_secret_format(s: &str) -> bool {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    engine
        .decode(s)
        .is_ok_and(|bytes| bytes.len() == 32 && engine.encode(&bytes) == s)
}

pub fn constant_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
