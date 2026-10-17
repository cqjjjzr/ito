use crate::{
    config::{Config, read_secret},
    error::{Result, invalid},
};
use base64::Engine as _;
use std::collections::BTreeMap;

pub use ito_shared::keys::derive_public_key;

/// Validates that `s` is a non-zero 32-byte WireGuard key in canonical standard base64.
pub fn validate_key(s: &str) -> Result<()> {
    ito_shared::keys::is_valid_key(s)
        .ok_or_else(|| invalid("key must be 32 bytes of canonical base64"))
}

/// Map of configured WireGuard interface names to their loaded server key pairs.
#[derive(Default)]
pub struct ServerKeyByInterface(BTreeMap<String, ServerKey>);

pub struct ServerKey {
    pub private: [u8; 32],
    pub public: String,
}

impl ServerKeyByInterface {
    /// Reads and validates the private key file for every configured WireGuard interface.
    pub fn read(config: &Config) -> Result<Self, String> {
        let mut keys = BTreeMap::new();
        for (name, i) in &config.interfaces {
            let path = i.private_key_file.display();
            let text = read_secret(&i.private_key_file)?;
            validate_key(&text).map_err(|_| format!("{path} is not a WireGuard key"))?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text)
                .expect("validated key");
            let private: [u8; 32] = bytes.try_into().expect("validated length");
            let public = derive_public_key(&private);
            keys.insert(name.clone(), ServerKey { private, public });
        }
        Ok(Self(keys))
    }

    pub fn get(&self, interface: &str) -> Option<&ServerKey> {
        self.0.get(interface)
    }

    /// Returns true if `public_key` matches any configured interface's server public key.
    pub fn contains_public(&self, public_key: &str) -> bool {
        self.0.values().any(|k| k.public == public_key)
    }
}
