use base64::Engine as _;
use ito::{
    error::{Result, internal},
    kernel::{KernelDriver, Link, Peer},
    wireguard_keys::derive_public_key,
};
use std::{collections::BTreeMap, sync::Mutex};

/// A fake kernel: an in-memory simulator of the WireGuard links that the reconciler's `ip` and `wg`
/// command lines change. Tests read its links to see what the reconciler did, log its commands to
/// see what it ran, and make it fail commands to see how the reconciler copes.
#[derive(Default)]
pub struct FakeKernel {
    links: Mutex<BTreeMap<String, Link>>,
    log: Mutex<Vec<String>>,
    /// Commands whose line contains one of these strings fail.
    failures: Mutex<Vec<String>>,
}

impl FakeKernel {
    /// Finds the link `name`, as the reconciler would read it.
    pub fn find_link(&self, name: &str) -> Option<Link> {
        self.links.lock().unwrap().get(name).cloned()
    }

    /// Finds the peers of the link `name`, or none when the link is absent.
    pub fn find_peers(&self, name: &str) -> Vec<Peer> {
        self.find_link(name).map(|l| l.peers).unwrap_or_default()
    }

    /// Inserts `link` as `name`, as if someone outside the controller created it.
    pub fn insert_link(&self, name: &str, link: Link) {
        self.links.lock().unwrap().insert(name.into(), link);
    }

    /// Changes the link `name` outside the reconciler.
    pub fn edit_link(&self, name: &str, change: impl FnOnce(&mut Link)) {
        change(self.links.lock().unwrap().get_mut(name).unwrap());
    }

    /// Makes every later command whose line contains `pattern` fail.
    pub fn inject_failure(&self, pattern: &str) {
        self.failures.lock().unwrap().push(pattern.into());
    }

    pub fn clear_failures(&self) {
        self.failures.lock().unwrap().clear();
    }

    /// Lists the command lines run so far.
    pub fn list_commands(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl KernelDriver for FakeKernel {
    async fn read_link(&self, name: &str) -> Result<Option<Link>> {
        Ok(self.find_link(name))
    }

    async fn list_links(&self) -> Result<BTreeMap<String, String>> {
        let links = self.links.lock().unwrap();
        Ok(links
            .iter()
            .map(|(n, l)| (n.clone(), l.alias.clone()))
            .collect())
    }

    async fn run(&self, line: Vec<String>, input: Option<String>) -> Result<Vec<u8>> {
        let text = line.join(" ");
        self.log.lock().unwrap().push(text.clone());
        let failures = self.failures.lock().unwrap();
        if failures.iter().any(|f| text.contains(f.as_str())) {
            return Err(internal(format!("injected failure: {text}")));
        }
        let input = input.unwrap_or_default();
        let mut links = self.links.lock().unwrap();
        let args: Vec<&str> = line.iter().map(String::as_str).collect();
        // Commands that create or delete a link; every other command changes an existing one.
        let name = match args[..] {
            [
                "ip",
                "link",
                "add",
                "dev",
                name,
                "mtu",
                mtu,
                "type",
                "wireguard",
            ] => {
                let link = Link {
                    mtu: mtu.parse().unwrap(),
                    ..Link::default()
                };
                links.insert(name.into(), link);
                return Ok(Vec::new());
            }
            ["ip", "link", "delete", "dev", name] => {
                links.remove(name);
                return Ok(Vec::new());
            }
            ["ip", "link", "set", "dev", name, ..]
            | ["ip", "address", _, _, "dev", name]
            | ["wg", "set", name, ..] => name,
            _ => panic!("unexpected command: {text}"),
        };
        let l = links.get_mut(name).ok_or_else(|| internal("no link"))?;
        match args[..] {
            ["ip", "link", "set", "dev", _, "alias", alias] => l.alias = alias.into(),
            ["ip", "link", "set", "dev", _, "mtu", mtu] => l.mtu = mtu.parse().unwrap(),
            ["ip", "link", "set", "dev", _, state @ ("up" | "down")] => l.up = state == "up",
            ["ip", "address", "replace", address, "dev", _] => {
                if !l.addresses.iter().any(|a| a == address) {
                    l.addresses.push(address.into());
                }
            }
            ["ip", "address", "delete", address, "dev", _] => l.addresses.retain(|a| a != address),
            [
                "wg",
                "set",
                _,
                "private-key",
                "/dev/stdin",
                "listen-port",
                port,
            ] => {
                let key: [u8; 32] = base64::engine::general_purpose::STANDARD
                    .decode(&input)
                    .unwrap()
                    .try_into()
                    .unwrap();
                l.public_key = derive_public_key(&key);
                l.listen_port = port.parse().unwrap();
            }
            [
                "wg",
                "set",
                _,
                "peer",
                key,
                "preshared-key",
                "/dev/stdin",
                "allowed-ips",
                allowed,
            ] => {
                let mut allowed_ips: Vec<String> = allowed
                    .split(',')
                    .filter(|a| !a.is_empty())
                    .map(String::from)
                    .collect();
                allowed_ips.sort();
                // An all-zero preshared key means none, as in `wg`.
                let zero = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
                let preshared_key = if input == zero { String::new() } else { input };
                l.peers.retain(|p| p.public_key != key);
                l.peers.push(Peer {
                    public_key: key.into(),
                    preshared_key,
                    allowed_ips,
                    ..Peer::default()
                });
            }
            ["wg", "set", _, "peer", key, "remove"] => l.peers.retain(|p| p.public_key != key),
            _ => panic!("unexpected command: {text}"),
        }
        Ok(Vec::new())
    }
}
