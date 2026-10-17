#!/bin/sh
# Runs the controller against the identity provider of `just idp-up`, keeping its state in the
# directory $1. Run it inside a user and network namespace, where it may create WireGuard links.
set -eu
umask 077
state=$(realpath "$1")
mkdir -p "$state"
[ -f "$state/wg0.key" ] || wg genkey > "$state/wg0.key"
echo demo-secret > "$state/oidc.secret"
cat > "$state/config.toml" <<END
public_url = "http://localhost:8000"
listen = "[::]:8000"
cookie_secure = false
database = "$state/ito.db"

[oidc]
issuer = "http://127.0.0.1:8080/realms/ito"
client_id = "ito"
secret_file = "$state/oidc.secret"
admin_groups = ["ito-admins"]

[interfaces.wg0]
private_key_file = "$state/wg0.key"
listen_port = 51820
endpoint = "${ITO_ENDPOINT:-127.0.0.1:51820}"
addresses = ["10.77.0.1/24", "fd77::1/64"]
dns = ["10.77.0.1", "fd77::1"]
dns_zone = "ito.test"
default_profile_id = "vpn"
route_profiles = [
  { id = "vpn", name = "VPN only", allowed_ips = ["10.77.0.0/24", "fd77::/64"] },
  { id = "all", name = "All traffic", allowed_ips = ["0.0.0.0/0", "::/0"] },
]

[[interfaces.wg0.pools]]
prefix = "10.77.0.0/24"
min_prefix_length = 28
max_prefixes = 2

[[interfaces.wg0.pools]]
prefix = "fd77::/64"
min_prefix_length = 112
max_prefixes = 2

[dns]
listen = "[::]:53"
name_server = "ns.example.test"
END
exec "${ITO_BIN:-target/debug/ito}" --config "$state/config.toml"
