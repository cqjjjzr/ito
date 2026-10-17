{ lib, rustPlatform, makeWrapper, cacert, iproute2, wireguard-tools, nftables, systemd
, version ? (lib.importTOML ../../Cargo.toml).workspace.package.version }:

let
  package = (lib.importTOML ../../crates/agent-linux/Cargo.toml).package;
in
rustPlatform.buildRustPackage {
  pname = package.name;
  inherit version;
  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../Cargo.toml ../../Cargo.lock ../../crates
      ../../LICENSE.txt ../../THIRD_PARTY_NOTICES.md
    ];
  };
  cargoLock.lockFile = ../../Cargo.lock;
  cargoBuildFlags = [ "-p" "ito-agent" ];
  cargoTestFlags = [ "-p" "ito-agent" "-p" "ito-agent-core" "-p" "ito-shared" ];
  nativeBuildInputs = [ makeWrapper ];
  preCheck = "export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt";
  postInstall = ''
    wrapProgram "$out/bin/ito-agent" --prefix PATH : ${lib.makeBinPath [ iproute2 wireguard-tools nftables systemd ]}
    install -Dm644 -t "$out/share/doc/ito-agent" LICENSE.txt THIRD_PARTY_NOTICES.md
  '';
  meta = {
    inherit (package) description;
    license = lib.licenses.mit;
    mainProgram = package.name;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
  };
}
