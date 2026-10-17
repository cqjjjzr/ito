{ lib, rustPlatform, makeWrapper, cacert, iproute2, wireguard-tools, nftables, systemd
, version ? (lib.importTOML ../../Cargo.toml).workspace.package.version }:

rustPlatform.buildRustPackage {
  pname = "ito-agent";
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
    description = "Connects a Linux host to Ito controllers and synchronizes its WireGuard tunnels";
    license = lib.licenses.mit;
    mainProgram = "ito-agent";
    platforms = [ "x86_64-linux" "aarch64-linux" ];
  };
}
