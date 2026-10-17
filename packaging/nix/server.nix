{ lib, rustPlatform, stdenvNoCC, fetchPnpmDeps, pnpmConfigHook, pnpm_10, nodejs, makeWrapper, cacert
, iproute2, wireguard-tools, version ? (lib.importTOML ../../Cargo.toml).workspace.package.version }:
let
  # Frontend assets embedded into the server binary from web/dist.
  web = stdenvNoCC.mkDerivation (finalAttrs: {
    pname = "ito-web";
    inherit version;
    src = lib.fileset.toSource {
      root = ../../.;
      fileset = lib.fileset.unions [
        ../../web/package.json ../../web/pnpm-lock.yaml ../../web/index.html ../../web/tsconfig.json
        ../../web/vite.config.ts ../../web/playwright.config.ts ../../web/src ../../web/public ../../web/e2e
        ../../docs/modules/ROOT/attachments/openapi.json
      ];
    };
    pnpmRoot = "web";
    pnpmDeps = fetchPnpmDeps {
      inherit (finalAttrs) pname version src;
      sourceRoot = "${finalAttrs.src.name}/web";
      pnpm = pnpm_10;
      fetcherVersion = 4;
      hash = "sha256-giMfxdmgqnQG7ujk5fDn5BNbC3q8Nr7eXBlYPO6noko=";
    };
    nativeBuildInputs = [ nodejs pnpm_10 pnpmConfigHook ];
    # pnpmConfigHook runs with --ignore-scripts; run postinstall explicitly to generate schema.d.ts.
    buildPhase = ''
      runHook preBuild
      cd web
      pnpm run postinstall
      pnpm build
      runHook postBuild
    '';
    installPhase = "cp -r dist $out";
  });
in
rustPlatform.buildRustPackage {
  pname = "ito";
  inherit version;
  src = lib.fileset.toSource {
    root = ../../.;
    fileset = lib.fileset.unions [
      ../../Cargo.toml ../../Cargo.lock ../../crates ../../config.sample.toml
      ../../LICENSE.txt ../../THIRD_PARTY_NOTICES.md ../../docs/modules/ROOT/attachments/openapi.json
      ../../config.default.toml ../../config.schema.json ../../docs/modules/ROOT/partials/configuration-keys.adoc
    ];
  };
  cargoLock.lockFile = ../../Cargo.lock;
  cargoBuildFlags = [ "-p" "ito" ];
  cargoTestFlags = [ "-p" "ito" ];
  nativeBuildInputs = [ makeWrapper ];
  preCheck = "export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt";
  preBuild = "mkdir -p web && cp -r ${web} web/dist";
  postInstall = ''
    wrapProgram "$out/bin/ito" --prefix PATH : ${lib.makeBinPath [ iproute2 wireguard-tools ]}
    install -Dm644 -t "$out/share/doc/ito" LICENSE.txt THIRD_PARTY_NOTICES.md \
      config.default.toml config.schema.json
  '';
  meta = {
    description = "A control plane for WireGuard allowing self-service of VPN users";
    license = lib.licenses.mit;
    mainProgram = "ito";
    platforms = [ "x86_64-linux" "aarch64-linux" ];
  };
}
