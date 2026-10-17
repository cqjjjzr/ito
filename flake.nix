{
  description = "Ito controller and Linux agent packages and NixOS services";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          rustPlatform = pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; };
        in rec {
          ito = pkgs.callPackage ./packaging/nix/server.nix { inherit rustPlatform; };
          ito-agent = pkgs.callPackage ./packaging/nix/agent.nix { inherit rustPlatform; };
          default = ito;
        });

      nixosModules = rec {
        ito = { lib, pkgs, ... }: {
          imports = [ ./packaging/nix/server-module.nix ];
          services.ito.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.ito;
        };
        ito-agent = { lib, pkgs, ... }: {
          imports = [ ./packaging/nix/agent-module.nix ];
          services.ito-agent.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.ito-agent;
        };
        default = ito;
      };

      checks = forAllSystems (system: {
        package = self.packages.${system}.ito;
        agent-package = self.packages.${system}.ito-agent;
        service = nixpkgs.legacyPackages.${system}.callPackage ./packaging/nix/test.nix {
          package = self.packages.${system}.ito;
          agentPackage = self.packages.${system}.ito-agent;
        };
      });
    };
}
