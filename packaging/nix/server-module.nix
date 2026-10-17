{ config, lib, pkgs, ... }:
let
  cfg = config.services.ito;
  toml = pkgs.formats.toml { };
  generated = toml.generate "ito.toml" cfg.settings;
in {
  options.services.ito = {
    enable = lib.mkEnableOption "ito";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./server.nix { };
      description = "Ito package.";
    };
    settings = lib.mkOption {
      type = toml.type;
      default = { };
      description = "Settings written to config.toml. Keep secrets in the files the settings point to.";
    };
    configFile = lib.mkOption {
      type = lib.types.nullOr (lib.types.pathWith { inStore = false; absolute = true; });
      default = null;
      description = "Absolute path to a complete config.toml, loaded through systemd credentials. Overrides settings.";
    };
  };
  config = lib.mkIf cfg.enable {
    systemd.services.ito = {
      description = "Ito";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      environment.ITO_CONFIG = if cfg.configFile == null then "${generated}" else "%d/config.toml";
      serviceConfig = {
        User = "root";
        Group = "root";
        ExecStart = lib.getExe cfg.package;
        StateDirectory = "ito";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/ito";
        UMask = "0077";
        Restart = "on-failure";
        RestartSec = 10;
        NoNewPrivileges = true;
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_NET_BIND_SERVICE" ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" ];
        LoadCredential = lib.mkIf (cfg.configFile != null) [ "config.toml:${toString cfg.configFile}" ];
      };
    };
  };
}
