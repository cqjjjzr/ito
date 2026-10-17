{ config, lib, pkgs, ... }:
let
  cfg = config.services.ito-agent;
in {
  options.services.ito-agent = {
    enable = lib.mkEnableOption "the Ito Linux agent";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./agent.nix { };
      description = "Ito Linux agent package.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
    boot.kernelModules = [ "wireguard" ];
    systemd.services.ito-agent = {
      description = "Ito agent: keeps this host's Ito connections in step";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} run";
        User = "root";
        Group = "root";
        Restart = "on-failure";
        RestartSec = 10;
        UMask = "0077";
        StateDirectory = "ito-agent";
        StateDirectoryMode = "0700";
        NoNewPrivileges = true;
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectClock = true;
        ProtectHostname = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
      };
    };
  };
}
