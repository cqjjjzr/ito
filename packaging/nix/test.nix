{ pkgs, package, agentPackage }:
pkgs.testers.runNixOSTest {
  name = "ito-service";
  requiredFeatures.kvm = false;
  nodes.machine = {
    imports = [ ./server-module.nix ./agent-module.nix ];
    virtualisation.memorySize = 768;
    services.ito = {
      enable = true;
      inherit package;
      settings = {
        public_url = "http://localhost:8888";
        listen = "127.0.0.1:8888";
        cookie_secure = false;
        oidc = { issuer = "http://localhost:8080"; client_id = "portal"; secret_file = "/etc/ito-oidc"; };
      };
    };
    services.ito-agent = {
      enable = true;
      package = agentPackage;
    };
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("ito.service")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:8888/health/ready")
    machine.wait_for_unit("ito-agent.service")
    machine.wait_until_succeeds("test -f /var/lib/ito-agent/.lock")
    machine.succeed("test $(stat -c %a /var/lib/ito-agent) = 700")
    machine.succeed("test $(stat -c %a /var/lib/ito-agent/.lock) = 600")
    machine.succeed("ito-agent list")
    machine.succeed("systemctl restart ito-agent.service")
    machine.wait_for_unit("ito-agent.service")
    machine.succeed("ito-agent list")
    machine.succeed("curl --fail http://127.0.0.1:8888/ | grep -q 'id=\"app\"'")
    machine.succeed("test $(stat -c %a /var/lib/ito/ito.db) = 600")
    machine.succeed("systemctl restart ito.service")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:8888/health/ready")
  '';
}
