{
  self,
  pkgs,
  lib,
}:

let
  testCerts =
    pkgs.runCommand "backend-test-certs"
      {
        nativeBuildInputs = [ pkgs.openssl ];
      }
      ''
        mkdir -p $out
        openssl req -new -x509 -nodes -days 1 \
          -newkey rsa:2048 \
          -keyout $out/key.pem -out $out/cert.pem \
          -subj "/CN=test"
      '';
in
pkgs.testers.runNixOSTest {
  name = "forgecache-backend";
  globalTimeout = 120;

  nodes = {
    # ── Gitea backend ────────────────────────────────────────────────
    gitea =
      {
        config,
        pkgs,
        lib,
        ...
      }:
      {
        imports = [
          self.nixosModules.forgecache
          self.nixosModules.nginx
          self.nixosModules.backend
        ];

        # We only need nginx config; disable the proxy service itself.
        services.forgecache.enable = lib.mkForce false;

        services.forgecache.backend.type = "gitea";

        services.forgecache-nginx = {
          enable = true;
          serverName = "gitea-proxy";
          sslCertificate = "${testCerts}/cert.pem";
          sslCertificateKey = "${testCerts}/key.pem";
          gheUpstream = "upstream.local";
          resolver = "127.0.0.53";
        };

        virtualisation.memorySize = 1024;
      };

    # ── GitLab backend ───────────────────────────────────────────────
    gitlab =
      {
        config,
        pkgs,
        lib,
        ...
      }:
      {
        imports = [
          self.nixosModules.forgecache
          self.nixosModules.nginx
          self.nixosModules.backend
        ];

        services.forgecache.enable = lib.mkForce false;

        services.forgecache.backend.type = "gitlab";

        services.forgecache-nginx = {
          enable = true;
          serverName = "gitlab-proxy";
          sslCertificate = "${testCerts}/cert.pem";
          sslCertificateKey = "${testCerts}/key.pem";
          gheUpstream = "upstream.local";
          resolver = "127.0.0.53";
        };

        virtualisation.memorySize = 1024;
      };
  };

  testScript = ''
    import re

    start_all()

    def get_nginx_conf(machine):
        """Extract the nginx config path from the systemd service and read it."""
        exec_start = machine.succeed("systemctl show nginx.service -p ExecStart --value")
        match = re.search(r'(/nix/store/[^\s]+nginx\.conf)', exec_start)
        assert match, f"Could not find nginx.conf path in ExecStart: {exec_start}"
        return machine.succeed(f"cat {match.group(1)}")

    # ── Gitea: verify nginx config uses /api/v1 and Gitea headers ─────
    with subtest("Gitea backend uses /api/v1 path prefix"):
        gitea.wait_for_unit("multi-user.target")
        nginx_conf = get_nginx_conf(gitea)
        assert "/api/v1/" in nginx_conf, \
            "Gitea backend should use /api/v1/ path prefix in nginx config"

    with subtest("Gitea backend uses X-Gitea-Event header"):
        nginx_conf = get_nginx_conf(gitea)
        assert "X-Gitea-Event" in nginx_conf, \
            "Gitea backend should reference X-Gitea-Event in nginx config"

    with subtest("Gitea backend uses X-Gitea-Signature header"):
        nginx_conf = get_nginx_conf(gitea)
        assert "X-Gitea-Signature" in nginx_conf, \
            "Gitea backend should reference X-Gitea-Signature in nginx config"

    # ── GitLab: verify nginx config uses /api/v4 and GitLab headers ───
    with subtest("GitLab backend uses /api/v4 path prefix"):
        gitlab.wait_for_unit("multi-user.target")
        nginx_conf = get_nginx_conf(gitlab)
        assert "/api/v4/" in nginx_conf, \
            "GitLab backend should use /api/v4/ path prefix in nginx config"

    with subtest("GitLab backend uses X-Gitlab-Event header"):
        nginx_conf = get_nginx_conf(gitlab)
        assert "X-Gitlab-Event" in nginx_conf, \
            "GitLab backend should reference X-Gitlab-Event in nginx config"

    with subtest("GitLab backend uses X-Gitlab-Token header"):
        nginx_conf = get_nginx_conf(gitlab)
        assert "X-Gitlab-Token" in nginx_conf, \
            "GitLab backend should reference X-Gitlab-Token in nginx config"
  '';
}
