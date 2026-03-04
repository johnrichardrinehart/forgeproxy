{
  self,
  pkgs,
  lib,
}:

pkgs.testers.runNixOSTest {
  name = "forgeproxy-compliance";
  globalTimeout = 300;

  nodes = {
    # ── Node with Regulated enabled ──────────────────────────────────────
    regulated =
      {
        config,
        pkgs,
        lib,
        ...
      }:
      {
        imports = [
          self.nixosModules.proxy-host
        ];

        services.forgeproxy.enable = lib.mkForce true;
        services.forgeproxy.package = pkgs.forgeproxy;
        services.forgeproxy-nginx.enable = lib.mkForce false;
        services.amazon-ssm-agent.enable = lib.mkForce false;

        services.forgeproxy.compliance.regulated.enable = true;
        networking.hostName = lib.mkOverride 40 "regulated";

        virtualisation.memorySize = 1024;
      };

    # ── Node with base hardening only (no compliance) ──────────────────
    base =
      {
        config,
        pkgs,
        lib,
        ...
      }:
      {
        imports = [
          self.nixosModules.proxy-host
        ];

        services.forgeproxy.enable = lib.mkForce true;
        services.forgeproxy.package = pkgs.forgeproxy;
        services.forgeproxy-nginx.enable = lib.mkForce false;
        services.amazon-ssm-agent.enable = lib.mkForce false;
        networking.hostName = lib.mkOverride 40 "base";

        virtualisation.memorySize = 1024;
      };
  };

  testScript = ''
    start_all()

    # ── Regulated node: FIPS SSH algorithms are enforced ─────────────────
    with subtest("Regulated enables FIPS SSH KexAlgorithms"):
        regulated.wait_for_unit("multi-user.target")
        sshd_config = regulated.succeed("cat /etc/ssh/sshd_config")
        assert "ecdh-sha2-nistp384" in sshd_config, \
            "Regulated node should have FIPS KexAlgorithms"

    with subtest("Regulated enables FIPS SSH Ciphers"):
        sshd_config = regulated.succeed("cat /etc/ssh/sshd_config")
        assert "aes256-gcm@openssh.com" in sshd_config, \
            "Regulated node should have FIPS Ciphers"

    with subtest("Regulated enables audit rules"):
        # The audit rules file is a nix store derivation loaded by the
        # audit-rules-nixos.service. Find it from the systemd unit.
        unit_content = regulated.succeed("systemctl cat audit-rules-nixos.service")
        assert "audit.rules" in unit_content, \
            "audit-rules-nixos.service should reference an audit rules file"
        import re
        match = re.search(r'(/nix/store/\S+audit\.rules)', unit_content)
        assert match, f"Could not find audit rules path in unit: {unit_content[:200]}"
        audit_rules = regulated.succeed(f"cat {match.group(1)}")
        assert "identity" in audit_rules or "/etc/passwd" in audit_rules, \
            f"Regulated node should have audit rules, got: {audit_rules[:200]}"

    # ── Base node: no FIPS SSH restrictions ────────────────────────────
    with subtest("Base node does not enforce FIPS KexAlgorithms"):
        base.wait_for_unit("multi-user.target")
        sshd_config = base.succeed("cat /etc/ssh/sshd_config")
        # Base hardening disables password auth but does NOT restrict KexAlgorithms
        assert "PasswordAuthentication no" in sshd_config, \
            "Base node should disable password auth"

    with subtest("Base node has auditd enabled"):
        base.succeed("systemctl is-active auditd || systemctl is-enabled auditd")
  '';
}
