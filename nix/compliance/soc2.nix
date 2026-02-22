{
  config,
  lib,
  ...
}:

let
  cfg = config.services.forgeproxy.compliance.soc2;
  keydbEnabled = config.services.keydb.enable or false;
  nginxEnabled = config.services.nginx.enable or false;
  firewallPorts = config.networking.firewall.allowedTCPPorts or [ ];
in
{
  options.services.forgeproxy.compliance.soc2 = {
    enable = lib.mkEnableOption "SOC2 compliance validation and gap-filling defaults";
  };

  config = lib.mkIf cfg.enable {
    # ══════════════════════════════════════════════════════════════════════
    # Active controls -- fill gaps with sensible defaults
    # ══════════════════════════════════════════════════════════════════════

    # Ensure audit logging is active.
    security.auditd.enable = true;

    # Ensure firewall is enabled by default.
    networking.firewall.enable = lib.mkDefault true;

    # SSH: disable password auth and root login by default.
    services.openssh.settings = {
      PasswordAuthentication = lib.mkDefault false;
      PermitRootLogin = lib.mkDefault "no";
    };

    # Minimal audit rules for SOC2 (lighter than FedRAMP).
    security.audit = {
      enable = true;
      rules = [
        # Monitor identity files.
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/group -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"

        # Monitor login/logout events.
        "-w /var/log/lastlog -p wa -k logins"
        "-w /var/log/wtmp -p wa -k logins"
        "-w /var/log/btmp -p wa -k logins"
      ];
    };

    # ══════════════════════════════════════════════════════════════════════
    # Assertions -- validate configuration meets SOC2 controls
    # ══════════════════════════════════════════════════════════════════════
    assertions = [
      # ── CC6: Logical Access Controls ──────────────────────────────────
      {
        assertion = config.networking.firewall.enable;
        message = "SOC2 CC6: networking.firewall.enable must be true.";
      }
      {
        assertion = config.services.openssh.settings.PasswordAuthentication == false;
        message = "SOC2 CC6: SSH password authentication must be disabled.";
      }
      {
        assertion = config.services.openssh.settings.PermitRootLogin == "no";
        message = "SOC2 CC6: SSH root login must be disabled.";
      }

      # ── CC7: System Operations / Monitoring ──────────────────────────
      {
        assertion = config.security.auditd.enable;
        message = "SOC2 CC7: security.auditd.enable must be true.";
      }
      {
        assertion = config.services.openssh.enable;
        message = "SOC2 CC7: SSH must be enabled for remote management.";
      }
    ]
    ++ lib.optionals nginxEnabled [
      {
        assertion = config.services.nginx.recommendedTlsSettings;
        message = "SOC2 CC6: nginx must use recommendedTlsSettings when enabled.";
      }
    ]
    ++ lib.optionals keydbEnabled [
      # ── CC9: Confidentiality ─────────────────────────────────────────
      {
        assertion = builtins.elem 6380 firewallPorts;
        message = "SOC2 CC9: KeyDB TLS port (6380) must be in firewall allowedTCPPorts.";
      }
      {
        assertion = !(builtins.elem 6379 firewallPorts);
        message = "SOC2 CC6: KeyDB plaintext port (6379) must NOT be in firewall allowedTCPPorts.";
      }
    ];

    # ══════════════════════════════════════════════════════════════════════
    # Informational warnings
    # ══════════════════════════════════════════════════════════════════════
    warnings = [
      "SOC2: External monitoring integration (CloudWatch, Datadog, etc.) must be configured outside NixOS."
      "SOC2: Application-level integrity should be validated via the /healthz endpoint."
      "SOC2: Backup and recovery procedures are operational concerns not configurable through NixOS."
    ];
  };
}
