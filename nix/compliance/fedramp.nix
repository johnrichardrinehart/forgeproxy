{
  config,
  lib,
  options,
  pkgs,
  ...
}:

let
  cfg = config.services.forgecache.compliance.fedramp;
  forgecacheModuleLoaded = options.services ? forgecache && options.services.forgecache ? package;
in
{
  options.services.forgecache.compliance.fedramp = {
    enable = lib.mkEnableOption "FedRAMP compliance controls (FIPS SSH, AU-2/AU-12 audit rules, FIPS build)";
  };

  config = lib.mkMerge (
    [
      (lib.mkIf cfg.enable {
        # ══════════════════════════════════════════════════════════════════════
        # FIPS 140-2/140-3 compliant SSH algorithms only
        # ══════════════════════════════════════════════════════════════════════
        services.openssh.settings = {
          # Key exchange: NIST-approved curves and DH group16 (4096-bit).
          KexAlgorithms = [
            "ecdh-sha2-nistp384"
            "ecdh-sha2-nistp521"
            "diffie-hellman-group16-sha512"
          ];

          # Ciphers: AES-GCM only (FIPS-approved AEAD).
          Ciphers = [
            "aes256-gcm@openssh.com"
            "aes128-gcm@openssh.com"
          ];

          # MACs: HMAC-SHA2 with Encrypt-then-MAC only.
          Macs = [
            "hmac-sha2-256-etm@openssh.com"
            "hmac-sha2-512-etm@openssh.com"
          ];
        };

        # Restrict host key types to FIPS-compliant algorithms.
        services.openssh.hostKeys = [
          {
            path = "/etc/ssh/ssh_host_ecdsa_key";
            type = "ecdsa";
            bits = 384;
          }
          {
            path = "/etc/ssh/ssh_host_ed25519_key";
            type = "ed25519";
          }
        ];

        # ══════════════════════════════════════════════════════════════════════
        # FedRAMP AU-2 / AU-12 audit rules
        # ══════════════════════════════════════════════════════════════════════
        security.auditd.enable = true;

        security.audit = {
          enable = true;
          rules = [
            # Monitor authentication databases.
            "-w /etc/passwd -p wa -k identity"
            "-w /etc/group -p wa -k identity"
            "-w /etc/shadow -p wa -k identity"
            "-w /etc/gshadow -p wa -k identity"

            # Monitor SSH configuration changes.
            "-w /etc/ssh/sshd_config -p wa -k sshd_config"
            "-w /etc/ssh/sshd_config.d -p wa -k sshd_config"

            # Monitor sudo and privileged command execution.
            "-w /etc/sudoers -p wa -k sudoers"
            "-w /etc/sudoers.d -p wa -k sudoers"

            # Monitor kernel module loading.
            "-w /sbin/insmod -p x -k modules"
            "-w /sbin/rmmod -p x -k modules"
            "-w /sbin/modprobe -p x -k modules"
            "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"

            # Monitor mount operations.
            "-a always,exit -F arch=b64 -S mount -S umount2 -k mounts"

            # Monitor changes to audit configuration.
            "-w /etc/audit/ -p wa -k audit_config"
            "-w /etc/audit/auditd.conf -p wa -k audit_config"
            "-w /etc/audit/audit.rules -p wa -k audit_config"

            # Monitor login/logout events.
            "-w /var/log/lastlog -p wa -k logins"
            "-w /var/log/wtmp -p wa -k logins"
            "-w /var/log/btmp -p wa -k logins"

            # Monitor cron configuration.
            "-w /etc/crontab -p wa -k cron"
            "-w /etc/cron.d -p wa -k cron"

            # Monitor TLS certificate stores used by forgecache and KeyDB.
            "-w /etc/ssl/forgecache/ -p wa -k tls_certs"
            "-w /etc/ssl/keydb/ -p wa -k tls_certs"

            # Make audit configuration immutable until next boot (-e 2).
            "-e 2"
          ];
        };
      })

    ]
    ++ lib.optionals forgecacheModuleLoaded [
      # ══════════════════════════════════════════════════════════════════════
      # FIPS package override -- when the proxy service is enabled and the
      # forgecache module is loaded, replace the default package with the
      # FIPS-enabled build.
      # ══════════════════════════════════════════════════════════════════════
      (lib.mkIf (cfg.enable && (config.services.forgecache.enable or false)) {
        services.forgecache.package = lib.mkDefault (pkgs.forgecache.override { fipsEnabled = true; });
      })
    ]
  );
}
