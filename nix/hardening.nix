{
  config,
  lib,
  pkgs,
  modulesPath,
  ...
}:

{
  imports = [
    "${modulesPath}/profiles/hardened.nix"
  ];

  # ══════════════════════════════════════════════════════════════════════
  # SSH hardening -- FIPS 140-2/140-3 compliant algorithms only
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

    PasswordAuthentication = false;
    PermitRootLogin = lib.mkForce "no";
    X11Forwarding = false;
    MaxAuthTries = 3;
    ClientAliveInterval = 300;
    ClientAliveCountMax = 2;
    AllowAgentForwarding = false;
    AllowTcpForwarding = false;
    PermitEmptyPasswords = false;
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
  # Audit daemon -- required for FedRAMP AU-2 / AU-12
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

      # Monitor TLS certificate stores used by gheproxy and KeyDB.
      "-w /etc/ssl/gheproxy/ -p wa -k tls_certs"
      "-w /etc/ssl/keydb/ -p wa -k tls_certs"

      # Make audit configuration immutable until next boot (-e 2).
      "-e 2"
    ];
  };

  # ══════════════════════════════════════════════════════════════════════
  # Kernel hardening via sysctl
  # ══════════════════════════════════════════════════════════════════════
  boot.kernel.sysctl = {
    # ── Network hardening ────────────────────────────────────────────
    # Disable IP source routing.
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv4.conf.default.accept_source_route" = 0;
    "net.ipv6.conf.all.accept_source_route" = 0;
    "net.ipv6.conf.default.accept_source_route" = 0;

    # Disable ICMP redirects.
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.default.accept_redirects" = 0;
    "net.ipv6.conf.all.accept_redirects" = 0;
    "net.ipv6.conf.default.accept_redirects" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.default.send_redirects" = 0;

    # Enable reverse-path filtering (BCP38 / anti-spoofing).
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.default.rp_filter" = 1;

    # Log martian packets.
    "net.ipv4.conf.all.log_martians" = 1;
    "net.ipv4.conf.default.log_martians" = 1;

    # Ignore ICMP broadcast echo requests.
    "net.ipv4.icmp_echo_ignore_broadcasts" = 1;

    # Enable SYN cookies (SYN flood protection).
    "net.ipv4.tcp_syncookies" = 1;

    # Disable IPv6 router advertisements.
    "net.ipv6.conf.all.accept_ra" = 0;
    "net.ipv6.conf.default.accept_ra" = 0;

    # ── Memory hardening ─────────────────────────────────────────────
    # Restrict access to kernel pointers in /proc.
    "kernel.kptr_restrict" = 2;

    # Restrict dmesg access to root.
    "kernel.dmesg_restrict" = 1;

    # Restrict perf_event access.
    "kernel.perf_event_paranoid" = 3;

    # Restrict unprivileged user namespaces.
    "kernel.unprivileged_userns_clone" = 0;

    # Restrict ptrace to parent processes only.
    "kernel.yama.ptrace_scope" = 1;

    # Disable SysRq key completely.
    "kernel.sysrq" = 0;

    # Randomize virtual address space layout.
    "kernel.randomize_va_space" = 2;

    # ── Filesystem hardening ─────────────────────────────────────────
    # Restrict creating hard/symbolic links.
    "fs.protected_hardlinks" = 1;
    "fs.protected_symlinks" = 1;

    # Restrict core dumps.
    "fs.suid_dumpable" = 0;
  };

  # Disable core dumps via resource limits as well.
  security.pam.loginLimits = [
    {
      domain = "*";
      type = "hard";
      item = "core";
      value = "0";
    }
  ];

  # ══════════════════════════════════════════════════════════════════════
  # Miscellaneous hardening
  # ══════════════════════════════════════════════════════════════════════

  # Remove unnecessary kernel modules from the initrd.
  boot.blacklistedKernelModules = [
    "dccp"
    "sctp"
    "rds"
    "tipc"
    "usb-storage"
    "firewire-core"
  ];

  # Disable wireless / Bluetooth (server environment).
  hardware.bluetooth.enable = false;

  # Ensure nix-daemon cannot be used by arbitrary users.
  nix.settings.allowed-users = [
    "root"
    "@wheel"
  ];
}
