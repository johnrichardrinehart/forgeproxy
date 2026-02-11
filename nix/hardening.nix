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
  # SSH hardening -- base security (no FIPS algorithm restrictions)
  # ══════════════════════════════════════════════════════════════════════
  services.openssh.settings = {
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

  # ══════════════════════════════════════════════════════════════════════
  # Basic audit daemon (no rules -- compliance modules add rules)
  # ══════════════════════════════════════════════════════════════════════
  security.auditd.enable = true;

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
