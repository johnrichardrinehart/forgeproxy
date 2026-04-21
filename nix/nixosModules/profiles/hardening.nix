{
  config,
  lib,
  ...
}:
{
  config = {
    # Keep SMT disabled here. forgeproxy is CPU-bound on Git operations, so
    # reducing the effective core count would directly hurt throughput and
    # clone/bundle latency.
    security.allowSimultaneousMultithreading = true;

    # Carry over the low-risk pieces of the old hardened profile that still
    # make sense for this deployment shape.
    security.forcePageTableIsolation = true;
    security.lockKernelModules = true;
    security.protectKernelImage = true;
    security.unprivilegedUsernsClone = false;

    # SSH hardening -- base security (no FIPS algorithm restrictions)
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

    # Basic audit daemon (no rules -- compliance modules add rules)
    security.auditd.enable = true;

    # Kernel hardening via sysctl
    boot.kernel.sysctl = {
      # ── Network hardening ────────────────────────────────────────────
      "net.ipv4.conf.all.accept_source_route" = 0;
      "net.ipv4.conf.default.accept_source_route" = 0;
      "net.ipv6.conf.all.accept_source_route" = 0;
      "net.ipv6.conf.default.accept_source_route" = 0;
      "net.ipv4.conf.all.accept_redirects" = 0;
      "net.ipv4.conf.default.accept_redirects" = 0;
      "net.ipv6.conf.all.accept_redirects" = 0;
      "net.ipv6.conf.default.accept_redirects" = 0;
      "net.ipv4.conf.all.send_redirects" = 0;
      "net.ipv4.conf.default.send_redirects" = 0;
      "net.ipv4.conf.all.rp_filter" = 1;
      "net.ipv4.conf.default.rp_filter" = 1;
      "net.ipv4.conf.all.log_martians" = 1;
      "net.ipv4.conf.default.log_martians" = 1;
      "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
      "net.ipv4.tcp_syncookies" = 1;
      "net.ipv6.conf.all.accept_ra" = 0;
      "net.ipv6.conf.default.accept_ra" = 0;

      # ── Memory hardening ─────────────────────────────────────────────
      "kernel.kptr_restrict" = 2;
      "kernel.dmesg_restrict" = 1;
      "kernel.perf_event_paranoid" = 3;
      "kernel.unprivileged_userns_clone" = 0;
      "kernel.yama.ptrace_scope" = 1;
      "kernel.sysrq" = 0;
      "kernel.randomize_va_space" = 2;

      # ── Filesystem hardening ─────────────────────────────────────────
      "fs.protected_hardlinks" = 1;
      "fs.protected_symlinks" = 1;
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
  };
}
