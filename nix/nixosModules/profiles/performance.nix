{
  config,
  lib,
  ...
}:

let
  cfg = config.services.forgeproxy-performance;
in
{
  options.services.forgeproxy-performance = {
    enable = lib.mkEnableOption "network and I/O performance tuning for forgeproxy";

    tcpRmemMax = lib.mkOption {
      type = lib.types.int;
      default = 134217728;
      description = ''
        Maximum TCP receive buffer size in bytes (net.core.rmem_max).
        The kernel's TCP auto-tuning scales per-connection receive buffers up to
        this ceiling based on observed bandwidth-delay product (BDP). The Linux
        default of 212992 (208 KiB) caps each connection to ~1.6 Gbps at 1ms RTT.
        128 MiB allows the kernel to auto-tune up to 25 Gbps+ per connection even
        on paths with several milliseconds of RTT.
      '';
    };

    tcpWmemMax = lib.mkOption {
      type = lib.types.int;
      default = 134217728;
      description = ''
        Maximum TCP send buffer size in bytes (net.core.wmem_max).
        Same rationale as tcpRmemMax: the default 208 KiB limits per-connection
        send throughput to ~1.6 Gbps at 1ms RTT. For streaming large git pack
        files at line rate, the kernel needs enough send buffer to keep the TCP
        pipe full during congestion window growth and loss recovery.
      '';
    };

    tcpRmem = lib.mkOption {
      type = lib.types.str;
      default = "4096 1048576 134217728";
      description = ''
        Per-socket TCP receive buffer auto-tuning range: "min default max".
        - min (4 KiB): minimum receive buffer even under memory pressure.
        - default (1 MiB): initial receive buffer, large enough for a ~8 Gbps
          connection at 1ms RTT without waiting for auto-tuning ramp-up.
        - max (128 MiB): ceiling for auto-tuning, matching tcpRmemMax.
      '';
    };

    tcpWmem = lib.mkOption {
      type = lib.types.str;
      default = "4096 1048576 134217728";
      description = ''
        Per-socket TCP send buffer auto-tuning range: "min default max".
        - min (4 KiB): minimum send buffer even under memory pressure.
        - default (1 MiB): initial send buffer. Forgeproxy streams large pack
          files, so starting at 1 MiB avoids a slow ramp-up phase where the
          kernel gradually increases the buffer from the Linux default of 16 KiB.
        - max (128 MiB): ceiling for auto-tuning, matching tcpWmemMax.
      '';
    };

    netdevMaxBacklog = lib.mkOption {
      type = lib.types.int;
      default = 16384;
      description = ''
        Maximum number of packets queued on the INPUT side of a network device
        (net.core.netdev_max_backlog). The Linux default of 1000 can cause drops
        when many concurrent pack streams generate bursts of incoming ACKs and
        data. 16384 provides headroom for 25 Gbps interfaces with many flows.
      '';
    };

    tcpCongestionControl = lib.mkOption {
      type = lib.types.str;
      default = "bbr";
      description = ''
        TCP congestion control algorithm (net.ipv4.tcp_congestion_control).
        BBR (Bottleneck Bandwidth and RTT) is a model-based congestion control
        algorithm that estimates actual bottleneck bandwidth and minimum RTT,
        then paces sends to match. Unlike loss-based algorithms like cubic, BBR:
        - Reaches line rate faster (probes bandwidth every ~10 RTTs vs. cubic's
          slow multiplicative increase after loss).
        - Avoids bufferbloat by targeting 1x BDP in-flight, keeping switch and
          NIC queues short.
        - Maintains throughput on paths with shallow buffers (common in AWS VPCs
          where NLBs and ENIs have limited queuing).
        - Provides better fairness among many concurrent streams.
        Requires the "tcp_bbr" kernel module and "fq" qdisc.
      '';
    };

    defaultQdisc = lib.mkOption {
      type = lib.types.str;
      default = "fq";
      description = ''
        Default queuing discipline (net.core.default_qdisc). BBR requires the
        Fair Queuing (fq) qdisc to pace packets at the rate it computes. Without
        fq, BBR falls back to non-paced sending which eliminates most of its
        advantages over cubic.
      '';
    };

    somaxconn = lib.mkOption {
      type = lib.types.int;
      default = 8192;
      description = ''
        Maximum listen backlog (net.core.somaxconn). During thundering-herd
        scenarios, many clients connect simultaneously. The default of 4096 is
        adequate for most cases, but 8192 provides additional headroom for burst
        connection storms from CI fleets.
      '';
    };

    blockReadaheadSectors = lib.mkOption {
      type = lib.types.int;
      default = 8192;
      description = ''
        Block device readahead in 512-byte sectors. 8192 sectors = 4 MiB.
        Forgeproxy's dominant I/O pattern is sequential reads of large pack files
        (hundreds of MiB to several GiB). Increasing readahead from the default
        of 256 sectors (128 KiB) to 4 MiB allows the kernel to prefetch more data
        per I/O request, reducing the number of block-layer round-trips and
        improving sequential read throughput from gp3 EBS volumes.
      '';
    };

    blockDevice = lib.mkOption {
      type = lib.types.str;
      default = "nvme*";
      description = ''
        Glob pattern for block devices to apply readahead tuning. Defaults to all
        NVMe devices, which covers both root and dedicated cache EBS volumes on
        Nitro instances.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    boot.kernelModules = lib.mkIf (cfg.tcpCongestionControl == "bbr") [ "tcp_bbr" ];

    boot.kernel.sysctl = {
      # ── TCP buffer auto-tuning ceilings ────────────────────────────
      "net.core.rmem_max" = cfg.tcpRmemMax;
      "net.core.wmem_max" = cfg.tcpWmemMax;
      "net.ipv4.tcp_rmem" = cfg.tcpRmem;
      "net.ipv4.tcp_wmem" = cfg.tcpWmem;

      # ── Network device queue depth ─────────────────────────────────
      "net.core.netdev_max_backlog" = cfg.netdevMaxBacklog;

      # ── Congestion control ─────────────────────────────────────────
      "net.ipv4.tcp_congestion_control" = cfg.tcpCongestionControl;
      "net.core.default_qdisc" = cfg.defaultQdisc;

      # ── Listen backlog ─────────────────────────────────────────────
      "net.core.somaxconn" = cfg.somaxconn;
    };

    services.udev.extraRules = ''
      ACTION=="add|change", KERNEL=="${cfg.blockDevice}", ATTR{bdi/read_ahead_kb}="${
        toString (cfg.blockReadaheadSectors / 2)
      }"
    '';
  };
}
