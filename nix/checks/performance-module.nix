{
  pkgs,
  self,
  inputs,
}:

let
  lib = inputs.nixpkgs.lib;

  performanceOnly = lib.nixosSystem {
    system = pkgs.system;
    modules = [
      self.nixosModules.performance
      {
        services.forgeproxy-performance = {
          enable = true;
          tcpCongestionControl = "cubic";
          defaultQdisc = "fq_codel";
          blockDevice = "xvd*";
          blockReadaheadSectors = 1024;
        };
      }
    ];
  };

  bbrPerformance = lib.nixosSystem {
    system = pkgs.system;
    modules = [
      self.nixosModules.performance
      {
        services.forgeproxy-performance.enable = true;
      }
    ];
  };

  proxyHostDefault = lib.nixosSystem {
    system = pkgs.system;
    modules = [
      self.nixosModules.proxy-host
      (
        { lib, ... }:
        {
          services.forgeproxy.enable = lib.mkForce false;
          services.forgeproxy-nginx.enable = lib.mkForce false;
        }
      )
    ];
  };

  proxyHostDisabled = lib.nixosSystem {
    system = pkgs.system;
    modules = [
      self.nixosModules.proxy-host
      (
        { lib, ... }:
        {
          services.forgeproxy.enable = lib.mkForce false;
          services.forgeproxy-nginx.enable = lib.mkForce false;
          services.forgeproxy-performance.enable = lib.mkForce false;
        }
      )
    ];
  };

  performanceConfig = performanceOnly.config;
  bbrPerformanceConfig = bbrPerformance.config;
  defaultHostConfig = proxyHostDefault.config;
  disabledHostConfig = proxyHostDisabled.config;

  assertions = [
    (self.nixosModules ? performance)
    defaultHostConfig.services.forgeproxy-performance.enable
    (!disabledHostConfig.services.forgeproxy-performance.enable)
    (performanceConfig.boot.kernel.sysctl."net.core.rmem_max" == 134217728)
    (performanceConfig.boot.kernel.sysctl."net.core.wmem_max" == 134217728)
    (performanceConfig.boot.kernel.sysctl."net.ipv4.tcp_congestion_control" == "cubic")
    (performanceConfig.boot.kernel.sysctl."net.core.default_qdisc" == "fq_codel")
    (!(builtins.elem "tcp_bbr" performanceConfig.boot.kernelModules))
    (builtins.elem "tcp_bbr" bbrPerformanceConfig.boot.kernelModules)
    (lib.hasInfix ''KERNEL=="xvd*"'' performanceConfig.services.udev.extraRules)
    (lib.hasInfix ''ATTR{bdi/read_ahead_kb}="512"'' performanceConfig.services.udev.extraRules)
  ];

  checked =
    assert builtins.all (value: value) assertions;
    "ok";
in
pkgs.runCommand "forgeproxy-performance-module-check"
  {
    inherit checked;
  }
  ''
    touch "$out"
  ''
