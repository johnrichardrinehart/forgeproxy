{ config, lib, ... }:
{
  imports = [
    ../forgeproxy/default.nix
    ../nginx/default.nix
    ../nginx/runtime.nix
    ../profiles/hardening.nix
    ../profiles/performance.nix
    ../forgeproxy/secrets.nix
    ../forgeproxy/backend.nix
    ../compliance/default.nix
    ../profiles/local-vm.nix
  ];

  config = {
    networking.hostName = lib.mkForce "forgeproxy";
    services.forgeproxy.enable = lib.mkDefault true;
    services.forgeproxy-nginx.enable = lib.mkDefault true;
    services.forgeproxy-performance.enable = lib.mkDefault true;
  };
}
