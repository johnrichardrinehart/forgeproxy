{ config, lib, ... }:
{
  imports = [
    ./module.nix
    ./nginx.nix
    ./nginx-runtime.nix
    ./hardening.nix
    ./secrets.nix
    ./backend.nix
    ./compliance/default.nix
    ./local-vm.nix
  ];

  config = {
    services.forgeproxy.enable = lib.mkDefault true;
    services.forgeproxy-nginx.enable = lib.mkDefault true;
  };
}
