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
    services.forgecache.enable = lib.mkDefault true;
    services.forgecache-nginx.enable = lib.mkDefault true;
  };
}
