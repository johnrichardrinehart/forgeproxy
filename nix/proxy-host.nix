{ config, lib, ... }:
{
  imports = [
    ./module.nix
    ./nginx.nix
    ./hardening.nix
    ./secrets.nix
  ];

  config = {
    services.gheproxy.enable = lib.mkDefault true;
    services.gheproxy-nginx.enable = lib.mkDefault true;
  };
}
