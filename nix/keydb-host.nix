{ config, lib, ... }:
{
  imports = [
    ./keydb.nix
    ./hardening.nix
  ];

  config = {
    services.keydb.enable = lib.mkDefault true;
  };
}
