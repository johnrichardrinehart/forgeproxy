{ config, lib, ... }:
{
  imports = [
    ./keydb.nix
    ./keydb-secrets.nix
    ./hardening.nix
    ./compliance/default.nix
  ];

  config = {
    services.keydb.enable = lib.mkDefault true;
  };
}
