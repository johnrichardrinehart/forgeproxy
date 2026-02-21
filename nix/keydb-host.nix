{ config, lib, ... }:
{
  imports = [
    ./keydb.nix
    ./keydb-secrets.nix
    ./keydb-tls.nix
    ./hardening.nix
    ./compliance/default.nix
    ./local-vm.nix
  ];

  config = {
    services.keydb.enable = lib.mkDefault true;
  };
}
