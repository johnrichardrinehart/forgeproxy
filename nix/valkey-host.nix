{ config, lib, ... }:
{
  imports = [
    ./valkey.nix
    ./valkey-secrets.nix
    ./valkey-tls.nix
    ./hardening.nix
    ./compliance/default.nix
    ./local-vm.nix
  ];

  config = {
    services.valkey.enable = lib.mkDefault true;
  };
}
