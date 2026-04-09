{ config, lib, ... }:
{
  imports = [
    ../valkey/default.nix
    ../valkey/secrets.nix
    ../valkey/tls.nix
    ../profiles/hardening.nix
    ../compliance/default.nix
    ../profiles/local-vm.nix
  ];

  config = {
    networking.hostName = lib.mkForce "valkey";
    services.valkey.enable = lib.mkDefault true;
  };
}
