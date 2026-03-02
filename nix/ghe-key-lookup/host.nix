{ lib, ... }:
{
  imports = [
    ./module.nix
    ../hardening.nix
    ../ami.nix
    ../local-vm.nix
  ];
  config.services.ghe-key-lookup.enable = lib.mkDefault true;
}
