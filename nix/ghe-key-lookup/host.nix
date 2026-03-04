{ lib, ... }:
{
  imports = [
    ./module.nix
    ../hardening.nix
    ../ami.nix
    ../local-vm.nix
  ];
  config = {
    services.ghe-key-lookup.enable = lib.mkDefault true;

    # Hardened default: no inbound SSH on production closure.
    services.openssh.enable = lib.mkDefault false;
    networking.firewall.allowedTCPPorts = lib.mkDefault [ ];

    # Keep serial console login disabled in hardened closure.
    systemd.services."serial-getty@ttyS0".enable = lib.mkDefault false;
  };
}
