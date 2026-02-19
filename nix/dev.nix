# Dev overlay — relaxes hardened-profile restrictions for debugging.
# Import alongside a production closure to get root SSH, password auth,
# and serial-console output without changing any other module composition.
{ lib, ... }:
{
  # mkOverride 40 wins over hardening.nix's mkForce (priority 50)
  services.openssh.settings.PermitRootLogin = lib.mkOverride 40 "yes";
  services.openssh.settings.PasswordAuthentication = lib.mkOverride 40 true;

  users.users.root.initialPassword = "root";

  boot.consoleLogLevel = lib.mkOverride 40 4;
  boot.kernelParams = lib.mkAfter [ "console=ttyS0,115200n8" ];

  # headless.nix disables the serial getty with mkDefault; re-enable it
  # so the EC2 Serial Console presents a login prompt.
  systemd.services."serial-getty@ttyS0".enable = true;
}
