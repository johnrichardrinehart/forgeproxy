# Overrides applied only to system.build.vm (QEMU local VMs).
# Does not affect AMI or other image builds.
{ lib, ... }:
{
  virtualisation.vmVariant = {
    systemd.services.fetch-ec2-metadata.enable = false;

    # headless.nix (via amazon-image.nix) disables all gettys; re-enable
    # tty1 + the autovt template so the QEMU window shows a login prompt.
    systemd.services."getty@tty1".enable = lib.mkForce true;
    systemd.services."autovt@".enable = lib.mkForce true;
  };
}
