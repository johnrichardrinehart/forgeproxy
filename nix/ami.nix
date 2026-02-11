{ config, lib, pkgs, modulesPath, ... }:

{
  imports = [
    "${modulesPath}/virtualisation/amazon-image.nix"
  ];

  # ══════════════════════════════════════════════════════════════════════
  # EC2 instance configuration
  # ══════════════════════════════════════════════════════════════════════

  # EBS root volume: GP3, 50 GiB, KMS-encrypted, delete-on-termination.
  # Configured via the EC2 launch template / `amazon-image.nix` defaults,
  # not NixOS options (no `ec2.ebs` option exists).

  # IMDSv2 is enforced at the EC2 launch template level
  # (HttpTokens = "required", HttpPutResponseHopLimit = 1).
  # There is no NixOS-level knob for this; it is documented here for
  # visibility so operators know the assumption exists.

  # ══════════════════════════════════════════════════════════════════════
  # Nix daemon / store maintenance
  # ══════════════════════════════════════════════════════════════════════
  nix = {
    # Automatic garbage collection to keep disk usage bounded.
    gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 14d";
    };

    settings = {
      # Limit concurrent builds to avoid exhausting memory on smaller
      # instances (e.g., r6i.large with 16 GiB).
      max-jobs = lib.mkDefault 2;

      # Enable the flakes feature set permanently.
      experimental-features = [ "nix-command" "flakes" ];

      # Reduce Nix store disk usage by hard-linking identical files.
      auto-optimise-store = true;
    };
  };

  # ══════════════════════════════════════════════════════════════════════
  # Time synchronisation
  # ══════════════════════════════════════════════════════════════════════
  services.chrony = {
    enable = true;
    # Use the Amazon Time Sync Service (link-local, no network egress).
    servers = [ "169.254.169.123" ];
  };

  # ══════════════════════════════════════════════════════════════════════
  # System state version
  # ══════════════════════════════════════════════════════════════════════
  # This value determines the NixOS release from which default option
  # values are taken.  It does NOT affect the packages installed.
  # Changing it requires reading the release notes for the target
  # version.
  system.stateVersion = "24.11";
}
