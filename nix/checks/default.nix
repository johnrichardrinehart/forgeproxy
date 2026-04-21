{
  pkgs,
  self,
  inputs,
}:

{
  nixos-vm-test-basic = pkgs.callPackage ./basic.nix { inherit self; };
  nixos-vm-test-pack-cache = pkgs.callPackage ./pack-cache.nix { inherit self; };
  nixos-vm-test-secrets-sops = pkgs.callPackage ./secrets-sops.nix {
    inherit (inputs) sops-nix;
  };
  nixos-vm-test-secrets-aws = pkgs.callPackage ./secrets-aws.nix { };
  nixos-vm-test-compliance = pkgs.callPackage ./compliance.nix { inherit self; };
  nixos-vm-test-backend = pkgs.callPackage ./backend.nix { inherit self; };
  nixos-vm-test-ssh-authz = pkgs.callPackage ./ssh-authz.nix { inherit self; };
  nixos-vm-test-ssh-large-lsrefs = pkgs.callPackage ./ssh-large-lsrefs.nix {
    inherit self;
  };
  nixos-vm-test-keyring-creds = pkgs.callPackage ./keyring-creds.nix { inherit self; };
  nixos-vm-test-ghe-key-lookup-keyring = pkgs.callPackage ./ghe-key-lookup-keyring.nix {
    inherit self;
  };
  nixos-vm-test-eviction-lfu = pkgs.callPackage ./eviction-lfu.nix { inherit self; };
  nixos-vm-test-eviction-lru = pkgs.callPackage ./eviction-lru.nix { inherit self; };
  nixos-vm-test-filtered-bundles = pkgs.callPackage ./filtered-bundles.nix {
    inherit self;
  };
  nixos-vm-test-startup-init-failure = pkgs.callPackage ./startup-init-failure.nix {
    inherit self;
  };
  terraform-config-sync = pkgs.callPackage ./terraform-config.nix { inherit self; };
}
