{
  description = "Git Caching Reverse Proxy";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    sops-nix = {
      url = "github:Mic92/sops-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ self, flake-parts, ... }:
    let
      lib = inputs.nixpkgs.lib;
      gitRevision =
        if self ? shortRev then
          self.shortRev
        else if self ? dirtyShortRev then
          self.dirtyShortRev
        else
          "unknown";
      appSource = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./.cargo
          ./config.example.yaml
          ./ghe-key-lookup
          ./nix/lib
          ./nix/nixosConfigurations
          ./nix/nixosModules
          ./nix/overlays
          ./nix/packages
          ./rust
          ./scripts
          ./terraform/scripts
        ];
      };
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      imports = [ inputs.flake-parts.flakeModules.partitions ];

      # ────────────────────────────────────────────────────────────────────
      # Partition: route dev-only outputs so consumers don't fetch
      # git-hooks / treefmt-nix inputs.
      # ────────────────────────────────────────────────────────────────────
      partitionedAttrs = {
        checks = "dev";
        devShells = "dev";
        formatter = "dev";
      };

      partitions.dev = {
        extraInputsFlake = ./dev;
        module = import ./nix/flake/dev-partition.nix;
      };

      # ────────────────────────────────────────────────────────────────────
      # Per-system outputs (packages only — checks/devShells are in dev)
      # ────────────────────────────────────────────────────────────────────
      perSystem =
        {
          config,
          pkgs,
          system,
          ...
        }:
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              inputs.rust-overlay.overlays.default
              self.overlays.default
            ];
            config.allowUnfreePredicate =
              pkg:
              builtins.elem (pkg.pname or "") [
                "terraform"
              ];
          };

          legacyPackages = pkgs;

          packages = import "${appSource}/nix/packages" {
            inherit pkgs config;
          };
        };

      # ────────────────────────────────────────────────────────────────────
      # Flake-wide outputs (overlays, modules, configurations)
      # ────────────────────────────────────────────────────────────────────
      flake = {
        overlays.default = import "${appSource}/nix/overlays/default.nix" { inherit gitRevision; };
        nixosModules = import "${appSource}/nix/nixosModules";
        nixosConfigurations = import "${appSource}/nix/nixosConfigurations" { inherit self inputs; };
      };
    };
}
