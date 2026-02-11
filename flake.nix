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
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];

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
        module =
          { inputs, ... }:
          {
            imports = [
              inputs.git-hooks.flakeModule
              inputs.treefmt-nix.flakeModule
            ];

            perSystem =
              {
                config,
                pkgs,
                system,
                ...
              }:
              {
                checks = {
                  nixos-vm-test-basic = pkgs.callPackage ./nix/tests/basic.nix { inherit self; };
                  nixos-vm-test-secrets-sops = pkgs.callPackage ./nix/tests/secrets-sops.nix {
                    inherit (inputs) sops-nix;
                  };
                  nixos-vm-test-secrets-aws = pkgs.callPackage ./nix/tests/secrets-aws.nix { };
                  nixos-vm-test-compliance = pkgs.callPackage ./nix/tests/compliance.nix { inherit self; };
                  nixos-vm-test-backend = pkgs.callPackage ./nix/tests/backend.nix { inherit self; };
                };

                # ── Formatting (consumed by git-hooks via treefmt hook) ──
                treefmt = {
                  projectRootFile = "flake.nix";
                  programs = {
                    nixfmt.enable = true;
                    rustfmt = {
                      enable = true;
                      edition = "2021";
                    };
                    yamlfmt.enable = true;
                  };
                };

                # ── Pre-commit hooks ─────────────────────────────────────
                # Disable the sandboxed check derivation: clippy and
                # cargo-check need network + rustc which aren't available
                # in a Nix build.  Formatting is already covered by the
                # treefmt check.
                pre-commit.check.enable = false;
                pre-commit.settings.hooks = {
                  treefmt.enable = true;

                  clippy = {
                    enable = true;
                    entry =
                      let
                        rust = pkgs.rust-bin.stable.latest.default;
                      in
                      toString (
                        pkgs.writeShellScript "clippy-hook" ''
                          cd src && ${rust}/bin/cargo clippy --all-targets -- -D warnings
                        ''
                      );
                    files = "\\.rs$";
                    pass_filenames = false;
                  };

                  cargo-check = {
                    enable = true;
                    entry =
                      let
                        rust = pkgs.rust-bin.stable.latest.default;
                      in
                      toString (
                        pkgs.writeShellScript "cargo-check-hook" ''
                          cd src && ${rust}/bin/cargo check --all-targets
                        ''
                      );
                    files = "\\.rs$";
                    pass_filenames = false;
                  };
                };

                devShells.default = pkgs.mkShell {
                  shellHook = config.pre-commit.installationScript;
                  buildInputs = with pkgs; [
                    (rust-bin.stable.latest.default.override {
                      extensions = [
                        "rust-src"
                        "rust-analyzer"
                      ];
                    })
                    pkg-config
                    cmake
                    openssl
                    git
                    keyutils
                  ];
                  OPENSSL_DIR = "${pkgs.openssl.dev}";
                  OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
                };
              };
          };
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
          };

          packages = {
            forgecache = pkgs.callPackage ./nix/package.nix { };
            forgecache-fips = pkgs.callPackage ./nix/package.nix { fipsEnabled = true; };
            default = config.packages.forgecache;
          };
        };

      # ────────────────────────────────────────────────────────────────────
      # Flake-wide outputs (overlays, modules, configurations)
      # ────────────────────────────────────────────────────────────────────
      flake = {
        overlays.default = final: prev: {
          forgecache = final.callPackage ./nix/package.nix { };
          forgecache-fips = final.callPackage ./nix/package.nix { fipsEnabled = true; };
        };

        nixosModules = {
          forgecache = ./nix/module.nix;
          keydb = ./nix/keydb.nix;
          nginx = ./nix/nginx.nix;
          hardening = ./nix/hardening.nix;
          secrets = ./nix/secrets.nix;
          ami = ./nix/ami.nix;
          backend = ./nix/backend.nix;
          compliance = ./nix/compliance/default.nix;
          proxy-host = ./nix/proxy-host.nix;
          keydb-host = ./nix/keydb-host.nix;
        };

        nixosConfigurations.forgecache = inputs.nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            { nixpkgs.overlays = [ self.overlays.default ]; }
            inputs.sops-nix.nixosModules.sops
            self.nixosModules.proxy-host
            self.nixosModules.ami
            # FedRAMP compliance is opt-in:
            # { services.forgecache.compliance.fedramp.enable = true; }
          ];
        };

        nixosConfigurations.keydb = inputs.nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            { nixpkgs.overlays = [ self.overlays.default ]; }
            inputs.sops-nix.nixosModules.sops
            self.nixosModules.keydb-host
            self.nixosModules.ami
          ];
        };
      };
    };
}
