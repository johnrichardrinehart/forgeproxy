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
                  nixos-vm-test-ssh-authz = pkgs.callPackage ./nix/tests/ssh-authz.nix { inherit self; };
                  nixos-vm-test-keyring-creds = pkgs.callPackage ./nix/tests/keyring-creds.nix { inherit self; };
                  nixos-vm-test-eviction-lfu = pkgs.callPackage ./nix/tests/eviction-lfu.nix { inherit self; };
                  nixos-vm-test-eviction-lru = pkgs.callPackage ./nix/tests/eviction-lru.nix { inherit self; };
                  nixos-vm-test-filtered-bundles = pkgs.callPackage ./nix/tests/filtered-bundles.nix {
                    inherit self;
                  };
                };

                # ── Formatting (consumed by git-hooks via treefmt hook) ──
                treefmt = {
                  projectRootFile = "flake.nix";
                  programs = {
                    nixfmt.enable = true;
                    rustfmt = {
                      enable = true;
                      edition = (builtins.fromTOML (builtins.readFile ./rust/Cargo.toml)).package.edition;
                    };
                    yamlfmt.enable = true;
                    terraform.enable = true;
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
                          cd rust && ${rust}/bin/cargo clippy --all-targets -- -D warnings
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
                          cd rust && ${rust}/bin/cargo check --all-targets
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
                    terraform
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
            config.allowUnfreePredicate =
              pkg:
              builtins.elem (pkg.pname or "") [
                "terraform"
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

            # ── AWS provider configuration ──────────────────────────────────────
            (
              {
                config,
                pkgs,
                lib,
                ...
              }:
              let
                awsForgeProxyProvider = pkgs.writeShellScript "forgecache-aws-provider" ''
                  set -euo pipefail

                  # ── Write config.yaml from Secrets Manager ────────────────────────
                  mkdir -p /etc/forgecache
                  ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                    --secret-id forgecache/service-config \
                    --query 'SecretString' --output text > /etc/forgecache/config.yaml

                  # ── Load per-org credentials into the kernel keyring ──────────────
                  # Discovers all secrets under forgecache/creds/ dynamically — no
                  # hardcoded org list. Adding an org requires creating a new SM secret,
                  # not rebuilding the AMI.
                  CRED_SECRETS=$(${pkgs.awscli2}/bin/aws secretsmanager list-secrets \
                    --filters Key=name,Values=forgecache/creds/ \
                    --query 'SecretList[].Name' --output text)
                  for SECRET_NAME in $CRED_SECRETS; do
                    SECRET_VALUE=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$SECRET_NAME" --query 'SecretString' --output text)
                    KEY_DESC="''${SECRET_NAME//\//-}"
                    echo -n "$SECRET_VALUE" | keyctl padd user "$KEY_DESC" @s >/dev/null || true
                  done

                  # ── Load fixed secrets into keyring ───────────────────────────────
                  for SECRET_NAME in \
                    forgecache/forge-admin-token \
                    forgecache/keydb-auth-token \
                    forgecache/webhook-secret; do
                    SECRET_VALUE=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$SECRET_NAME" --query 'SecretString' --output text) || true
                    if [ -n "''${SECRET_VALUE}" ]; then
                      KEY_DESC="''${SECRET_NAME//\//-}"
                      echo -n "$SECRET_VALUE" | keyctl padd user "$KEY_DESC" @s >/dev/null || true
                    fi
                  done
                '';

                awsNginxProvider = pkgs.writeShellScript "forgecache-nginx-provider" ''
                                  set -euo pipefail
                                  UPSTREAM=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                                    --secret-id forgecache/nginx-upstream-hostname \
                                    --query 'SecretString' --output text)
                                  UPSTREAM_PORT=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                                    --secret-id forgecache/nginx-upstream-port \
                                    --query 'SecretString' --output text)

                                  mkdir -p /etc/ssl/forgecache /etc/nginx/conf.d

                                  # TLS material for nginx
                                  ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                                    --secret-id forgecache/nginx-tls-cert --query 'SecretString' --output text \
                                    > /etc/ssl/forgecache/cert.pem
                                  ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                                    --secret-id forgecache/nginx-tls-key --query 'SecretString' --output text \
                                    > /etc/ssl/forgecache/key.pem
                                  chmod 640 /etc/ssl/forgecache/key.pem
                                  chown root:nginx /etc/ssl/forgecache/key.pem

                                  # Upstream block (http-level include)
                                  cat > /etc/nginx/conf.d/forgecache-upstream.conf <<EOF
                  upstream forge-upstream {
                    server $UPSTREAM:$UPSTREAM_PORT;
                    keepalive 32;
                  }
                  EOF

                                  # Server-level variable (server-level include)
                                  cat > /etc/nginx/conf.d/forgecache-server.conf <<EOF
                  set \$forge_upstream_host "$UPSTREAM";
                  EOF
                '';
              in
              {
                services.forgecache-secrets = lib.mkDefault {
                  enable = true;
                  providerScript = awsForgeProxyProvider;
                };

                services.forgecache-nginx-runtime = lib.mkDefault {
                  enable = true;
                  providerScript = awsNginxProvider;
                };
              }
            )
          ];
        };

        nixosConfigurations.keydb = inputs.nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            { nixpkgs.overlays = [ self.overlays.default ]; }
            inputs.sops-nix.nixosModules.sops
            self.nixosModules.keydb-host
            self.nixosModules.ami

            # ── AWS provider configuration ──────────────────────────────────────
            (
              {
                config,
                pkgs,
                lib,
                ...
              }:
              let
                awsKeydbProvider = pkgs.writeShellScript "keydb-aws-provider" ''
                  set -euo pipefail
                  fetch() {
                    ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$1" --query 'SecretString' --output text
                  }
                  # Write TLS material to paths configured in services.keydb.tls.{certFile,keyFile,caFile}
                  # (defaults: /var/lib/keydb/tls/{cert,key,ca}.pem — writable under ProtectSystem=strict)
                  mkdir -p /var/lib/keydb/tls
                  fetch forgecache/keydb-tls-cert > /var/lib/keydb/tls/cert.pem
                  fetch forgecache/keydb-tls-key  > /var/lib/keydb/tls/key.pem
                  fetch forgecache/keydb-tls-ca   > /var/lib/keydb/tls/ca.pem
                  chmod 600 /var/lib/keydb/tls/key.pem
                  chown -R keydb:keydb /var/lib/keydb/tls

                  # Write runtime conf (second keydb-server arg, overrides requirepass from main conf)
                  # Path matches services.keydb.extraConfFile (default: /run/keydb/runtime.conf)
                  printf 'requirepass %s\n' "$(fetch forgecache/keydb-auth-token)" \
                    > /run/keydb/runtime.conf
                  chmod 600 /run/keydb/runtime.conf
                '';
              in
              {
                services.keydb.tls.enable = lib.mkDefault false;

                services.keydb-secrets = lib.mkDefault {
                  enable = false;
                  providerScript = awsKeydbProvider;
                };
              }
            )
          ];
        };
      };
    };
}
