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
                    terraform = {
                      enable = true;
                      package = pkgs.terraform;
                    };
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

                  terraform-validate = {
                    enable = true;
                    entry = toString (
                      pkgs.writeShellScript "terraform-validate-hook" ''
                        for arg in "$@"; do
                          dirname "$arg"
                        done | sort | uniq | while read dir; do
                          ${pkgs.terraform}/bin/terraform -chdir="$dir" init
                          ${pkgs.terraform}/bin/terraform -chdir="$dir" validate
                        done
                      ''
                    );
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
            forgeproxy = pkgs.callPackage ./nix/package.nix { };
            forgeproxy-fips = pkgs.callPackage ./nix/package.nix { fipsEnabled = true; };
            default = config.packages.forgeproxy;
          };
        };

      # ────────────────────────────────────────────────────────────────────
      # Flake-wide outputs (overlays, modules, configurations)
      # ────────────────────────────────────────────────────────────────────
      flake = {
        overlays.default = final: prev: {
          forgeproxy = final.callPackage ./nix/package.nix { };
          forgeproxy-fips = final.callPackage ./nix/package.nix { fipsEnabled = true; };
        };

        nixosModules = {
          forgeproxy = ./nix/module.nix;
          keydb = ./nix/keydb.nix;
          keydb-tls = ./nix/keydb-tls.nix;
          nginx = ./nix/nginx.nix;
          hardening = ./nix/hardening.nix;
          secrets = ./nix/secrets.nix;
          ami = ./nix/ami.nix;
          backend = ./nix/backend.nix;
          compliance = ./nix/compliance/default.nix;
          proxy-host = ./nix/proxy-host.nix;
          keydb-host = ./nix/keydb-host.nix;
          dev = ./nix/dev.nix;
        };

        nixosConfigurations.forgeproxy = inputs.nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            { nixpkgs.overlays = [ self.overlays.default ]; }
            inputs.sops-nix.nixosModules.sops
            self.nixosModules.proxy-host
            self.nixosModules.ami
            # FedRAMP compliance is opt-in:
            # { services.forgeproxy.compliance.fedramp.enable = true; }

            # ── AWS provider configuration ──────────────────────────────────────
            (
              {
                config,
                pkgs,
                lib,
                ...
              }:
              let
                awsForgeProxyProvider = pkgs.writeShellScript "forgeproxy-aws-provider" ''
                  set -euo pipefail

                  # ── Read SM_PREFIX from EC2 user_data (required, set by Terraform) ──
                  _IMDS_TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
                  SM_PREFIX=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/user-data")
                  if [ -z "$SM_PREFIX" ]; then
                    echo "FATAL: EC2 user_data is empty; SM_PREFIX must be set via user_data" >&2
                    exit 1
                  fi

                  # ── Resolve secret names under SM_PREFIX (handles name_prefix random suffix) ──
                  ALL_SECRETS=$(${pkgs.awscli2}/bin/aws secretsmanager list-secrets \
                    --filters "Key=name,Values=''${SM_PREFIX}/" \
                    --query 'SecretList[].Name' --output json)

                  resolve() {
                    echo "$ALL_SECRETS" | ${pkgs.jq}/bin/jq -r --arg p "''${SM_PREFIX}/$1" \
                      '[.[] | select(startswith($p))][0]'
                  }

                  # ── Write config.yaml from Secrets Manager ────────────────────────
                  # /run/forgeproxy is writable via RuntimeDirectory=forgeproxy;
                  # /etc is read-only under ProtectSystem=strict.
                  ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                    --secret-id "$(resolve service-config)" \
                    --query 'SecretString' --output text > /run/forgeproxy/config.yaml

                  # ── Write KeyDB CA cert (for TLS verification) ─────────────────────
                  KEYDB_CA_SECRET=$(resolve keydb-tls-ca)
                  if [ "$KEYDB_CA_SECRET" != "null" ]; then
                    ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$KEYDB_CA_SECRET" \
                      --query 'SecretString' --output text > /run/forgeproxy/keydb-ca.pem
                  fi

                  # ── Load per-org credentials into the kernel keyring ──────────────
                  # Discovers all secrets under ''${SM_PREFIX}/creds-<org> dynamically —
                  # no hardcoded org list.  Adding an org requires creating a new SM
                  # secret, not rebuilding the AMI.
                  CRED_SECRETS=$(echo "$ALL_SECRETS" | ${pkgs.jq}/bin/jq -r \
                    --arg p "''${SM_PREFIX}/creds-" '.[] | select(startswith($p))')
                  for SECRET_NAME in $CRED_SECRETS; do
                    SECRET_VALUE=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$SECRET_NAME" --query 'SecretString' --output text)
                    # Extract org name: strip SM_PREFIX/creds- prefix and Terraform's
                    # random suffix (26-char unique ID starting with a digit).
                    REMAINDER="''${SECRET_NAME#''${SM_PREFIX}/creds-}"
                    ORG_NAME="''${REMAINDER%-[0-9]*}"
                    KEY_DESC="''${SM_PREFIX//\//-}-creds-''${ORG_NAME}"
                    echo -n "$SECRET_VALUE" | keyctl padd user "$KEY_DESC" @u >/dev/null || true
                  done

                  # ── Load fixed secrets into keyring ───────────────────────────────
                  # Stored under their env-var names so the Rust binary can look them
                  # up from the user keyring (same pattern as org credentials).
                  declare -A SUFFIX_TO_ENV=(
                    [forge-admin-token]=FORGE_ADMIN_TOKEN
                    [keydb-auth-token]=KEYDB_AUTH_TOKEN
                    [webhook-secret]=FORGE_WEBHOOK_SECRET
                  )

                  for SUFFIX in "''${!SUFFIX_TO_ENV[@]}"; do
                    SECRET_NAME=$(resolve "$SUFFIX")
                    SECRET_VALUE=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$SECRET_NAME" --query 'SecretString' --output text) || true
                    if [ -n "''${SECRET_VALUE}" ]; then
                      echo -n "$SECRET_VALUE" | keyctl padd user "''${SUFFIX_TO_ENV[$SUFFIX]}" @u >/dev/null || true
                    fi
                  done
                '';

                awsNginxProvider = pkgs.writeShellScript "forgeproxy-nginx-provider" ''
                                  set -euo pipefail

                                  # ── Read SM_PREFIX from EC2 user_data (required, set by Terraform) ──
                                  _IMDS_TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
                                  SM_PREFIX=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/user-data")
                                  if [ -z "$SM_PREFIX" ]; then
                                    echo "FATAL: EC2 user_data is empty; SM_PREFIX must be set via user_data" >&2
                                    exit 1
                                  fi

                                  # ── Resolve secret names under SM_PREFIX (handles name_prefix random suffix) ──
                                  ALL_SECRETS=$(${pkgs.awscli2}/bin/aws secretsmanager list-secrets \
                                    --filters "Key=name,Values=''${SM_PREFIX}/" \
                                    --query 'SecretList[].Name' --output json)

                                  resolve() {
                                    echo "$ALL_SECRETS" | ${pkgs.jq}/bin/jq -r --arg p "''${SM_PREFIX}/$1" \
                                      '[.[] | select(startswith($p))][0]'
                                  }

                                  UPSTREAM=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                                    --secret-id "$(resolve nginx-upstream-hostname)" \
                                    --query 'SecretString' --output text)
                                  UPSTREAM_PORT=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                                    --secret-id "$(resolve nginx-upstream-port)" \
                                    --query 'SecretString' --output text)

                                  mkdir -p /run/nginx/ssl

                                  # TLS material for nginx
                                  ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                                    --secret-id "$(resolve nginx-tls-cert)" --query 'SecretString' --output text \
                                    > /run/nginx/ssl/cert.pem
                                  ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                                    --secret-id "$(resolve nginx-tls-key)" --query 'SecretString' --output text \
                                    > /run/nginx/ssl/key.pem
                                  chmod 600 /run/nginx/ssl/key.pem

                                  # Upstream block (http-level include)
                                  cat > /run/nginx/forgeproxy-upstream.conf <<EOF
                  upstream forge-upstream {
                    server $UPSTREAM:$UPSTREAM_PORT;
                    keepalive 32;
                  }
                  EOF

                                  # Server-level variable (server-level include)
                                  cat > /run/nginx/forgeproxy-server.conf <<EOF
                  set \$forge_upstream_host "$UPSTREAM";
                  EOF
                '';
              in
              {
                services.forgeproxy-secrets = lib.mkDefault {
                  enable = true;
                  providerScript = awsForgeProxyProvider;
                };

                services.forgeproxy-nginx-runtime = lib.mkDefault {
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
                awsKeydbAuthProvider = pkgs.writeShellScript "keydb-aws-auth-provider" ''
                  set -euo pipefail

                  # ── Read SM_PREFIX from EC2 user_data (required, set by Terraform) ──
                  _IMDS_TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
                  SM_PREFIX=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/user-data")
                  if [ -z "$SM_PREFIX" ]; then
                    echo "FATAL: EC2 user_data is empty; SM_PREFIX must be set via user_data" >&2
                    exit 1
                  fi

                  # ── Resolve secret names under SM_PREFIX (handles name_prefix random suffix) ──
                  ALL_SECRETS=$(${pkgs.awscli2}/bin/aws secretsmanager list-secrets \
                    --filters "Key=name,Values=''${SM_PREFIX}/" \
                    --query 'SecretList[].Name' --output json)

                  resolve() {
                    echo "$ALL_SECRETS" | ${pkgs.jq}/bin/jq -r --arg p "''${SM_PREFIX}/$1" \
                      '[.[] | select(startswith($p))][0]'
                  }

                  fetch() {
                    ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$(resolve "$1")" --query 'SecretString' --output text
                  }

                  # Write runtime conf (second keydb-server arg, overrides requirepass from main conf)
                  # Path matches services.keydb.extraConfFile (default: /run/keydb/runtime.conf)
                  printf 'requirepass %s\n' "$(fetch keydb-auth-token)" \
                    > /run/keydb/runtime.conf
                  chmod 600 /run/keydb/runtime.conf
                '';

                awsKeydbTlsProvider = pkgs.writeShellScript "keydb-aws-tls-provider" ''
                  set -euo pipefail

                  # ── Read SM_PREFIX from EC2 user_data (required, set by Terraform) ──
                  _IMDS_TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
                  SM_PREFIX=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/user-data")
                  if [ -z "$SM_PREFIX" ]; then
                    echo "FATAL: EC2 user_data is empty; SM_PREFIX must be set via user_data" >&2
                    exit 1
                  fi

                  # ── Resolve secret names under SM_PREFIX (handles name_prefix random suffix) ──
                  ALL_SECRETS=$(${pkgs.awscli2}/bin/aws secretsmanager list-secrets \
                    --filters "Key=name,Values=''${SM_PREFIX}/" \
                    --query 'SecretList[].Name' --output json)

                  resolve() {
                    echo "$ALL_SECRETS" | ${pkgs.jq}/bin/jq -r --arg p "''${SM_PREFIX}/$1" \
                      '[.[] | select(startswith($p))][0]'
                  }

                  fetch() {
                    ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$(resolve "$1")" --query 'SecretString' --output text
                  }

                  # Write TLS material to paths configured in services.keydb.tls.{certFile,keyFile,caFile}
                  # (defaults: /var/lib/keydb/tls/{cert,key,ca}.pem — writable under ProtectSystem=strict)
                  mkdir -p /var/lib/keydb/tls
                  fetch keydb-tls-cert > /var/lib/keydb/tls/cert.pem
                  fetch keydb-tls-key  > /var/lib/keydb/tls/key.pem
                  fetch keydb-tls-ca   > /var/lib/keydb/tls/ca.pem
                  chmod 600 /var/lib/keydb/tls/key.pem
                '';
              in
              {
                services.keydb.tls.enable = lib.mkDefault true;

                services.keydb-secrets = lib.mkDefault {
                  enable = true;
                  providerScript = awsKeydbAuthProvider;
                };

                services.keydb-tls = {
                  enable = lib.mkDefault config.services.keydb.tls.enable;
                  providerScript = awsKeydbTlsProvider;
                };
              }
            )
          ];
        };

        nixosConfigurations.forgeproxy-dev = self.nixosConfigurations.forgeproxy.extendModules {
          modules = [ self.nixosModules.dev ];
        };

        nixosConfigurations.keydb-dev = self.nixosConfigurations.keydb.extendModules {
          modules = [ self.nixosModules.dev ];
        };
      };
    };
}
