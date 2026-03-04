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

          legacyPackages = pkgs;

          packages = {
            forgeproxy = pkgs.callPackage ./nix/package.nix { };
            forgeproxy-fips = pkgs.callPackage ./nix/package.nix { fipsEnabled = true; };
            default = config.packages.forgeproxy;
            ghe-key-lookup = pkgs.callPackage ./nix/ghe-key-lookup/package.nix { };
            ghe-key-lookup-oci = pkgs.callPackage ./nix/ghe-key-lookup/oci.nix { };
          };
        };

      # ────────────────────────────────────────────────────────────────────
      # Flake-wide outputs (overlays, modules, configurations)
      # ────────────────────────────────────────────────────────────────────
      flake = {
        overlays.default = final: prev: {
          forgeproxy = final.callPackage ./nix/package.nix { };
          forgeproxy-fips = final.callPackage ./nix/package.nix { fipsEnabled = true; };
          ghe-key-lookup = final.callPackage ./nix/ghe-key-lookup/package.nix { };
        };

        nixosModules = {
          forgeproxy = ./nix/module.nix;
          valkey = ./nix/valkey.nix;
          valkey-tls = ./nix/valkey-tls.nix;
          nginx = ./nix/nginx.nix;
          hardening = ./nix/hardening.nix;
          secrets = ./nix/secrets.nix;
          ami = ./nix/ami.nix;
          backend = ./nix/backend.nix;
          compliance = ./nix/compliance/default.nix;
          proxy-host = ./nix/proxy-host.nix;
          valkey-host = ./nix/valkey-host.nix;
          dev = ./nix/dev.nix;
          ghe-key-lookup = ./nix/ghe-key-lookup/module.nix;
          ghe-key-lookup-host = ./nix/ghe-key-lookup/host.nix;
        };

        nixosConfigurations.forgeproxy-hardened = inputs.nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            { nixpkgs.overlays = [ self.overlays.default ]; }
            inputs.sops-nix.nixosModules.sops
            self.nixosModules.proxy-host
            self.nixosModules.ami
<<<<<<< HEAD
            # Regulated compliance is opt-in:
            # { services.forgeproxy.compliance.regulated.enable = true; }
=======
            # Regulated compliance is opt-in:
            # { services.forgeproxy.compliance.regulated.enable = true; }
>>>>>>> db70f7a (Rename forgecache to forgeproxy across the entire codebase)

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

                  # ── Write Valkey CA cert (for TLS verification) ─────────────────────
                  VALKEY_CA_SECRET=$(resolve valkey-tls-ca)
                  if [ "$VALKEY_CA_SECRET" != "null" ]; then
                    ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$VALKEY_CA_SECRET" \
                      --query 'SecretString' --output text > /run/forgeproxy/valkey-ca.pem
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
                    [valkey-auth-token]=VALKEY_AUTH_TOKEN
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

        nixosConfigurations.valkey-hardened = inputs.nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            { nixpkgs.overlays = [ self.overlays.default ]; }
            inputs.sops-nix.nixosModules.sops
            self.nixosModules.valkey-host
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
                awsValkeyAuthProvider = pkgs.writeShellScript "valkey-aws-auth-provider" ''
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

                  # Write runtime conf (second valkey-server arg, overrides requirepass from main conf)
                  # Path matches services.valkey.extraConfFile (default: /run/valkey/runtime.conf)
                  printf 'requirepass %s\n' "$(fetch valkey-auth-token)" \
                    > /run/valkey/runtime.conf
                  chmod 600 /run/valkey/runtime.conf
                '';

                awsValkeyTlsProvider = pkgs.writeShellScript "valkey-aws-tls-provider" ''
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

                  # Write TLS material to paths configured in services.valkey.tls.{certFile,keyFile,caFile}
                  # (defaults: /var/lib/valkey/tls/{cert,key,ca}.pem — writable under ProtectSystem=strict)
                  mkdir -p /var/lib/valkey/tls
                  fetch valkey-tls-cert > /var/lib/valkey/tls/cert.pem
                  fetch valkey-tls-key  > /var/lib/valkey/tls/key.pem
                  fetch valkey-tls-ca   > /var/lib/valkey/tls/ca.pem
                  chmod 600 /var/lib/valkey/tls/key.pem
                '';
              in
              {
                services.valkey.tls.enable = lib.mkDefault true;

                services.valkey-secrets = lib.mkDefault {
                  enable = true;
                  providerScript = awsValkeyAuthProvider;
                };

                services.valkey-tls = {
                  enable = lib.mkDefault config.services.valkey.tls.enable;
                  providerScript = awsValkeyTlsProvider;
                };
              }
            )
          ];
        };

        nixosConfigurations.forgeproxy = self.nixosConfigurations.forgeproxy-hardened.extendModules {
          modules = [
            self.nixosModules.dev
            {
              services.forgeproxy.allowEnvSecretFallback = true;
            }
          ];
        };

        nixosConfigurations.valkey = self.nixosConfigurations.valkey-hardened.extendModules {
          modules = [ self.nixosModules.dev ];
        };

        nixosConfigurations.ghe-key-lookup-hardened = inputs.nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            { nixpkgs.overlays = [ self.overlays.default ]; }
            self.nixosModules.ghe-key-lookup-host
            (
              {
                config,
                lib,
                pkgs,
                ...
              }:
              let
                awsGheKeyLookupProvider = pkgs.writeShellScript "ghe-key-lookup-aws-provider" ''
                  set -euo pipefail

                  _IMDS_TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
                  SM_PREFIX=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/user-data")
                  if [ -z "$SM_PREFIX" ]; then
                    echo "FATAL: EC2 user_data is empty; SM_PREFIX must be set via user_data" >&2
                    exit 1
                  fi

                  ALL_SECRETS=$(${pkgs.awscli2}/bin/aws secretsmanager list-secrets \
                    --filters "Key=name,Values=''${SM_PREFIX}/" \
                    --query 'SecretList[].Name' --output json)

                  resolve() {
                    echo "$ALL_SECRETS" | ${pkgs.jq}/bin/jq -r --arg p "''${SM_PREFIX}/$1" \
                      '[.[] | select(startswith($p))][0]'
                  }

                  mkdir -p /run/ghe-key-lookup

                  ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                    --secret-id "$(resolve ghe-key-lookup-config)" \
                    --query 'SecretString' --output text > /run/ghe-key-lookup/config.toml

                  ADMIN_KEY=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                    --secret-id "$(resolve ghe-key-lookup-admin-key)" \
                    --query 'SecretString' --output text)

                  # Load into kernel keyring for the service UID.
                  EXISTING_ID=$(${pkgs.keyutils}/bin/keyctl search @u user "GHE_KEY_LOOKUP_IDENTITY" 2>/dev/null || true)
                  if [ -n "$EXISTING_ID" ]; then
                    printf %s "$ADMIN_KEY" | ${pkgs.keyutils}/bin/keyctl pupdate "$EXISTING_ID"
                  else
                    printf %s "$ADMIN_KEY" | ${pkgs.keyutils}/bin/keyctl padd user "GHE_KEY_LOOKUP_IDENTITY" @u >/dev/null
                  fi
                  ${lib.optionalString (config.services.ghe-key-lookup.identityFile != null) ''
                    printf %s "$ADMIN_KEY" > ${toString config.services.ghe-key-lookup.identityFile}
                    chmod 600 ${toString config.services.ghe-key-lookup.identityFile}
                  ''}
                '';
              in
              {
                services.ghe-key-lookup = {
                  sshTargetEndpoint = lib.mkDefault "ghe.internal.example.com";
                  configPath = lib.mkDefault "/run/ghe-key-lookup/config.toml";
                  openFirewall = lib.mkDefault false;
                  identityKeyringKey = lib.mkDefault "GHE_KEY_LOOKUP_IDENTITY";
                  identityFile = lib.mkDefault null;
                  identityEnvVar = lib.mkDefault null;
                  # gheUrl defaults to https://<sshTargetEndpoint>; set explicitly
                  # only when the HTTPS hostname differs from the SSH endpoint.
                };

                systemd.services.ghe-key-lookup = {
                  preStart = lib.mkBefore "${awsGheKeyLookupProvider}";
                  path = lib.mkAfter [
                    pkgs.awscli2
                    pkgs.curl
                    pkgs.jq
                    pkgs.keyutils
                  ];
                };
              }
            )
          ];
        };

        nixosConfigurations.ghe-key-lookup =
          self.nixosConfigurations.ghe-key-lookup-hardened.extendModules
            {
              modules = [
                self.nixosModules.dev
                (
                  { lib, ... }:
                  {
                    services.openssh.enable = lib.mkDefault true;
                    networking.firewall.allowedTCPPorts = lib.mkAfter [ 22 ];

                    services.ghe-key-lookup = {
                      # Dev fallback chain: keyring -> env -> filesystem path.
                      identityEnvVar = lib.mkOverride 40 "GHE_KEY_LOOKUP_IDENTITY_PEM";
                      identityFile = lib.mkOverride 40 "/run/ghe-key-lookup/admin-key";
                    };
                  }
                )
              ];
            };
      };
    };
}
