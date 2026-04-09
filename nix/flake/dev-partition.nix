{ inputs, self, ... }:

{
  imports = [
    inputs.git-hooks.flakeModule
    inputs.treefmt-nix.flakeModule
  ];

  perSystem =
    {
      config,
      pkgs,
      ...
    }:
    {
      checks = import ../checks {
        inherit pkgs self inputs;
      };

      # ── Formatting (consumed by git-hooks via treefmt hook) ──
      treefmt = {
        projectRootFile = "flake.nix";
        programs = {
          nixfmt.enable = true;
          rustfmt = {
            enable = true;
            edition = (builtins.fromTOML (builtins.readFile ../../rust/Cargo.toml)).package.edition;
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
}
