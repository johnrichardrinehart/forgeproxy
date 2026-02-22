{
  sops-nix,
  pkgs,
  lib,
}:

let
  # ── Generate age keypair + encrypt secrets in one derivation (no IFD) ─────
  testSecretsData =
    pkgs.runCommand "test-secrets-data"
      {
        nativeBuildInputs = [
          pkgs.age
          pkgs.sops
        ];
      }
      ''
        mkdir -p $out

        # Generate age keypair
        age-keygen -o $out/key.txt 2>/dev/null
        AGE_PUB=$(age-keygen -y $out/key.txt)

        # Plaintext secrets
        cat > plain.yaml <<'YAML'
        default-pat: ghp_TESTSECRET1234567890abcdef
        webhook-secret: whsec_testabc123
        YAML

        # Encrypt with sops
        sops --encrypt --age "$AGE_PUB" \
          --input-type yaml --output-type yaml \
          plain.yaml > $out/secrets.yaml
      '';

  # ── Provider script: read sops-decrypted files → keyring ──────────────────
  sopsProvider = pkgs.writeShellScript "sops-keyring-provider" ''
    set -euo pipefail
    for secret_file in /run/secrets/*; do
      [ -f "$secret_file" ] || continue
      key_name="''${secret_file##*/}"
      keyctl padd user "$key_name" @u < "$secret_file" >/dev/null
    done
  '';
in
pkgs.testers.runNixOSTest {
  name = "forgeproxy-secrets-sops";
  globalTimeout = 300;

  nodes.proxy =
    { config, pkgs, ... }:
    {
      imports = [ sops-nix.nixosModules.sops ];

      # ── sops-nix configuration ──────────────────────────────────────────
      # sops-nix's types.path check does `/. + string` internally, which
      # Nix rejects for strings referencing store paths.  Place the
      # encrypted file via environment.etc so we can hand sops-nix a
      # plain filesystem path that passes the type check.
      environment.etc."test-sops/secrets.yaml".source = "${testSecretsData}/secrets.yaml";
      environment.etc."test-sops/key.txt".source = "${testSecretsData}/key.txt";

      sops.defaultSopsFile = "/etc/test-sops/secrets.yaml";
      sops.age.keyFile = "/etc/test-sops/key.txt";
      sops.validateSopsFiles = false;

      sops.secrets."default-pat" = { };
      sops.secrets."webhook-secret" = { };

      environment.systemPackages = [ pkgs.keyutils ];
    };

  testScript = ''
    start_all()

    with subtest("sops-nix decrypts secrets"):
        # sops-nix uses an activation script (not a systemd service) by
        # default, so secrets are already in /run/secrets/ after boot.
        proxy.wait_for_unit("multi-user.target")
        proxy.succeed("test -f /run/secrets/default-pat")
        proxy.succeed("test -f /run/secrets/webhook-secret")

    with subtest("provider loads secrets into keyring"):
        proxy.succeed("${sopsProvider}")
        # Link the user keyring into the session keyring so the test
        # process "possesses" the keys (mirrors KeyringMode=shared).
        proxy.succeed("keyctl link @u @s")

    with subtest("default-pat secret is in the keyring"):
        key_id = proxy.succeed("keyctl search @u user default-pat").strip()
        assert key_id, "keyctl search returned empty key ID"
        value = proxy.succeed(f"keyctl pipe {key_id}").strip()
        assert value == "ghp_TESTSECRET1234567890abcdef", f"unexpected value: {value}"

    with subtest("webhook-secret is in the keyring"):
        key_id = proxy.succeed("keyctl search @u user webhook-secret").strip()
        assert key_id, "keyctl search returned empty key ID"
        value = proxy.succeed(f"keyctl pipe {key_id}").strip()
        assert value == "whsec_testabc123", f"unexpected value: {value}"
  '';
}
