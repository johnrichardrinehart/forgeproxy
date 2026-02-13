{
  pkgs,
  lib,
}:

let
  motoServer = pkgs.python3.withPackages (ps: [ ps.moto ] ++ ps.moto.optional-dependencies.server);

  # ── Provider script: fetch from AWS Secrets Manager → keyring ─────────────
  awsProvider = pkgs.writeShellScript "aws-keyring-provider" ''
    set -euo pipefail
    for SECRET_NAME in $SECRETS; do
      SECRET_VALUE=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
        --secret-id "$SECRET_NAME" \
        --query 'SecretString' --output text)
      KEY_DESC="''${SECRET_NAME//\//-}"
      echo -n "$SECRET_VALUE" | keyctl padd user "$KEY_DESC" @s >/dev/null
    done
  '';

  # Dummy AWS credentials for moto (it accepts anything)
  dummyCreds = {
    AWS_ACCESS_KEY_ID = "testing";
    AWS_SECRET_ACCESS_KEY = "testing";
    AWS_DEFAULT_REGION = "us-east-1";
  };
in
pkgs.testers.runNixOSTest {
  name = "forgecache-secrets-aws";
  globalTimeout = 300;

  nodes = {
    # ── Mock AWS Secrets Manager (moto) ───────────────────────────────────
    mock-aws =
      { config, pkgs, ... }:
      {
        systemd.services.moto = {
          description = "Moto AWS mock server";
          after = [ "network.target" ];
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            ExecStart = "${motoServer}/bin/moto_server -H 0.0.0.0 -p 5000";
            Restart = "on-failure";
          };
        };

        networking.firewall.allowedTCPPorts = [ 5000 ];
      };

    # ── Proxy node ────────────────────────────────────────────────────────
    proxy =
      { config, pkgs, ... }:
      {
        # ── Wait for mock-aws:5000 to be reachable ────────────────────────
        systemd.services.wait-for-moto = {
          description = "Wait for moto mock AWS endpoint";
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = pkgs.writeShellScript "wait-for-moto" ''
              set -euo pipefail
              until ${pkgs.curl}/bin/curl -sf http://mock-aws:5000/moto-api/ >/dev/null 2>&1; do
                sleep 1
              done
            '';
          };
        };

        # ── Seed test secrets into moto ───────────────────────────────────
        systemd.services.seed-moto-secrets = {
          description = "Seed test secrets into moto Secrets Manager";
          after = [ "wait-for-moto.service" ];
          requires = [ "wait-for-moto.service" ];
          wantedBy = [ "multi-user.target" ];
          environment = dummyCreds // {
            AWS_ENDPOINT_URL = "http://mock-aws:5000";
          };
          path = [ pkgs.awscli2 ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = pkgs.writeShellScript "seed-moto-secrets" ''
              set -euo pipefail
              aws secretsmanager create-secret \
                --name forgecache/default-pat \
                --secret-string "ghp_AWSTEST1234567890abcdef"
              aws secretsmanager create-secret \
                --name forgecache/webhook-secret \
                --secret-string "whsec_awstest456"
            '';
          };
        };

        environment.systemPackages = with pkgs; [
          keyutils
          awscli2
        ];
      };
  };

  testScript = ''
    start_all()

    with subtest("moto server starts"):
        mock_aws.wait_for_unit("moto.service")
        mock_aws.wait_for_open_port(5000)

    with subtest("test secrets are seeded"):
        proxy.wait_for_unit("seed-moto-secrets.service")

    with subtest("provider loads secrets into keyring"):
        proxy.succeed(
            "export AWS_ACCESS_KEY_ID=testing"
            " AWS_SECRET_ACCESS_KEY=testing"
            " AWS_DEFAULT_REGION=us-east-1"
            " AWS_ENDPOINT_URL=http://mock-aws:5000"
            " SECRETS='forgecache/default-pat forgecache/webhook-secret'"
            " && ${awsProvider}"
        )

    with subtest("default-pat secret is in the keyring"):
        key_id = proxy.succeed("keyctl search @s user forgecache-default-pat").strip()
        assert key_id, "keyctl search returned empty key ID"
        value = proxy.succeed(f"keyctl pipe {key_id}").strip()
        assert value == "ghp_AWSTEST1234567890abcdef", f"unexpected value: {value}"

    with subtest("webhook-secret is in the keyring"):
        key_id = proxy.succeed("keyctl search @s user forgecache-webhook-secret").strip()
        assert key_id, "keyctl search returned empty key ID"
        value = proxy.succeed(f"keyctl pipe {key_id}").strip()
        assert value == "whsec_awstest456", f"unexpected value: {value}"
  '';
}
