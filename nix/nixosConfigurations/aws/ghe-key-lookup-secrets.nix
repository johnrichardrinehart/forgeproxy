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
    _USER_DATA=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/user-data" || true)
    SM_PREFIX=$(printf '%s\n' "$_USER_DATA" | ${pkgs.gnused}/bin/sed -n 's/^# SM_PREFIX=//p' | ${pkgs.coreutils}/bin/head -n1)
    if [ -z "$SM_PREFIX" ]; then
      echo "FATAL: Could not resolve SM_PREFIX from EC2 user_data" >&2
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
      case "$ADMIN_KEY" in
        *$'\n') ;;
        *) printf '\n' >> ${toString config.services.ghe-key-lookup.identityFile} ;;
      esac
      chmod 600 ${toString config.services.ghe-key-lookup.identityFile}
    ''}
  '';
in
{
  services.ghe-key-lookup = {
    sshTargetEndpoint = lib.mkDefault "ghe.internal.example.com";
    configPath = lib.mkDefault "/run/ghe-key-lookup/config.toml";
    openFirewall = lib.mkDefault true;
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
