{ config, lib, pkgs, ... }:

let
  cfg = config.gheproxy.secrets;
in
{
  options.gheproxy.secrets = {
    enable = lib.mkEnableOption "sops-nix based secrets management for gheproxy";

    sopsFile = lib.mkOption {
      type = lib.types.path;
      default = ../secrets/secrets.yaml;
      description = "Path to the sops-encrypted secrets YAML file.";
    };

    ageKeyFile = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/sops-nix/age-key.txt";
      description = "Path to the age private key used to decrypt sops secrets.";
    };

    owner = lib.mkOption {
      type = lib.types.str;
      default = "gheproxy";
      description = "System user that owns the decrypted secret files.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "gheproxy";
      description = "System group that owns the decrypted secret files.";
    };
  };

  config = lib.mkIf cfg.enable {
    # ── sops-nix global defaults ───────────────────────────────────────
    sops.defaultSopsFile = cfg.sopsFile;
    sops.age.keyFile = cfg.ageKeyFile;

    # ── Individual secrets ─────────────────────────────────────────────

    # KeyDB authentication token used by the gheproxy service to connect
    # to the KeyDB cluster over TLS.
    sops.secrets."keydb-auth-token" = {
      owner = cfg.owner;
      group = cfg.group;
      mode = "0400";
      restartUnits = [ "gheproxy.service" ];
    };

    # GitHub Enterprise admin / API token used by the proxy for upstream
    # API calls (e.g., repository listing, webhook verification).
    sops.secrets."ghe-admin-token" = {
      owner = cfg.owner;
      group = cfg.group;
      mode = "0400";
      restartUnits = [ "gheproxy.service" ];
    };

    # Webhook secret used to verify incoming GitHub webhook payloads.
    sops.secrets."webhook-secret" = {
      owner = cfg.owner;
      group = cfg.group;
      mode = "0400";
      restartUnits = [ "gheproxy.service" ];
    };

    # TLS private key for the gheproxy HTTPS / SSH endpoints.
    sops.secrets."tls-private-key" = {
      owner = cfg.owner;
      group = cfg.group;
      mode = "0400";
      path = "/etc/ssl/gheproxy/key.pem";
    };
  };
}
