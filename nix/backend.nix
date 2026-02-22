{
  config,
  lib,
  ...
}:

let
  cfg = config.services.forgeproxy.backend;

  # Per-backend derived values consumed by nginx.nix and the Rust binary.
  derivedValues = {
    "github-enterprise" = {
      apiPathPrefix = "/api/v3";
      webhookEventHeader = "X-GitHub-Event";
      webhookSignatureHeader = "X-Hub-Signature-256";
      acceptHeader = "application/vnd.github.v3+json";
    };
    "github" = {
      apiPathPrefix = "/api/v3";
      webhookEventHeader = "X-GitHub-Event";
      webhookSignatureHeader = "X-Hub-Signature-256";
      acceptHeader = "application/vnd.github.v3+json";
    };
    "gitlab" = {
      apiPathPrefix = "/api/v4";
      webhookEventHeader = "X-Gitlab-Event";
      webhookSignatureHeader = "X-Gitlab-Token";
      acceptHeader = "application/json";
    };
    "gitea" = {
      apiPathPrefix = "/api/v1";
      webhookEventHeader = "X-Gitea-Event";
      webhookSignatureHeader = "X-Gitea-Signature";
      acceptHeader = "application/json";
    };
    "forgejo" = {
      apiPathPrefix = "/api/v1";
      webhookEventHeader = "X-Forgejo-Event";
      webhookSignatureHeader = "X-Forgejo-Signature";
      acceptHeader = "application/json";
    };
  };
in
{
  options.services.forgeproxy.backend = {
    type = lib.mkOption {
      type = lib.types.enum [
        "github-enterprise"
        "github"
        "gitlab"
        "gitea"
        "forgejo"
      ];
      default = "github-enterprise";
      description = ''
        The type of upstream Git forge backend.

        This controls webhook header normalization in nginx, the API path
        prefix used for pass-through requests, and the Accept header the
        Rust proxy sends to upstream API calls.
      '';
    };

    _derived = lib.mkOption {
      type = lib.types.attrs;
      readOnly = true;
      internal = true;
      default = derivedValues.${cfg.type};
      description = "Derived per-backend values (internal, read-only).";
    };
  };
}
