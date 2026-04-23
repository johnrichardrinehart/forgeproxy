{
  pkgs,
  config ? null,
}:

{
  inherit (pkgs)
    forgeproxy
    forgeproxy-dev
    forgeproxy-fips
    valkey-stock-jemalloc
    valkey-stock-jemalloc-no-tests
    valkey-jemalloc-dev
    valkey-jemalloc-dev-no-tests
    valkey-no-tests
    ghe-key-lookup
    ghe-key-lookup-oci
    forgeproxy-cache-report
    forgeproxy-rollout-prepare
    forgeproxy-rollout-cleanup
    ;
}
// {
  # When imported from flake-parts `perSystem.packages`, prefer
  # `config.packages.forgeproxy` so `packages.default` stays tied to the
  # perSystem package set. The `config == null` branch is a fallback for
  # direct non-flake-parts imports of this file.
  default = if config == null then pkgs.forgeproxy else config.packages.forgeproxy;
}
