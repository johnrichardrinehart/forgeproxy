{
  final,
  prev,
  gitRevision,
}:

let
  jemallocPatches = import ./jemalloc/patches;
  valkeyPatches = import ./valkey/patches;
in
rec {
  jemalloc-valkey-rtree-fix = import ./jemalloc {
    inherit prev;
    patches = jemallocPatches;
  };

  valkey-stock-jemalloc = prev.valkey;
  valkey = import ./valkey {
    inherit prev;
    patches = valkeyPatches;
  };
  valkey-jemalloc-dev = import ./valkey {
    inherit prev;
    patches = valkeyPatches;
  };

  forgeproxy = final.callPackage ./forgeproxy { inherit gitRevision; };
  forgeproxy-dev = final.callPackage ./forgeproxy {
    inherit gitRevision;
    devEnabled = true;
  };
  forgeproxy-fips = final.callPackage ./forgeproxy {
    inherit gitRevision;
    fipsEnabled = true;
  };

  ghe-key-lookup = final.callPackage ./ghe-key-lookup { };
  ghe-key-lookup-oci = final.callPackage ./ghe-key-lookup/oci.nix { };
  forgeproxy-cache-report = final.callPackage ./forgeproxy-cache-report { };
  forgeproxy-rollout-prepare = final.callPackage ./rollout-script {
    scriptName = "forgeproxy-rollout-prepare";
    scriptPath = ../../terraform/scripts/forgeproxy-rollout-prepare.sh;
  };
  forgeproxy-rollout-cleanup = final.callPackage ./rollout-script {
    scriptName = "forgeproxy-rollout-cleanup";
    scriptPath = ../../terraform/scripts/forgeproxy-rollout-cleanup.sh;
  };

  valkey-stock-jemalloc-no-tests = valkey-stock-jemalloc.overrideAttrs (_: {
    doCheck = false;
    doInstallCheck = false;
  });

  valkey-jemalloc-dev-no-tests = valkey-jemalloc-dev.overrideAttrs (_: {
    doCheck = false;
    doInstallCheck = false;
  });

  valkey-no-tests = valkey.overrideAttrs (_: {
    doCheck = false;
    doInstallCheck = false;
  });
}
