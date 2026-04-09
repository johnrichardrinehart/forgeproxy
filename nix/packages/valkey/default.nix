{ prev, patches }:

(prev.valkey.override {
  useSystemJemalloc = false;
}).overrideAttrs
  (old: {
    makeFlags = (old.makeFlags or [ ]) ++ [ "MALLOC=libc" ];
    patches = (old.patches or [ ]) ++ patches;
    preCheck = (old.preCheck or "") + ''
      # The libc/Scudo runtime path is materially slower on some builders.
      # Keep the test runner from overcommitting replication-heavy suites.
      export NIX_BUILD_CORES=2
    '';
  })
