{ prev, patches }:

prev.jemalloc.overrideAttrs (old: {
  patches = (old.patches or [ ]) ++ patches;
})
