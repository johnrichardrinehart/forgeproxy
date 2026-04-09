{ gitRevision }:

final: prev: import ../packages/catalog.nix { inherit final prev gitRevision; }
