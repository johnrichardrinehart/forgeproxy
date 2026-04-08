{ lib }:

import ../cache-layout.nix {
  inherit lib;
  root = "/var/cache/forgeproxy";
}
