{ self, inputs }:

{
  forgeproxy-hardened = import ./forgeproxy-hardened.nix { inherit self inputs; };
  forgeproxy = import ./forgeproxy.nix { inherit self inputs; };
  valkey-hardened = import ./valkey-hardened.nix { inherit self inputs; };
  valkey = import ./valkey.nix { inherit self inputs; };
  ghe-key-lookup-hardened = import ./ghe-key-lookup-hardened.nix { inherit self inputs; };
  ghe-key-lookup = import ./ghe-key-lookup.nix { inherit self inputs; };
}
