{ self, inputs }:

let
  mkConfigs =
    system:
    let
      suffix = "-${system}";
    in
    {
      "forgeproxy-hardened${suffix}" = import ./forgeproxy-hardened.nix { inherit self inputs system; };
      "forgeproxy${suffix}" = import ./forgeproxy.nix { inherit self inputs system; };
      "valkey-hardened${suffix}" = import ./valkey-hardened.nix { inherit self inputs system; };
      "valkey${suffix}" = import ./valkey.nix { inherit self inputs system; };
      "ghe-key-lookup-hardened${suffix}" = import ./ghe-key-lookup-hardened.nix {
        inherit self inputs system;
      };
      "ghe-key-lookup${suffix}" = import ./ghe-key-lookup.nix { inherit self inputs system; };
    };
in
mkConfigs "x86_64-linux" // mkConfigs "aarch64-linux"
