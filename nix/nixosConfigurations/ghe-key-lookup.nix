{
  self,
  inputs,
  system ? "x86_64-linux",
}:

(import ./ghe-key-lookup-hardened.nix { inherit self inputs system; }).extendModules {
  modules = [
    self.nixosModules.dev
    self.nixosModules.dev-tools
    (
      { lib, ... }:
      {
        services.openssh.enable = lib.mkDefault true;
        networking.firewall.allowedTCPPorts = lib.mkAfter [ 22 ];

        services.ghe-key-lookup = {
          # Dev fallback chain: keyring -> env -> filesystem path.
          identityEnvVar = lib.mkOverride 40 "GHE_KEY_LOOKUP_IDENTITY_PEM";
          identityFile = lib.mkOverride 40 "/run/ghe-key-lookup/admin-key";
        };
      }
    )
  ];
}
