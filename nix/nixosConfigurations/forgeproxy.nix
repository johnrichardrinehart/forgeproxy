{ self, ... }:

self.nixosConfigurations.forgeproxy-hardened.extendModules {
  modules = [
    self.nixosModules.dev
    self.nixosModules.dev-tools
    (
      { pkgs, ... }:
      {
        services.forgeproxy.package = pkgs.forgeproxy-dev;
        services.forgeproxy.allowEnvSecretFallback = true;
        environment.systemPackages = [ pkgs.forgeproxy-dev ];
      }
    )
  ];
}
