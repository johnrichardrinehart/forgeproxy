{
  self,
  inputs,
  system ? "x86_64-linux",
}:

(import ./forgeproxy-hardened.nix { inherit self inputs system; }).extendModules {
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
