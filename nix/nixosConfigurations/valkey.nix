{ self, ... }:

self.nixosConfigurations.valkey-hardened.extendModules {
  modules = [
    self.nixosModules.dev
    self.nixosModules.dev-tools
  ];
}
