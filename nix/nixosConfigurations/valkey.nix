{
  self,
  inputs,
  system ? "x86_64-linux",
}:

(import ./valkey-hardened.nix { inherit self inputs system; }).extendModules {
  modules = [
    self.nixosModules.dev
    self.nixosModules.dev-tools
  ];
}
