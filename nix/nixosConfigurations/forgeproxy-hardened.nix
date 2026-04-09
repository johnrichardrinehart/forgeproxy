{ self, inputs }:

inputs.nixpkgs.lib.nixosSystem {
  system = "x86_64-linux";
  modules = [
    { nixpkgs.overlays = [ self.overlays.default ]; }
    inputs.sops-nix.nixosModules.sops
    self.nixosModules.proxy-host
    self.nixosModules.ami
    ./aws/forgeproxy-secrets.nix
  ];
}
