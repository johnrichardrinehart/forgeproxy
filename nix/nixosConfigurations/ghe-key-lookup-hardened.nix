{ self, inputs }:

inputs.nixpkgs.lib.nixosSystem {
  system = "x86_64-linux";
  modules = [
    { nixpkgs.overlays = [ self.overlays.default ]; }
    self.nixosModules.ghe-key-lookup-host
    ./aws/ghe-key-lookup-secrets.nix
  ];
}
