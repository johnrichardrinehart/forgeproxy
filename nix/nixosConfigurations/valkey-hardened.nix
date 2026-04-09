{ self, inputs }:

inputs.nixpkgs.lib.nixosSystem {
  system = "x86_64-linux";
  modules = [
    { nixpkgs.overlays = [ self.overlays.default ]; }
    inputs.sops-nix.nixosModules.sops
    self.nixosModules.valkey-host
    self.nixosModules.ami
    ./aws/valkey-secrets.nix
  ];
}
