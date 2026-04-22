{
  self,
  inputs,
  system ? "x86_64-linux",
}:

inputs.nixpkgs.lib.nixosSystem {
  inherit system;
  modules = [
    { nixpkgs.overlays = [ self.overlays.default ]; }
    self.nixosModules.ghe-key-lookup-host
    ./aws/ghe-key-lookup-secrets.nix
  ];
}
