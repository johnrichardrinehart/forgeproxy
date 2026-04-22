{
  self,
  inputs,
  system ? "x86_64-linux",
}:

inputs.nixpkgs.lib.nixosSystem {
  inherit system;
  modules = [
    { nixpkgs.overlays = [ self.overlays.default ]; }
    inputs.sops-nix.nixosModules.sops
    self.nixosModules.proxy-host
    self.nixosModules.ami
    ./aws/forgeproxy-secrets.nix
  ];
}
