{
  description = "GHE Caching Reverse Proxy - NixOS AMI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    sops-nix = {
      url = "github:Mic92/sops-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, sops-nix, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
    in
    {
      packages.${system} = {
        gheproxy = pkgs.callPackage ./nix/package.nix { };
        default = self.packages.${system}.gheproxy;
      };

      nixosConfigurations.gheproxy = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = { inherit self; };
        modules = [
          sops-nix.nixosModules.sops
          ./nix/module.nix
          ./nix/nginx.nix
          ./nix/hardening.nix
          ./nix/secrets.nix
          ./nix/ami.nix
        ];
      };

      nixosConfigurations.keydb = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = { inherit self; };
        modules = [
          sops-nix.nixosModules.sops
          ./nix/keydb.nix
          ./nix/hardening.nix
          ./nix/ami.nix
        ];
      };

      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          (rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" "rust-analyzer" ];
          })
          pkg-config
          cmake
          openssl
          git
          keyutils
        ];
        OPENSSL_DIR = "${pkgs.openssl.dev}";
        OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
      };
    };
}
