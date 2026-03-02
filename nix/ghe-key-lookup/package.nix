{ lib, rustPlatform }:
rustPlatform.buildRustPackage {
  pname = "ghe-key-lookup";
  version = "0.1.0";
  src = ../../ghe-key-lookup;
  cargoLock.lockFile = ../../ghe-key-lookup/Cargo.lock;
  meta = with lib; {
    description = "Map SSH key fingerprints to GHE users via admin SSH";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "ghe-key-lookup";
  };
}
