{ lib
, rustPlatform
, pkg-config
, cmake
, openssl
}:

rustPlatform.buildRustPackage {
  pname = "gheproxy";
  version = "0.1.0";

  src = ../src;

  cargoLock.lockFile = ../src/Cargo.lock;

  nativeBuildInputs = [
    pkg-config
    cmake
  ];

  buildInputs = [
    openssl
  ];

  buildFeatures = [ "fips" ];

  # Ensure openssl-sys can find headers and libraries.
  OPENSSL_NO_VENDOR = 1;

  meta = with lib; {
    description = "GHE Caching Reverse Proxy with bundle-uri support";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "gheproxy";
  };
}
