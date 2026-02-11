{ lib
, rustPlatform
, pkg-config
, cmake
, openssl
, go
, perl
, fipsEnabled ? true
}:

rustPlatform.buildRustPackage {
  pname = "gheproxy";
  version = "0.1.0";

  src = ../src;

  cargoLock.lockFile = ../src/Cargo.lock;

  nativeBuildInputs = [
    pkg-config
    cmake
  ] ++ lib.optionals fipsEnabled [
    go    # required by aws-lc-fips-sys
    perl  # required by aws-lc-fips-sys
  ];

  buildInputs = [
    openssl
  ];

  buildFeatures = lib.optionals fipsEnabled [ "fips" ];

  # Ensure openssl-sys can find headers and libraries.
  OPENSSL_NO_VENDOR = 1;

  meta = with lib; {
    description = "GHE Caching Reverse Proxy with bundle-uri support";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "gheproxy";
  };
}
