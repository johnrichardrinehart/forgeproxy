{
  lib,
  rustPlatform,
  pkg-config,
  cmake,
  openssl,
  go,
  perl,
  fipsEnabled ? false,
}:

rustPlatform.buildRustPackage {
  pname = "forgecache";
  version = "0.1.0";

  src = ../rust;

  cargoLock.lockFile = ../rust/Cargo.lock;

  nativeBuildInputs = [
    pkg-config
    cmake
  ]
  ++ lib.optionals fipsEnabled [
    go # required by aws-lc-fips-sys
    perl # required by aws-lc-fips-sys
  ];

  buildInputs = [
    openssl
  ];

  buildFeatures = lib.optionals fipsEnabled [ "fips" ];

  # Ensure openssl-sys can find headers and libraries.
  OPENSSL_NO_VENDOR = 1;

  meta = with lib; {
    description = "Git Caching Reverse Proxy";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "forgecache";
  };
}
