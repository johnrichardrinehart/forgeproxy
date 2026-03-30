{
  lib,
  rustPlatform,
  pkg-config,
  cmake,
  git,
  openssl,
  go,
  perl,
  devEnabled ? false,
  fipsEnabled ? false,
  gitRevision ? "unknown",
}:

rustPlatform.buildRustPackage {
  pname = "forgeproxy";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../rust
      # Config parser tests use include_str! on the repo-root example config,
      # so include it in the Rust build sandbox alongside the crate sources.
      ../config.example.yaml
    ];
  };
  sourceRoot = "source/rust";

  cargoLock = {
    lockFile = ../rust/Cargo.lock;
    outputHashes = {
      "pageant-0.0.1-beta.3" = "sha256-791tlOrQc8nSjSvVfSlk0T1smk/H7I7SvmLvQSvqdhA=";
      "russh-0.46.0" = "sha256-791tlOrQc8nSjSvVfSlk0T1smk/H7I7SvmLvQSvqdhA=";
      "russh-cryptovec-0.7.3" = "sha256-791tlOrQc8nSjSvVfSlk0T1smk/H7I7SvmLvQSvqdhA=";
      "russh-keys-0.46.0" = "sha256-791tlOrQc8nSjSvVfSlk0T1smk/H7I7SvmLvQSvqdhA=";
      "russh-util-0.46.0" = "sha256-791tlOrQc8nSjSvVfSlk0T1smk/H7I7SvmLvQSvqdhA=";
    };
  };

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

  nativeCheckInputs = [
    git
  ];

  buildFeatures = lib.optionals devEnabled [ "dev" ] ++ lib.optionals fipsEnabled [ "fips" ];
  FORGEPROXY_GIT_REVISION = gitRevision;

  # Ensure openssl-sys can find headers and libraries.
  OPENSSL_NO_VENDOR = 1;

  meta = with lib; {
    description = "Git Caching Reverse Proxy";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "forgeproxy";
  };
}
