{
  lib,
  rustPlatform,
  stdenvNoCC,
  pkg-config,
  cmake,
  coreutils,
  git,
  openssl,
  go,
  perl,
  devEnabled ? false,
  fipsEnabled ? false,
  gitRevision ? "unknown",
}:

let
  version = "0.1.0";
  rustSource = lib.fileset.toSource {
    root = ../../..;
    fileset = lib.fileset.unions [
      ../../../.cargo
      ../../../rust
      # Config parser tests use include_str! on the repo-root example config,
      # so include it in the Rust build sandbox alongside the crate sources.
      ../../../config.example.yaml
    ];
  };
  unstamped = rustPlatform.buildRustPackage {
    pname = "forgeproxy-unstamped";
    inherit version;

    src = rustSource;
    sourceRoot = "source/rust";

    cargoLock = {
      lockFile = "${rustSource}/rust/Cargo.lock";
      outputHashes = {
        "pageant-0.2.0" = "sha256-bWcaN8euCiW3eOjzsULiw5OKrRvTLi8n+V5rSz/IAH4=";
        "russh-0.58.0" = "sha256-bWcaN8euCiW3eOjzsULiw5OKrRvTLi8n+V5rSz/IAH4=";
        "russh-cryptovec-0.58.0" = "sha256-bWcaN8euCiW3eOjzsULiw5OKrRvTLi8n+V5rSz/IAH4=";
        "russh-util-0.52.0" = "sha256-bWcaN8euCiW3eOjzsULiw5OKrRvTLi8n+V5rSz/IAH4=";
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

    # Ensure openssl-sys can find headers and libraries.
    OPENSSL_NO_VENDOR = 1;

    meta = with lib; {
      description = "Git Caching Reverse Proxy";
      license = licenses.mit;
      platforms = platforms.linux;
      mainProgram = "forgeproxy";
    };
  };
  embeddedBuildInfo = builtins.toJSON {
    git_revision = gitRevision;
  };
in
stdenvNoCC.mkDerivation {
  pname = "forgeproxy";
  inherit version;

  dontUnpack = true;
  nativeBuildInputs = [ coreutils ];

  installPhase = ''
    runHook preInstall

    mkdir -p "$out"
    cp -a ${unstamped}/. "$out"/
    chmod u+w "$out/bin/forgeproxy"

    metadata_json=${lib.escapeShellArg embeddedBuildInfo}
    metadata_len=$(printf '%s' "$metadata_json" | wc -c | tr -d '[:space:]')
    printf '%s' "$metadata_json" >> "$out/bin/forgeproxy"
    printf '%016x%s' "$metadata_len" 'FGPXBUILDINFOv1!' >> "$out/bin/forgeproxy"
    chmod 0555 "$out/bin/forgeproxy"

    runHook postInstall
  '';

  passthru = (unstamped.passthru or { }) // {
    unstamped = unstamped;
  };

  meta = unstamped.meta;
}
