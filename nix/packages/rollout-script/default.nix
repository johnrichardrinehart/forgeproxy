{
  lib,
  bash,
  awscli2,
  coreutils,
  curl,
  makeWrapper,
  stdenvNoCC,
  symlinkJoin,
  scriptName,
  scriptPath,
}:

let
  script = stdenvNoCC.mkDerivation {
    pname = scriptName;
    version = "0";
    src = scriptPath;
    dontUnpack = true;

    installPhase = ''
      install -Dm755 "$src" "$out/bin/${scriptName}"
      substituteInPlace "$out/bin/${scriptName}" \
        --replace-fail '#!/usr/bin/env bash' '#!${bash}/bin/bash'
    '';
  };
in
symlinkJoin {
  name = scriptName;
  paths = [
    script
    awscli2
    bash
    coreutils
    curl
  ];
  nativeBuildInputs = [ makeWrapper ];
  postBuild = ''
    wrapProgram "$out/bin/${scriptName}" --prefix PATH : "$out/bin"
  '';

  meta = with lib; {
    description = "forgeproxy Terraform rollout helper script";
    mainProgram = scriptName;
    platforms = platforms.linux;
  };
}
