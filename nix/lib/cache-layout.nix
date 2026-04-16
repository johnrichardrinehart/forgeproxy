{
  lib,
  root,
}:

let
  trimGitSuffix = name: if lib.hasSuffix ".git" name then lib.removeSuffix ".git" name else name;

  splitOwnerRepo =
    ownerRepo:
    let
      parts = lib.splitString "/" ownerRepo;
      owner = builtins.head parts;
      repoParts = builtins.tail parts;
      repo = lib.concatStringsSep "/" repoParts;
    in
    if repoParts == [ ] then
      {
        inherit owner;
        repo = trimGitSuffix owner;
        hasOwner = false;
      }
    else
      {
        inherit owner;
        repo = trimGitSuffix repo;
        hasOwner = true;
      };

  repoPathUnder =
    base: ownerRepo: keepGitSuffix:
    let
      parts = splitOwnerRepo ownerRepo;
      repoLeaf = if keepGitSuffix then "${parts.repo}.git" else parts.repo;
    in
    if parts.hasOwner then "${base}/${parts.owner}/${repoLeaf}" else "${base}/${repoLeaf}";
in
rec {
  cacheRoot = root;
  generationsRoot = "${cacheRoot}/published";
  mirrorsRoot = "${cacheRoot}/mirrors";
  snapshotsRoot = "${cacheRoot}/snapshots";
  stateRoot = "${cacheRoot}/.state";
  stateGenerationsRoot = "${stateRoot}/generations";
  stateDeltaRoot = "${stateRoot}/delta";
  stateTeeRoot = "${stateRoot}/tee";
  stateBundleTmpRoot = "${stateRoot}/bundle-tmp";

  repoPath = ownerRepo: repoPathUnder generationsRoot ownerRepo true;
  generationDir = ownerRepo: repoPathUnder stateGenerationsRoot ownerRepo true;
  mirrorPath = ownerRepo: repoPathUnder mirrorsRoot ownerRepo true;
  deltaDir = ownerRepo: repoPathUnder stateDeltaRoot ownerRepo true;
  teeDir = ownerRepo: repoPathUnder stateTeeRoot ownerRepo false;

  snapshotRepoDir = owner: repo: "${snapshotsRoot}/${owner}/${trimGitSuffix repo}";
}
