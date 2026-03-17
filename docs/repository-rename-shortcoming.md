# Repository Rename Shortcoming

## Problem

`forgeproxy` currently keys cached state by the textual repository path
(`owner/repo`) instead of by a stable upstream repository identity.

That means a renamed repository can be treated as two different repositories if
the upstream forge continues to serve both the old and new path during a rename
transition. In that case, `forgeproxy` can create duplicate:

- published generations
- bundle metadata and bundle objects
- Valkey coordination state
- hydration and fetch state

This is a correctness and efficiency shortcoming. The local cache should dedupe
old and new names onto one canonical repository identity.

## Current Impact

Today, the duplicate-state risk is highest for upstreams that preserve old clone
URLs after a rename or redirect Git traffic from the old path to the new path.

At a high level:

- GitHub Cloud and GitHub Enterprise keep old repository URLs redirecting after
  a rename.
- GitLab Cloud, GitLab Dedicated, and self-managed GitLab instances keep old
  project paths redirecting after a rename.
- Gitea and Forgejo may also preserve old paths, but this should be treated as
  instance-dependent until we verify the exact behavior against the deployed
  version and configuration.

## Required Direction

The cache key needs to move from `owner/repo` to a canonical upstream identity.

The intended model is:

- use a stable forge-side repository identifier as the primary cache key
- maintain an alias map from every observed repository path to that canonical ID
- store the current canonical path as metadata, not as the identity itself
- key generations, bundles, and coordination state by canonical ID
- update alias metadata when webhooks or API responses reveal a rename

This also requires a migration plan for existing path-keyed state so that older
bundles and generations can be adopted rather than duplicated.

## Upstream Plans

### GitHub Cloud and GitHub Enterprise

Plan:

- use the repository ID returned by the GitHub repository API as the canonical
  identity
- record both the observed request path and the API-reported canonical
  `full_name` as aliases for that ID
- update alias metadata when repository webhook payloads indicate a rename
- move bundle and generation storage from path-derived names to canonical-ID
  derived names

Expected result:

- clones through either the old or new repository name converge on one local
  cache entry
- post-rename traffic warms the same generations and bundles instead of
  starting a second cache lineage

### GitLab Cloud, Dedicated, and Self-Managed

Plan:

- use the GitLab project `id` as the canonical identity
- treat `path_with_namespace` as mutable metadata and maintain aliases for old
  and new paths
- update alias metadata from API responses and project webhook events
- move coordination keys, bundle keys, and generation directories to canonical
  project-ID based names

Expected result:

- old and new project paths dedupe to one cache entry during and after rename
- rename redirects do not create duplicate bundles or published generations

### Gitea

Plan:

- verify whether the deployed Gitea version exposes a stable repository ID that
  can be used as the canonical identity
- if a stable ID is available, key all local cache state by that ID
- if only mutable path information is available, add an explicit alias layer and
  canonicalization step before touching cache state
- verify rename and redirect behavior for Git transport and webhook payloads on
  the target Gitea version

Expected result:

- once the API behavior is verified, Gitea-backed repos follow the same
  canonical-ID plus alias model as GitHub and GitLab

### Forgejo

Plan:

- treat Forgejo the same way as Gitea unless the API diverges in a relevant way
- verify stable repository identity fields, rename behavior, and webhook rename
  signals against the deployed Forgejo version
- use the verified stable identity as the canonical cache key and keep path
  aliases separate

Expected result:

- renamed Forgejo repositories converge on one cache lineage instead of
  splintering by path

## Migration Notes

Any implementation should include reconciliation for already-cached
path-keyed repositories. At minimum:

- detect when an observed path alias maps to an existing path-keyed cache entry
- choose one canonical ID-backed home for the repository
- migrate or adopt prior generations and bundle metadata into that home
- leave compatibility redirects or alias records so older paths still resolve

Without this migration step, the design change would avoid future duplication
but still strand existing bundle and generation state under older names.
