# forgeproxy

Git caching reverse proxy with [bundle-uri](https://git-scm.com/docs/bundle-uri) support.

## Overview

forgeproxy sits between Git clients and an upstream forge (GitHub Enterprise,
GitHub.com, GitLab, Gitea, or Forgejo). It maintains bare-repo caches on local
disk, serves clones and fetches from cache, and generates Git bundles that
clients can download over HTTP before negotiating a pack — dramatically reducing
load on the upstream forge and speeding up clones.

## Features

- **SSH and HTTP transport** — proxy both `git clone ssh://` and `git clone https://`
- **Bundle-URI** — automatic bundle generation with incremental, daily, and weekly consolidation; clients that support `bundle-uri` fetch most data from pre-built bundles
- **Filtered bundles** — optional blobless / treeless bundle variants for partial-clone workflows
- **Multi-forge support** — pluggable backend for GitHub Enterprise, GitHub.com, GitLab, Gitea, and Forgejo
- **Distributed coordination** — KeyDB/Redis-backed locks, pub/sub invalidation, and node registry for multi-node deployments
- **Adaptive fetch scheduling** — background re-fetch interval adapts to repo activity with exponential backoff for idle repos
- **Two-tier cache eviction** — local disk cache with configurable LRU or LFU eviction and high/low water marks
- **S3 bundle storage** — bundles are persisted to S3 (with optional FIPS endpoints) and served via pre-signed URLs
- **Linux kernel keyring credentials** — upstream PATs and SSH keys stored in the kernel keyring via `linux-keyutils`
- **Auth caching** — SSH fingerprint and HTTP token auth results cached in KeyDB with configurable TTLs
- **Webhook-driven invalidation** — push webhooks trigger immediate re-fetch of affected repos
- **Forge API rate-limit awareness** — self-throttles when the upstream API rate-limit budget runs low
- **Prometheus metrics** — counters, gauges, and histograms for clone latency, cache hit rate, bundle generation, and more
- **FIPS 140 build** — optional `fips` Cargo feature for FIPS-validated TLS via rustls
- **NixOS module** — declarative deployment with systemd hardening out of the box
- **Comprehensive NixOS VM tests** — 10 integration tests covering basic operation, SSH authz, secrets, cache eviction, compliance, and more

## Architecture

```
  ┌───────────┐       SSH (2222)       ┌──────────────┐        SSH / HTTPS        ┌───────────┐
  │           │ ────────────────────▶  │              │ ──────────────────────▶   │           │
  │  Git      │       HTTPS (8080)     │  forgeproxy  │                           │  Upstream │
  │  Clients  │ ────────────────────▶  │              │ ◀── push webhook ───────  │  Forge    │
  │           │ ◀── bundle-uri ──────  │              │                           │           │
  └───────────┘                        └──────┬───────┘                           └───────────┘
                                              │
                                   ┌──────────┼──────────┐
                                   ▼          ▼          ▼
                              ┌────────┐ ┌────────┐ ┌────────┐
                              │ Local  │ │ KeyDB  │ │   S3   │
                              │ Disk   │ │ Redis  │ │Bundles │
                              │ Cache  │ │        │ │        │
                              └────────┘ └────────┘ └────────┘
```

## Supported Forges

| Backend              | SSH key resolution | Notes                                           |
|----------------------|--------------------|-------------------------------------------------|
| `github-enterprise`  | Yes                | Requires `site_admin` PAT scope on GHE          |
| `github`             | No                 | GitHub.com has no admin key-lookup API           |
| `gitlab`             | Yes                | Requires self-managed instance admin token       |
| `gitea`              | Yes                | Requires instance admin token                    |
| `forgejo`            | Yes                | Same API as Gitea; different webhook headers     |

When SSH key resolution is unavailable, clients must authenticate via HTTP
token rather than SSH key passthrough.

## Quick Start

Build with Nix:

```bash
nix build .#forgeproxy          # standard build
nix build .#forgeproxy-fips     # FIPS 140 TLS build
```

Copy and edit the example configuration:

```bash
cp config.example.yaml /run/forgeproxy/config.yaml
# edit upstream hostname, API URL, KeyDB endpoint, S3 bucket, etc.
```

Run:

```bash
forgeproxy --config /run/forgeproxy/config.yaml
```

## Configuration

See [`config.example.yaml`](config.example.yaml) for a fully commented example.
Top-level sections:

| Section                | Purpose                                                        |
|------------------------|----------------------------------------------------------------|
| `upstream`             | Forge hostname, API URL, admin token env var                   |
| `backend_type`         | Forge flavour (`github-enterprise`, `github`, `gitlab`, etc.)  |
| `upstream_credentials` | Default credential mode and per-org overrides (PAT / SSH)      |
| `proxy`                | SSH and HTTP listen addresses, bundle-URI base URL             |
| `keydb`                | KeyDB/Redis endpoint, TLS, auth token                          |
| `auth`                 | SSH/HTTP auth cache TTLs, webhook secret env var               |
| `clone`                | Freshness threshold, lock TTLs, concurrency semaphores         |
| `fetch_schedule`       | Background re-fetch interval, backoff, rolling window          |
| `bundles`              | Consolidation schedule, min clone count, filtered bundles      |
| `storage`              | Local disk path/limits/eviction policy, S3 bucket/region/FIPS  |
| `repo_overrides`       | Per-repo overrides for fetch interval, freshness, bundles      |

## NixOS Deployment

The flake exports a NixOS module for declarative deployment:

```nix
{
  inputs.forgeproxy.url = "github:your-org/forgeproxy";

  outputs = { self, nixpkgs, forgeproxy, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        { nixpkgs.overlays = [ forgeproxy.overlays.default ]; }
        forgeproxy.nixosModules.forgeproxy
        {
          services.forgeproxy = {
            enable = true;
            configFile = "/run/forgeproxy/config.yaml";
            logLevel = "info";
          };
        }
      ];
    };
  };
}
```

Additional NixOS modules are available for companion services:

- `forgeproxy.nixosModules.keydb` — KeyDB instance
- `forgeproxy.nixosModules.nginx` — nginx TLS termination
- `forgeproxy.nixosModules.hardening` — extra systemd hardening
- `forgeproxy.nixosModules.secrets` — sops-nix secrets integration
- `forgeproxy.nixosModules.compliance` — FedRAMP compliance profile

## Metrics

Prometheus metrics are exposed at `GET /metrics`. A health check endpoint is
available at `GET /healthz`.

## Development

Enter the dev shell:

```bash
nix develop
```

Run Rust tests:

```bash
cd rust && cargo test
```

Run the full check suite (formatting, clippy, and all NixOS VM tests):

```bash
nix flake check
```

## License

[MIT](https://opensource.org/licenses/MIT)
