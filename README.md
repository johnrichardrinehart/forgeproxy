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
- **Bundle-URI** — automatic generational bundle publication from freshly updated mirrors; clients that support `bundle-uri` fetch most data from pre-built bundles
- **Filtered bundles** — optional blobless / treeless bundle variants for partial-clone workflows
- **Multi-forge support** — pluggable backend for GitHub Enterprise, GitHub.com, GitLab, Gitea, and Forgejo
- **Distributed coordination** — Valkey/Redis-backed locks, pub/sub invalidation, and node registry for multi-node deployments
- **Adaptive fetch scheduling** — background re-fetch interval adapts to repo activity with exponential backoff for idle repos
- **Two-tier cache eviction** — local disk cache with configurable LRU or LFU eviction and high/low water marks
- **S3 bundle storage** — bundles are persisted to S3 (with optional FIPS endpoints) and served via pre-signed URLs
- **Linux kernel keyring credentials** — upstream PATs and SSH keys stored in the kernel keyring via `linux-keyutils`
- **Auth caching** — SSH fingerprint and HTTP token auth results cached in Valkey with configurable TTLs
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
                              │ Local  │ │ Valkey │ │   S3   │
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
# edit upstream hostname, API URL, Valkey endpoint, S3 bucket, etc.
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
| `proxy`                | SSH and HTTP listen addresses                                  |
| `valkey`               | Valkey/Redis endpoint, TLS, auth token                          |
| `auth`                 | SSH/HTTP auth cache TTLs, webhook secret env var               |
| `clone`                | Freshness threshold, lock TTLs, concurrency semaphores         |
| `fetch_schedule`       | Background re-fetch interval, backoff, rolling window          |
| `bundles`              | Consolidation schedule, min clone count, filtered bundles      |
| `storage`              | Local disk path/percentages/eviction policy, S3 bucket/region/FIPS |
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

- `forgeproxy.nixosModules.valkey` — Valkey instance
- `forgeproxy.nixosModules.nginx` — nginx TLS termination
- `forgeproxy.nixosModules.hardening` — extra systemd hardening
- `forgeproxy.nixosModules.secrets` — sops-nix secrets integration
- `forgeproxy.nixosModules.security-controls` — security control profiles (regulated, SOC2)

## Metrics

Prometheus metrics are exposed at `GET /metrics`. A health check endpoint is
available at `GET /healthz`.

When forgeproxy's local observability config and the collector-specific OTLP
config enable any signal export, the forgeproxy host also runs a local
OpenTelemetry Collector. Forgeproxy and the collector now have separate config
surfaces:

- `config.yaml`: forgeproxy-owned observability toggles and local behavior
- `otel-collector-config.yaml`: collector-owned host metrics and OTLP egress

The signal flow is:

- Metrics: forgeproxy exposes Prometheus/OpenMetrics at `/metrics`; the
  host-local Collector scrapes that endpoint and re-exports it as OTLP. If
  `metrics.host.enabled` is true in the collector config, the same Collector
  also emits host CPU, disk, filesystem, load, memory, network, and paging
  metrics from the forgeproxy node itself.
- Logs: forgeproxy continues to write structured logs to journald; the
  host-local Collector tails `forgeproxy.service` and exports those logs as
  OTLP.
- Traces: forgeproxy emits tracing spans through Rust `tracing`; when
  `observability.traces.enabled` is true, forgeproxy sends those spans to the
  host-local Collector over a fixed loopback OTLP receiver at
  `127.0.0.1:4317`, and the Collector exports them onward.

At service startup, forgeproxy also performs best-effort runtime environment
detection and writes a shared resource-attributes file under
`/run/forgeproxy/runtime-resource-attributes.json`. Both forgeproxy itself and
the host-local Collector reuse that file so all three signals share the same
resource identity. On AWS this uses IMDSv2; Azure and GCP metadata detection is
also attempted. If cloud metadata is indeterminate, startup continues and
forgeproxy logs a warning before falling back to local identifiers such as
`/etc/machine-id`.

That means the internal Collector endpoint and the external backend endpoints
are different things:

- Internal endpoint: a private loopback hop used only on the forgeproxy host so
  forgeproxy can hand trace spans to the Collector.
- External endpoints: the real egress destinations configured in
  `otel-collector-config.yaml`.

The normal forgeproxy configuration shape is:

```yaml
observability:
  metrics:
    prometheus:
      enabled: true
      refresh_interval_secs: 60
  logs:
    journald:
      enabled: true
  traces:
    enabled: true
    sample_ratio: 1.0
```

The matching collector configuration shape is:

```yaml
metrics:
  host:
    enabled: false
exporters:
  otlp:
    metrics:
      enabled: true
      endpoint: "https://collector.internal.example/v1/metrics"
      protocol: "http/protobuf"
      auth:
        basic:
          username: "metrics-user"
          password: "metrics-password"
    logs:
      enabled: true
      endpoint: "https://logs.internal.example/v1/logs"
      protocol: "http/protobuf"
    traces:
      enabled: true
      endpoint: "https://traces.internal.example/v1/traces"
      protocol: "http/protobuf"
```

Each signal can use a different OTLP endpoint, protocol, and basic-auth
credential pair in the collector config. That is the intended way to point the
on-host Collector at an internal Collector or auth proxy which then forwards to
the final backend, such as a VictoriaMetrics metrics ingest URL plus different
log/trace backends.

The Collector also upserts these runtime resource attributes onto metrics,
logs, and traces when it exports them:

- `service.instance.id`: cloud instance ID when available, otherwise a
  best-effort stable fallback
- `service.machine_id`: `/etc/machine-id`
- `service.ip_address`: best-effort source IP for the node's outbound interface
- `cloud.provider`, `cloud.platform`, `cloud.region`: when detected from AWS,
  Azure, or GCP metadata

Host metrics are controlled separately from forgeproxy's own `/metrics`
endpoint:

- `observability.metrics.prometheus.enabled`: expose forgeproxy application
  metrics locally at `/metrics` so the on-host Collector can scrape them.
- `observability.metrics.prometheus.refresh_interval_secs`: refresh cache usage
  gauges such as mirror sizes and cache subtree sizes in the forgeproxy
  process. Defaults to 60 seconds.
- `metrics.host.enabled` in `otel-collector-config.yaml`: collect host-level
  system metrics from the forgeproxy node through the Collector's
  `hostmetrics` receiver.
- `exporters.otlp.metrics.enabled` in `otel-collector-config.yaml`: actually
  export whichever
  metrics sources were enabled above.

The current host metrics include CPU, disk I/O, filesystem capacity and usage,
load average, memory usage, paging activity, and network traffic. The OTLP
metric names for those come from the Collector's hostmetrics receiver, for
example `system.cpu.time`, `system.memory.usage`, `system.filesystem.usage`,
and `system.network.io`.

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

## Design Notes

- [`docs/consolidation-locking.md`](docs/consolidation-locking.md)
- [`docs/repository-rename-shortcoming.md`](docs/repository-rename-shortcoming.md)

## License

[MIT](https://opensource.org/licenses/MIT)
