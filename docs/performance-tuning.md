# Forgeproxy Performance Tuning

This note captures the parts of clone-performance tuning that are now backed by
the repo, plus the follow-up experiments that still need validation before they
become default guidance.

## Benchmark context

The observations below came from one deployment shape, not from the module's
Terraform defaults:

- 5-10 concurrent workers cloning a ~2 GiB repository
- high host load average
- low CPU utilization
- warm page cache after the first clone
- bursty write traffic during hydration, but little steady-state read I/O

That shape is consistent with a workload where local `git upload-pack`
subprocesses spend more time blocked on downstream socket pressure than on CPU
or storage. Treat that as a hypothesis to verify on your own deployment, not as
a universal property of every forgeproxy install.

## Implemented observability

### Application metrics

This branch adds:

- `forgeproxy_upload_pack_duration_seconds{protocol,source,repo}`
  - duration of successful upload-pack handling
  - `source="local"` for local `git upload-pack`
  - `source="upstream"` for proxied upstream pack streams
- `forgeproxy_upload_pack_first_byte_seconds{protocol,source,cache_status,repo}`
  - latency to the first downstream upload-pack byte
  - `source="local_upload_pack"`, `source="pack_cache"`, or `source="upstream"`
- `forgeproxy_upload_pack_concurrent{protocol}`
  - currently running local `git upload-pack` subprocesses
  - this is intentionally local-process concurrency, not total clone requests
- `forgeproxy_hydration_skipped_total{reason}`
  - `reason="same_node_dedup"` when a repo is already hydrating on this node
  - `reason="semaphore_saturated"` when the clone-hydration semaphore refuses
    new work

Existing metrics that remain useful for the same investigation:

- `forgeproxy_clone_duration_seconds`
- `forgeproxy_clone_upstream_bytes_total`
- `forgeproxy_clone_downstream_bytes_total`
- `forgeproxy_lock_waits_total`
- `forgeproxy_active_connections`

### Grafana dashboard

The forgeproxy dashboard now includes:

- local upload-pack subprocess concurrency in the Clone Operations row
- active clone serving counts observed by forgeproxy: forgeproxy-served versus
  forgeproxy-proxied upstream upload-pack streams across SSH and HTTPS, plus
  the active upstream path/reason breakdown
- upload-pack first-byte percentiles by source and cache status
- pack-cache bypass, warming-skip, recent-entry, and composite-candidate
  diagnostics in the Cache & Storage row
- host I/O wait percentage
- disk queue depth from `system.disk.weighted_io_time`
- disk read latency from `system.disk.operation_time / system.disk.operations`
- major page fault rate
- page-cache size
- a tighter memory breakdown focused on `used`, `cached`, `free`, and
  `slab_reclaimable`

Those panels are enough to answer the first-order question: is a slow clone
limited by disk, memory pressure, or downstream socket backpressure?

### Terraform knobs

The module now exposes these performance controls directly:

- `forgeproxy_root_volume_iops` (default `3000`)
- `forgeproxy_root_volume_throughput_mbps` (default `125`)
- `forgeproxy_cache_volume_enabled` (default `false`) moves
  `/var/cache/forgeproxy` onto a retained dedicated EBS volume. During
  blue/green rollout, the standby slot is seeded from live snapshots of the
  currently active slot's cache volumes when available.
- `forgeproxy_cache_volume_gb` (default `1024`), plus gp3
  `forgeproxy_cache_volume_iops` and
  `forgeproxy_cache_volume_throughput_mbps`, size and tune those dedicated
  cache volumes.
- `bundle_pack_threads` (default `4`), wired through `pack.threads` for bundle
  generation, background bitmap/MIDX preparation, and pack-cache deltas
- `local_upload_pack_threads` (default `2`), wired to
  `git -c pack.threads=<n> upload-pack` for local disk serves

Dedicated cache EBS is opt-in. Defaults stay unchanged so existing deployments
do not drift without operator intent.

For emergency relief, an AWS forgeproxy instance tagged
`forgeproxy-disable=true` is removed from the acceleration path locally: nginx
continues to answer health checks but sends client HTTPS and SSH Git traffic
directly to the upstream forge. This is intentionally instance-scoped and only
the exact value `true` activates it.

## How to read the signals

### Disk vs. socket pressure

During a clone benchmark, check these together:

- `forgeproxy_upload_pack_concurrent`
- I/O Wait %
- Disk Queue Depth
- Disk Read Latency
- Major Page Faults / sec
- Page Cache Size

Interpretation:

- High upload-pack concurrency with low iowait, low queue depth, and near-zero
  major faults points to downstream socket pressure, not storage.
- Rising read latency and queue depth during hydration suggests writes are
  interfering with cache-cold reads.
- Sustained major page faults or shrinking cached memory means the working set
  no longer fits comfortably in RAM.

### Clone path attribution

Compare these two metric families:

- `forgeproxy_upload_pack_duration_seconds{source="local"}`
- `forgeproxy_upload_pack_duration_seconds{source="upstream"}`

If local upload-pack remains slow while disk signals stay quiet, the bottleneck
is probably after pack generation: TCP buffers, client receive rate, or another
network boundary.

## Follow-up work not yet implemented

These are still reasonable ideas, but they are not shipped by this branch and
should not be described as present-tense behavior.

### Host `process` scraper

Per-process host metrics would help attribute CPU and I/O to `git-upload-pack`
versus the forgeproxy daemon, but adding the OpenTelemetry `process` scraper is
not just a secret-template edit. The collector module currently hardcodes the
host scraper list in `nix/nixosModules/forgeproxy/otel-collector.nix`, so this
needs collector-module work and test coverage.

### Kernel tuning

Treat these as opt-in experiments:

- larger TCP send/receive buffers
- `bbr` congestion control
- lower dirty ratios for hydration bursts
- readahead tuning for cache-cold packfile reads
- `mq-deadline` tuning

None of those should become defaults without before/after benchmarks and a
clear statement of the deployment risk. Some of them trade operational
predictability for performance on one workload shape.

### Instance sizing

Do not encode a single instance-family recommendation into repo-level guidance.
Choose shape after measuring:

- page-cache sufficiency
- network saturation
- hydration write interference
- clone concurrency versus local upload-pack concurrency

For some environments, more RAM is the right next move. For others, more gp3
throughput/IOPS is enough. For others, neither helps because the bottleneck is
downstream network backpressure.

## Suggested experiment order

1. Enable host metrics and use the updated dashboard.
2. Run the clone-throughput benchmark again.
3. If hydration writes correlate with read latency spikes, raise gp3 throughput
   and IOPS first because that change is easy to roll back.
4. Only after that, test kernel tuning or instance-family changes.

## Runbook

Quick checks on a loaded instance:

```bash
# Where are processes blocked?
cat /proc/*/wchan 2>/dev/null | sort | uniq -c | sort -rn | head -20

# TCP socket pressure
ss -tm | head -20
cat /proc/net/sockstat

# Page-cache state
grep -E "^(MemTotal|MemFree|Cached|Buffers|Active\\(file\\)|Inactive\\(file\\))" /proc/meminfo

# Local upload-pack subprocess count
pgrep -af "git upload-pack" | wc -l
```

Useful wait-channel hints:

- `sk_stream_wait_memory` or `sk_wait_data`: socket backpressure
- `io_schedule`: disk wait
- `do_futex_wait`: lock contention
