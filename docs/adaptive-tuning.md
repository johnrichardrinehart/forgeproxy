# Adaptive Runtime Tuning

`adaptive_tuning` controls runtime limits for clone, fetch, tee-capture,
bundle, pack-cache, and local upload-pack work. The static values under
`clone`, `bundles`, `pack_cache`, and `prewarm` remain the startup fallback.
When adaptive tuning is enabled, forgeproxy starts from those values and then
applies bounded controller recommendations at runtime.

The shared principle is SLO-first best effort:

- Avoid proxying clients upstream when local service is likely to satisfy the
  request soon enough.
- Avoid making clients wait on local work when current evidence says local
  service is unlikely to meet the SLO.
- Keep every runtime value inside operator-supplied bounds.
- Preserve enough host headroom for imminent requests instead of assigning all
  visible resources to the first expensive operation.

## Basic Configuration

For the compatibility `aimd` controller:

```yaml
adaptive_tuning:
  enabled: true
  mode: "shadow"
  controller: "aimd"
  evaluation_interval_secs: 60
  cpu_poll_interval_secs: 10
  warmup_interval_secs: 300
  min_sample_count: 20
  recommendation_ttl_secs: 300
  recommendation_max_staleness_secs: 300
```

For the event-based `demand_resource` controller:

```yaml
adaptive_tuning:
  enabled: true
  mode: "shadow"
  controller: "demand_resource"
  demand_resource:
    cpu_provisioning_fraction: 1.5
    cpu_provisioning_fraction_when_memory_constrained: 0.5
```

`enabled` turns the adaptive controller task on. When disabled, startup static
configuration is used for controller-managed runtime limits. Request-time
flexible SLO admission is controlled separately by `slo_policy.enabled`.

`mode` selects how recommendations are used:

- `active`: apply recommendations to the in-process effective policy and persist
  them to Valkey for startup reuse.
- `shadow`: compute and publish recommendation metrics without applying them.
- `disabled`: ignore the controller even when `enabled` is true.

`controller` selects the global runtime controller:

- `aimd`: the original interval-based additive-increase/multiplicative-decrease
  controller. This is the default for compatibility.
- `demand_resource`: an event-driven controller that evaluates on resource-claim
  and observation events, then derives concurrency and thread limits from
  current demand plus measured host headroom.

`evaluation_interval_secs` is the `aimd` controller cadence and host-pressure
sample window. `demand_resource` does not use this field and does not wake up on
a recommendation interval.

`cpu_poll_interval_secs` controls how often CPU and disk pressure are sampled
inside the `aimd` host-pressure sample window. `demand_resource` does not poll
CPU or disk pressure on a timer; it takes a short CPU/disk point sample when a
demand event triggers evaluation.

`warmup_interval_secs` suppresses `aimd` active tuning after process start so
startup transients do not immediately steer policy. `demand_resource` does not
wait for warmup before responding to demand events.

`min_sample_count` is the minimum observation-window sample count before SLO
signals such as fallback rate and latency steer policy. `demand_resource` may
still rebalance from current resource claims before this threshold.

`recommendation_ttl_secs` is how long persisted global and repo recommendations
remain in Valkey. This is persistence hygiene, not a controller evaluation
interval.

`recommendation_max_staleness_secs` is the maximum age forgeproxy will trust
when loading persisted recommendations at startup or aggregating peer repo
recommendations. It does not make `demand_resource` wait before recalculating a
policy from current demand.

## Controller Behavior

### `aimd`

`aimd` evaluates on `evaluation_interval_secs`. After warmup and minimum sample
count:

- Host pressure decreases background-heavy work first.
- Excess fallback rate increases the capacity or wait budget most directly
  associated with the dominant fallback reason.
- Clone or first-byte SLO latency breaches decrease foreground and background
  capacity.
- Healthy windows gradually increase capacity and tighten wait budgets.

This controller is useful as a conservative rollback target because it preserves
the historical behavior and uses the existing step sizes on every bound.
Repo-scoped adaptive policy overlays are also produced by the AIMD path.

### `demand_resource`

`demand_resource` evaluates when a relevant event happens:

- A resizable gate permit is acquired or released, which changes active claims.
- Clone latency, first-byte latency, or upstream fallback observations arrive.
- The effective policy is manually applied or reloaded.

It does not probe every knob upward on a timer, and it skips evaluation when no
resource claims are active. Instead, it builds a current demand snapshot from
active claims and computes:

- foreground demand: upstream clone, upstream fetch, request pack-cache delta,
  and local upload-pack claims.
- background demand: tee capture, bundle generation, background pack-cache
  warming, deep validation, prewarm, and low-priority fetch claims.
- host CPU budget from cgroup-aware available parallelism, reserving host
  headroom before assigning per-operation threads.
- reduced usable CPU under memory pressure. CPU, disk, and memory watermarks
  are checked before demand-based allocation; CPU and disk use a short point
  sample so recommendation calculation stays event-triggered.

Concurrency knobs are set to current claims plus bounded headroom. Per-operation
thread knobs are set from a fair share of usable CPU across expected active and
near-future work. This prevents a 64-vCPU host from assigning all vCPUs to one
clone or bundle operation while still allowing larger allocations when demand
and headroom justify them.

When `controller: "demand_resource"` is selected, the AIMD repo-scoped
recommendation loop is not run. That avoids a hidden interval/warmup controller
inside an event-driven global controller.

For first-byte latency SLO breaches, `demand_resource` uses a stage-aware TTFB
breakdown before choosing a knob. The HTTP and SSH local upload-pack paths
record these stages:

- `published_generation_lease_wait`: time spent waiting for the published local
  repository generation lease.
- `pack_cache_lookup_wait`: time spent in request-time pack-cache
  lookup/reservation.
- `pack_cache_composite_wait`: time spent attempting request-time pack-cache
  composite generation before falling through to local upload-pack.
- `local_upload_pack_permit_wait`: time spent acquiring/spawning local
  upload-pack. This stage includes the permit wait plus process startup because
  both consume the same admission path.
- `local_upload_pack_spawn_and_stdin`: time spent writing the buffered request
  body to the spawned upload-pack process.
- `local_upload_pack_first_byte_wait`: time spent waiting for local upload-pack
  stdout to produce the first response bytes.

The controller aggregates stage samples globally and per repository, picks the
dominant stage in the current observation window, and maps that stage to the
most relevant resource policy:

- published-generation lease wait increases generation recovery capacity first,
  then `generation_publish_secs` if capacity is already at its bound.
- pack-cache lookup or composite wait increases
  `pack_cache_request_delta_concurrency` first, then request wait budgets if
  pack-cache request capacity is already at its bound.
- local upload-pack permit wait increases `local_upload_pack_concurrency`,
  `local_upload_pack_per_repo`, and `local_upload_pack_threads`.
- local upload-pack spawn/stdin or first-byte wait increases
  `local_upload_pack_threads` first, then local upload-pack capacity, then
  `local_upload_pack_first_byte_secs` if capacity is already at its bound.

The TTFB stage estimator is still event-based. It records completed local
upload-pack attempts and non-early first-byte fallbacks; it does not wake the
controller on a clock and it does not evaluate when there are no active
resource claims. Partial admission fallbacks before later stages ran, such as
published-generation lease or local upload-pack permit contention, still emit
stage and fallback metrics but do not enter adaptive TTFB history. If flexible
SLO admission chooses an early abort before local upload-pack has had a fair
chance to produce a first byte, forgeproxy records the fallback pressure but
does not write a fabricated short or worst-case TTFB sample into the latency
history.

### `demand_resource` Configuration

```yaml
adaptive_tuning:
  demand_resource:
    cpu_provisioning_fraction: 1.5
    cpu_provisioning_fraction_when_memory_constrained: 0.5
```

`cpu_provisioning_fraction` is the total CPU budget the controller may allocate
across CPU-heavy runtime operations, expressed as a fraction of detected CPU
parallelism. The value may exceed `1.0` when controlled overcommit is acceptable.
For example, `1.5` on a 64-vCPU host allows the controller to allocate up to 96
thread-equivalents across operations such as bundle pack, local upload-pack,
and index-pack.

`cpu_provisioning_fraction_when_memory_constrained` is the lower CPU allocation
ceiling used when available memory falls below
`resource_pressure.memory_available_min_percent`, also expressed as a fraction
of detected CPU parallelism. With the default `0.5`, a 64-vCPU host is limited
to 32 thread-equivalents while memory is constrained.

Memory affects this CPU budget because Git parallelism is not purely CPU-bound.
Increasing `pack.threads` and `index-pack` work also increases live memory,
buffering, object traversal state, and page-cache burden. When memory is
scarce, reducing thread-equivalent allocation helps avoid reclaim, swap, OOM
risk, and first-byte latency regressions.

Concurrency headroom for request-path and background application resources is
an internal heuristic derived from active claims and the provisioned CPU budget.
Operators configure hardware resource policy here; they do not configure
foreground/background application semaphore headroom directly.

## SLOs

```yaml
adaptive_tuning:
  slo:
    clone_latency_secs: 30.0
    first_byte_latency_secs: 5.0
    fallback_rate: 0.05
  slo_policy:
    enabled: true
    min_sample_count: 5
    near_miss_grace_fraction: 0.10
    near_miss_grace_secs: 3.0
    early_abort_overrun_fraction: 0.25
```

`clone_latency_secs` is the target average clone/request completion latency for
adaptive observation windows.

`first_byte_latency_secs` is the target average time to first byte from local
upload-pack service.

`fallback_rate` is the maximum acceptable fraction of locally eligible clone
requests that fall back to upstream in an observation window.

These SLOs are best-effort steering inputs, not hard guarantees. Controllers may
allow bounded SLO exceptions when current evidence suggests the local path will
finish close enough to the target, and may proxy upstream early when evidence
suggests the local path will miss by too much.

`slo_policy.enabled` turns flexible SLO admission on for request-time decisions
that have live or historical estimates. It is independent of controller
`enabled` and `mode`; set `slo_policy.enabled = false` when operators want
strict configured local upload-pack first-byte waits. The first implemented
operation is local upload-pack time-to-first-byte for HTTP and SSH fetches.
If the global short-circuit budget or effective
`local_upload_pack_first_byte_secs` is `0`, the configured timeout already
forces upstream short-circuiting and the SLO policy is not considered.

`slo_policy.min_sample_count` is the minimum historical sample count needed
before historical latency can change admission behavior. Below this count,
forgeproxy still uses live in-request elapsed estimates, but not historical
aggregate latency.

`slo_policy.near_miss_grace_fraction` is the fraction of the SLO that may be
added as near-miss grace. With a 5-second first-byte SLO and `0.10`, the
fractional grace is 0.5 seconds.

`slo_policy.near_miss_grace_secs` is the absolute near-miss grace. Forgeproxy
uses the larger of fractional and absolute grace. With the defaults, a
5-second first-byte SLO allows up to 8 seconds for historically near-miss local
service.

`slo_policy.early_abort_overrun_fraction` controls when a historical estimate
is considered too far beyond the SLO to keep the client waiting locally. With a
5-second SLO, 3-second grace, and `0.25`, estimates above 9.25 seconds are
allowed to proxy upstream immediately instead of waiting for the local first
byte timeout.

For local upload-pack first-byte admission, forgeproxy uses per-repository
observations only. A repository with no local history uses the live in-request
estimate until per-repository samples have accumulated. The policy extends a
near-miss timeout only within the remaining request budget, and it can return a
zero-duration timeout when historical evidence says the local path is very
unlikely to satisfy the flexible SLO window.

Flexible SLO admission uses aggregate historical first-byte estimates to decide
whether a request should keep waiting locally or proxy upstream early. The
stage-aware TTFB estimator is used by `demand_resource` after observations
arrive to decide which resources or wait budgets should change for future
requests.

Historical first-byte estimates are blended with the in-flight request estimate
as a weighted average biased toward the current request. The live estimate
includes elapsed time in the current TTFB stage plus weighted historical
expectations for the current and remaining stages, so a slow
`local_upload_pack_first_byte_wait` is not hidden by already-completed fast
stages. If the configured first-byte wait is longer than the early-abort
elapsed deadline, the live request is allowed to continue only until that
deadline; a first byte before then is served locally, and no first byte by then
falls back upstream.

Request shape also affects that weighting. Shallow fetches, partial clones with
`filter` requests such as blobless or treeless clones, and single-tip requests
are treated as narrow requests. For those requests, forgeproxy uses the live
request estimate rather than assuming the repository's full-clone history
applies. Unknown request metadata keeps normal historical weighting, so parser
failures do not accidentally erase useful history.

### Deferred: Multi-Instance Historical Observations

Production currently runs a single `forgeproxy` instance, so the SLO admission
estimator intentionally uses local in-process historical observations:

- per-repository first-byte latency totals
- per-repository TTFB stage totals
- live elapsed/request estimates for repositories without local history

Valkey currently stores adaptive recommendation outputs and audit observation
envelopes, but not the raw per-repository stage history that feeds
`ttfb_stage_estimate_for_repo`. In a future multi-instance deployment, a new or
lightly used instance could therefore start with the right adaptive policy
recommendation but still have cold per-stage SLO estimates until it observes
local traffic.

Future work should persist compact historical estimator inputs to Valkey and
merge them with local observations. A conservative design should:

- store per-repository TTFB stage EWMA or bounded totals, not unbounded raw
  samples
- include sample count, updated-at timestamp, source instance id, and controller
  schema version
- apply TTL and max-staleness checks before using shared history
- prefer local recent observations over shared stale observations
- fall back to instance-global history and then live elapsed-only estimates when
  shared repo history is missing
- avoid making request admission depend on a synchronous Valkey read in the hot
  path; refresh shared estimates in the background or cache them locally

The goal is cross-instance estimator consistency, not distributed consensus for
every request. Valkey should provide bounded, stale-safe prior history so an
instance can make reasonable SLO admission decisions before its local per-repo
sample window is warm.

## Resource Pressure

```yaml
adaptive_tuning:
  resource_pressure:
    cpu_busy_high_watermark: 0.85
    disk_busy_high_watermark: 0.85
    memory_available_min_percent: 10.0
```

`cpu_busy_high_watermark` is the sampled CPU busy fraction at or above which the
host is considered CPU pressured.

`disk_busy_high_watermark` is the sampled disk busy fraction at or above which
the host is considered disk pressured.

`memory_available_min_percent` is the minimum acceptable available memory
percentage. Values below this indicate memory pressure.

`aimd` reduces work when sampled CPU, disk, or memory pressure exceeds these
watermarks. `demand_resource` evaluates the same CPU, disk, and memory
watermarks on each demand event. CPU and disk pressure are sampled over a short
point window, while memory is read directly from cgroup or host memory state.

## Bounds

Every tunable runtime value has:

```yaml
{ min: 1, max: 16, max_increase_step: 1, max_decrease_step: 2 }
```

`min` is the lower runtime limit.

`max` is the upper runtime limit.

`max_increase_step` is the maximum single-step increase used by the `aimd`
controller and fallback-recovery helpers.

`max_decrease_step` is the maximum single-step decrease used by the `aimd`
controller and wait-budget tightening helpers.

`demand_resource` always respects `min` and `max`. It uses step sizes only when
it delegates to existing fallback/wait recovery helpers; demand-derived
concurrency and thread values are otherwise computed directly from active claims
and host headroom.

### Global Host Concurrency

`upstream_clone_concurrency` limits concurrent full clone hydrations against the
upstream forge on this host.

`upstream_fetch_concurrency` limits concurrent upstream fetches on this host.
Lower-priority fetches may additionally be limited by reserved request-time
fetch capacity.

`tee_capture_concurrency` limits simultaneous tee capture/import work on this
host.

`local_upload_pack_concurrency` limits simultaneous local `git upload-pack`
processes on this host.

`deep_validation_concurrency` limits background `git fsck --connectivity-only`
validation work.

`prewarm_concurrency` limits startup/background repository prewarm work.

`bundle_generation_concurrency` limits concurrent CPU-heavy bundle, bitmap, and
MIDX generation work.

`pack_cache_request_delta_concurrency` limits request-time pack-cache delta
generation.

`pack_cache_background_warming_concurrency` limits background pack-cache warming
work.

### Per-Repository Concurrency

`upstream_clone_per_repo_per_instance` limits concurrent upstream clone
hydrations for one repository on this host.

`upstream_clone_per_repo_across_instances` limits concurrent upstream clone
hydrations for one repository across the deployment, coordinated through Valkey.

`tee_capture_per_repo` limits tee capture/import concurrency for one repository
on this host.

`local_upload_pack_per_repo` limits concurrent local `git upload-pack` processes
for one repository on this host.

### Git Subprocess Threads

`bundle_pack_threads` is passed as `pack.threads` to `git bundle create` and
related bundle/MIDX work.

`local_upload_pack_threads` is passed as `pack.threads` to local
`git upload-pack`.

`index_pack_threads` is passed to `git index-pack` for request-adjacent pack
imports and pack-cache indexing.

For thread knobs, high maxima are useful only if the selected controller can
spread the CPU budget across current and likely-near-term work. With
`demand_resource`, a high max allows large operations to use more CPU when the
host is quiet, while the controller still avoids assigning the whole provisioned
CPU budget to the first operation.

### Wait Budgets

`request_wait_for_local_catch_up_secs` is the request-path patience budget for
waiting on local catch-up before proxying upstream.

`request_time_s3_restore_secs` is the request-path budget for restoring local
state or artifacts from S3.

`generation_publish_secs` is the request-path budget for publishing a refreshed
local generation.

`local_upload_pack_first_byte_secs` is the budget for local upload-pack to
produce its first response bytes before falling back. An effective value of `0`
immediately falls back upstream and bypasses flexible SLO admission.

Wait budgets should be treated as best-effort SLO exception limits. Increasing
them may reduce upstream proxying but can make clients wait longer. Decreasing
them improves client responsiveness when the local path is unlikely to finish
soon.

## Terraform

Terraform passes `var.adaptive_tuning` directly into `config.yaml`:

```hcl
adaptive_tuning = {
  enabled                  = true
  mode                     = "shadow"
  controller               = "demand_resource"
  slo = {
    clone_latency_secs      = 30.0
    first_byte_latency_secs = 5.0
    fallback_rate           = 0.05
  }
  slo_policy = {
    enabled                       = true
    min_sample_count              = 5
    near_miss_grace_fraction      = 0.10
    near_miss_grace_secs          = 3.0
    early_abort_overrun_fraction  = 0.25
  }
  resource_pressure = {
    cpu_busy_high_watermark      = 0.85
    disk_busy_high_watermark     = 0.85
    memory_available_min_percent = 10.0
  }
  demand_resource = {
    cpu_provisioning_fraction          = 1.5
    cpu_provisioning_fraction_when_memory_constrained = 0.5
  }
  bounds = {
    bundle_pack_threads = {
      min               = 1
      max               = 16
      max_increase_step = 1
      max_decrease_step = 2
    }
  }
}
```

For rollout, start with `mode = "shadow"` and compare:

- `forgeproxy_adaptive_recommended_value`
- `forgeproxy_adaptive_effective_value`
- `forgeproxy_adaptive_shadow_delta`
- `forgeproxy_upload_pack_ttfb_stage_seconds`
- fallback counters by reason
- clone and first-byte latency distributions

Move to `mode = "active"` only after the selected controller recommends values
that match the host shape and observed request behavior.
