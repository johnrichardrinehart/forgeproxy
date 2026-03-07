# Consolidation Locking Goal

## Problem

`forgeproxy` currently coordinates per-repo background fetch and incremental
bundle generation with a distributed Valkey lock, but daily and weekly bundle
consolidation do not have equivalent cross-node coordination.

In a multi-instance deployment, that means more than one `forgeproxy` node can:

- scan the same repo for daily consolidation
- generate the same full daily bundle
- upload competing consolidated bundles to S3
- race to update the Valkey metadata that points at the "latest" daily/base bundle

This is mostly wasteful rather than immediately corrupting, but it is not the
intended coordination model.

## Goal

For any given repository and consolidation window, at most one `forgeproxy`
instance should perform the consolidation work.

That means:

- only one node should run daily consolidation for `owner/repo` at a time
- only one node should run weekly/base consolidation for `owner/repo` at a time
- other nodes should observe the lock and skip the work

## Required Properties

The locking design should provide:

- per-repo granularity
- distributed coordination through shared state already available to the fleet
  (Valkey)
- TTL-based recovery if a consolidating node dies
- idempotent skip behavior for losing nodes
- no requirement for global leader election

## Preferred Shape

Use dedicated Valkey locks, separate from the existing fetch/incremental bundle
lock, for example:

- `forgeproxy:lock:daily-consolidation:<owner_repo>`
- `forgeproxy:lock:weekly-consolidation:<owner_repo>`

Recommended behavior:

1. Node decides a repo is eligible for daily or weekly consolidation.
2. Node attempts to acquire the corresponding distributed lock with a TTL.
3. If lock acquisition fails, the node skips that repo.
4. If lock acquisition succeeds, the node performs consolidation.
5. On success or failure, the node releases the lock.
6. If the node crashes, the TTL eventually frees the lock for a later attempt.

## Scope Boundary

This goal is only about coordinating the consolidation jobs themselves.

It does not require:

- changing the local generation-publish model
- changing request-path cache serving
- changing the external scrubber
- deleting superseded S3 bundles as part of lock acquisition

## Non-Goal

This does not aim to guarantee that only one node in the entire fleet runs the
consolidation scheduler loop. The intent is narrower:

- many nodes may wake up and evaluate the schedule
- only one node should do the actual per-repo daily/weekly consolidation work

## Expected Result

After this is implemented, multi-instance `forgeproxy` deployments should avoid
duplicate daily/weekly bundle generation and metadata races, while keeping the
existing distributed, per-repo execution model.
