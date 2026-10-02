# swal-mesh-signaling

Self-hosted WebRTC signaling relay for the SWAL mesh (option 3 in `MESH.md`): a Cloudflare Worker
routing `wss://mesh.swal.network/r/<rid>` to one Durable Object (`MeshRoom`) per room, using the
WebSocket Hibernation API. Protocol: [`docs/SIGNALING-PROTOCOL.md`](../../docs/SIGNALING-PROTOCOL.md).

Design: pure relay, no storage of any kind (no KV, no DO storage, no alarms), state only in socket
attachments. Idle rooms are hibernated and cost nothing. Limits: 16 peers, 16 KB messages,
per-connection token bucket, `p_` pairing rooms (2 peers, 5 min, 10 signals, no token).

## Develop

```sh
pnpm install --ignore-workspace
pnpm test            # vitest + @cloudflare/vitest-pool-workers
pnpm typecheck
pnpm deploy:dry      # wrangler deploy --dry-run, deploys nothing
```

Deploy (manual, not done yet): `wrangler secret put MESH_ENTITLEMENT_SECRET`, uncomment the route
in `wrangler.toml`, then `wrangler deploy`. Durable Objects need the Workers Free plan at least
(SQLite-backed class, migration `v1`).

## Cost estimate

Billing units (check current Cloudflare pricing before relying on these): Worker requests; DO
requests, where each incoming WebSocket message counts as 1/20 of a request; DO duration in GB-s
(128 MB), which does not accrue while hibernated. Plans: Free = 100k requests/day and 13k GB-s/day
for DOs; Paid ($5/mo) = 1M DO requests/mo and 400k GB-s/mo included, then $0.15/M requests and
$12.50/M GB-s.

Assumed session: 3 devices in a room, 3 upgrades + about 150 signaling messages (SDP/ICE and
re-announces), awake roughly 5 s in total.

- Requests: 3 upgrades + 3 Worker requests + 150/20 = about 14 billed DO requests per session.
- Duration: 5 s x 0.128 GB = about 0.64 GB-s per session (hibernation covers the idle time).
- 1,000 sessions/day: about 14k DO requests/day and 640 GB-s/day, inside the Free plan (100k, 13k).
- 10,000 sessions/day: about 140k requests/day (above Free) -> Paid: 4.2M/mo, 3.2M billed, about
  $0.48/mo; 192k GB-s/mo, inside the included 400k. Total about $5.5/mo including the base fee.
- Pairing rooms are capped at 10 signals, so abuse there costs at most a few requests per room.
