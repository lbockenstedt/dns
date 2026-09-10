---
summary: "DNS management spoke coordinating one or more Unbound resolver workers. Repo: dns. moduletype = 'dns'."
keywords: [auto, backends, behaviors, dns, dns_delete, dns_forwarders, dns_update, list_forwards, lm, stats_noreset]
---

# dns — DNS (Unbound)

DNS management spoke coordinating Unbound resolvers. Repo: `dns`. `module_type = "dns"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

The `dns` role is management-only and does not install, start, or invoke a local Unbound service. Resolver workers are deployed separately with the `dns-server` role. Load both roles when management and a resolver intentionally share one host.

## What it does

The `dns` module manages DNS records across one or more **Unbound** resolver workers and shows their query statistics and configured upstream forwarders. Records are simple name/type/value entries (A/AAAA get an automatic PTR companion; CNAME and PTR are also supported) — add one by hand, or let it fill in automatically from NetBox. Global Admins can add persistent per-zone forwarders from the **Forwarders** tab; the change is applied to every resolver worker.

In the WebUI, open a node's **DNS** module from the sidebar to reach the **Records**, **Statistics**, **Diagnostics**, and **Forwarders** tabs — see the [WebUI](#webui) section below for what each tab shows.

## Entrypoints

`python3 -m src.main` (`DNSControlPlane`); spoke `DNSSpoke(BaseSpoke)`. `install_dns.sh` performs Unbound host prep for direct installs and `dns-server`; the agent `dns` role loader installs only management dependencies.

> **Primarily a role now.** DNS runs mainly as the **`dns`** role hosted by the agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a management-only sub-spoke `{agent}-dns` (module_type `dns`, parent-auto-approved). Load `dns-server` separately on each resolver worker; load both roles when the coordinator and resolver intentionally share one host. `install_dns.sh` can create a direct local deployment when needed. Config comes from the hub push (WebUI), not a per-module `.env`.

## Ports / backends

DNS Management talks to DNS Server workers over its verified TLS listener on port **8769**. Each worker invokes local `unbound-control` (`status`, `stats_noreset`, `list_forwards`, `reload`) and manages its own conf.d file; the management host never invokes local Unbound.

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`, `UNBOUND_CONTROL` (default `unbound-control`).

## Install flags

None (no installer present).

## Key commands / handlers (`dns_spoke.handle_command`)

`GET_VERSION`, `UPDATE_CONFIG` (rebuild manager), `DNS_STATUS`, `DNS_DIAGNOSTICS` (service/config/control status, port-53 listeners, configured/local addresses, and loopback/LAN DNS probes; relayed by `GET /api/dns/diagnostics`), `DNS_LIST` (regex-parses `local-data:`/`local-data-ptr:` directives out of the managed conf.d file — `<name>. <ttl> IN <type> <value>`; memoized on the conf file's mtime — NOT `unbound-control list_local_data`), `DNS_ADD` (append to the parsed record list + full conf rewrite + `unbound-control reload`), `DNS_DELETE` (filter out the matching record + full conf rewrite + reload), `DNS_UPDATE` (delete-then-add, non-atomic), `DNS_SYNC` (`sync_records` — only-add-missing against existing names, added/skipped counts), `DNS_STATS` (`get_stats` via `unbound-control stats_noreset` — total queries, cache hit/miss + ratio, recursion latency, uptime, per-type breakdown; relayed by `GET /api/dns/stats`), `DNS_FORWARDERS` (`list_forwarders` via `unbound-control list_forwards` — per-zone upstream servers; relayed by `GET /api/dns/forwarders`), and `DNS_FORWARDER_ADD` (Global-Admin-only persistent forwarding-zone creation; relayed by `POST /api/dns/forwarders`).

## Resolver workers (one or more Unbound hosts, one DNS module)

A DNS module drives **one or more Unbound hosts** and becomes the authoritative owner of the record set. Two or more workers provide redundancy and are kept identical.

**Shape.** One `dns` spoke is the **coordinator**; each resolver host runs an `lm-dns-worker` unit that dials the coordinator's `/ws/agent` listener on **8769** (pxmx 8766 / cs 8767 / hub-self 8768 are taken, so the dns and dhcp roles can be co-loaded on one agent). Workers authenticate with a shared PSK and every frame is HMAC-signed — the same machinery pxmx node-agents use (`core/src/messaging/agent_hosting.py` + `core/src/messaging/service_cluster.py`). Workers are **not** spokes: they never appear in the hub registry and tenant routing stays "one tenant → one coordinator".

**The hop is always encrypted AND verified.** The PSK rides in the first handshake frame, so the coordinator URL defaults to `wss://`, a `ws://` URL to a **remote** host is rejected outright, and — unlike the hub leg — there is **no unverified mode at all**. The installer mints (or accepts) a coordinator certificate at `/etc/lm-dns/tls/`, wires it into the unit as `LM_TLS_CERT`/`LM_TLS_KEY`, and each worker install requires `--ca-cert` (that certificate, pinned as `LM_CLUSTER_CA_CERT`). A configured CA path that does not exist fails closed. `LM_CLUSTER_TLS_CHECK_HOSTNAME=0` relaxes only the SAN match for a self-signed-by-IP coordinator; the trust anchor is still enforced. The listener **refuses to bind** plaintext on `0.0.0.0` (`AGENT_LISTENER_REQUIRE_TLS`): with no cert it leaves the port closed and logs why.

**The worker is not a generic agent.** Its op table is fixed at import: `DNSW_APPLY`, `DNSW_STATE`, `DNSW_STATUS`, `DNSW_DIAGNOSTICS`, `DNSW_STATS`, `DNSW_FORWARDERS`, `DNSW_FORWARDER_ADD`, `DNSW_FORWARDER_REMOVE`, `DNSW_STANDDOWN`. There is no `RUN_COMMAND`, no `WRITE_FILE`, no caller-supplied path or URL. The conf path is fixed at start from local config. Forwarders are per-resolver, so the **Forwarders** tab in cluster mode aggregates `DNSW_FORWARDERS` from every member (tagged with the member it came from) instead of reading the coordinator box's own Unbound, which may not exist. Adds fan out to every member and roll back successful members if any resolver rejects the change.

**Desired state — persisted first, fail closed.** Every write (`DNS_SYNC` / `DNS_ADD` / `DNS_UPDATE` / `DNS_DELETE`) lands in the coordinator's versioned, digested desired state (`/var/lib/lm-dns/desired.json`), which is written to disk **before** anything is fanned out: if the write fails, no worker is touched and the coordinator stays exactly where it was. A desired-state file that exists but cannot be read (or whose digest does not match its own records) **blocks every mutation and the reconcile loop** with an actionable error — starting clean there would silently republish an empty record set to both resolvers. Mutations and reconcile passes are serialized under one lock, so two concurrent changes can never interleave their fan-outs. Once persisted the set is fanned out to every member. Records are **validated before they are versioned** — a name or value containing a quote, newline, whitespace or config punctuation is rejected outright, because Unbound's `local-data: "…"` is quote-delimited and line-oriented and would otherwise accept injected directives. An identical re-sync does not bump the version, so the periodic NetBox loop doesn't make every worker look momentarily stale.

**Convergence needs three facts to agree.** `DNSW_STATE` reports the digest of the managed records on disk (parsed from the conf, with the auto-generated PTR companions folded back out), the digest the worker **confirmed applying** (written only after a successful `unbound-control reload`), and the applied version. A member counts as converged only when all three match the desired set. That distinction matters: a conf write whose reload failed already has the right digest ON DISK while the resolver is still ANSWERING the previous set — the member is reported `pending-reload`, stays degraded, and reconcile re-issues `DNSW_APPLY` until the reload is confirmed. An out-of-band edit shows as `drifted`.

**Partial application is reported as partial.** A commit is `SUCCESS` only when every member confirmed the exact desired digest. A worker records the applied version only after Unbound **confirmed the reload** — `unbound-control reload` failures are propagated (they used to be swallowed with a warning), so a conf file the resolver never picked up shows as drift and is reconciled rather than counted as applied. A member that is offline, errored, *or that answers SUCCESS with a different digest* counts as failed → `PARTIAL` (some applied) or `ERROR` (none did). The module telemetry is `DEGRADED` until the cluster is converged and fully reachable.

**Reconcile.** A 30s loop asks each member what it actually has on disk (`DNSW_STATE`) and re-pushes only to members that drifted. That is also the reconnect path: a resolver that reboots reports a stale/absent version and is brought back automatically. `POST /api/dns/cluster/reconcile` forces a pass.

**Configure it.** Active DNS Server roles installed through LM are discovered and enrolled automatically when an administrator opens the DNS module. The generic agent reports its private local service address; the hub never substitutes the public/NAT source address of the agent's WebSocket. DNS Management mints or reuses the worker credential, hands the public coordinator certificate and ephemeral credential to the server agent over the authenticated control channel, and the agent idempotently installs `lm-dns-worker`. After the worker connects, DNS Management adopts its existing records before allowing any mutation; an explicitly unloaded/disabled DNS Server is never re-enabled by discovery. The discovered server is also added to Setup inventory. Worker ID and Worker Secret are only needed for an external/manual resolver that was not installed as an LM role. DNS → **Diagnostics** → *Configure resolver cluster* remains the advanced direct topology editor.

**Enabling adopts what is already live — and never guesses.** On the first worker configuration, the coordinator seeds its desired state from reachable workers. Every populated worker must agree **exactly**; otherwise enablement aborts with a per-source record count and digest. Adopting the largest set would silently erase every record unique to a smaller one. Until something is committed the reconcile pass skips rather than fanning an empty default out over resolvers that are already answering.

**Enabling is one transaction.** Validate → persist topology → bind the listener → seed → stand down removed members all run under the same lock every record apply takes, and the listener is **awaited**: if it does not actually come up (no cert, port in use) the call returns `ERROR` with the reason and the topology is rolled back, rather than reporting success before an asynchronous failure. A rolled-back change also **restores the previous worker PSK** — overwriting it and then reverting the topology would leave every already-provisioned resolver unable to authenticate against a coordinator whose config no longer reflects the change.

**Each cluster role serves its own certificate.** A generic agent hosting both the dns and dhcp cluster roles gives each listener its own material (`/etc/lm-dns/tls`, `/etc/lm-dhcp/tls`, overridable via `LM_DNS_TLS_CERT`/`LM_DHCP_TLS_CERT`). Provisioning binds it to that role instance and never writes the process environment, so the role that starts first cannot supply the certificate for the other — a worker pinning its own role's cert would then fail to verify.

**Removing a member deconfigures it.** A removed resolver is sent `DNSW_STANDDOWN` (drops its cluster marker; its records are left in place so it keeps answering). A removal that cannot be reached is reported as `PARTIAL` with the node named — never as a clean success. On the resolver itself, `install_dns.sh --stand-down` stops `lm-dns-worker` and clears its marker; it runs **before** the `--hub` check, because a node that no longer belongs to any coordinator has no hub to name. Unloading the `dns-server` deploy role stops the worker too. Then install each resolver host with the same value:

```
sudo bash install_dns.sh --member-id dns-a --coordinator <coordinator-host> --worker-secret <secret>
```

…plus `--ca-cert <coordinator cert>`, which is **required** — the worker verifies the coordinator before sending its secret. That installs Unbound **and** the `lm-dns-worker` unit; it implies `--infra-only` (the module lives on the coordinator, not here). Both the hosted management role and standalone coordinator install create `/etc/lm-dns/tls` and mint a self-signed coordinator certificate when one is absent (standalone installs may override it with `--tls-cert`/`--tls-key`/`--tls-san`). Copy `/etc/lm-dns/tls/coordinator.crt` to each resolver and pass it as `--ca-cert`. One configured worker enables remote management; two or more add redundancy.

**See it.** DNS → **Diagnostics** grows a *Resolver cluster* panel (per-member convergence, applied version + digest, Unbound up/down, last-seen, and the last commit's per-member errors) plus each member's own diagnostics findings. `GET /api/dns/cluster` returns the same report; Settings → Diagnostics carries a one-line summary. A non-admin sees the verdict but not member hostnames, digests or error text.


## NetBox auto-sync (source of truth)

NetBox is the IPAM source of truth. The hub's `DnsDhcpSyncMixin` (`core/src/dns_dhcp_sync.py`) reconciles Unbound to NetBox on a periodic loop (`run_dns_dhcp_sync_loop`, `global_config.dns_dhcp_sync` `{enabled` default true`, interval` default 300s`}`) — an IP given a `dns_name` in NetBox lands in Unbound without pressing **Sync now**. The loop and the on-demand `POST /api/dns/sync` share the same extraction helper (`build_dns_records`), so button and loop never diverge. Only-add-missing (idempotent); skips quietly when NetBox/DNS spokes are offline. Per-run status at `GET /api/dns-dhcp/sync-status`.

## WebUI

Module view tabs: **Records**, **Statistics** (total-queries / cache-hit-ratio / recursion / uptime tiles + queries-by-type breakdown, `GET /api/dns/stats`), **Diagnostics** (live service/config checks, port-53 listener ownership, detected LAN addresses, local query probes, and recommended checks), **Forwarders** (per-zone upstream resolvers, `GET /api/dns/forwarders`), and **External DNS** (internet-facing DNS providers such as HE.NET — appears once an external-DNS spoke is connected; one tile per provider; see [henet.md](henet.md)).

## Key files

`src/main.py`, `src/dns_spoke.py`, `src/unbound_manager.py`, `src/__init__.py` (empty), `.env.template`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- Records normalized with FQDN trailing-dot on add/remove.
- `list_records` swallows any read failure of the managed conf file (missing file, permission denied) and returns `[]` — no error surfaces to the WebUI.
- `DNS_UPDATE` is delete-then-add (non-atomic).
- Backend is **Unbound** (not dnsmasq) — confirmed by the `unbound-control` CLI (`status`/`stats_noreset`/`list_forwards`/`reload`) and the managed `local-data`/`local-data-ptr` conf.d file.

## How it works

- **Where it runs.** Standard path: the **`dns`** role on the agent (unit `lm-agent`) opens a sub-spoke `{agent}-dns` (parent-auto-approved) and loads this repo in-process via `agent_spoke.py::_install_role`. Rare alternative: a hand-rolled `lm-dns` unit running `python3 -m src.main` (`DNSControlPlane`) standalone.
- **Config delivery.** The hub pushes config with `UPDATE_CONFIG` (rebuilds the `UnboundManager` with the configured conf path) — there's no per-module `.env` to hand-edit on the box; `UNBOUND_CONF` env var is only the fallback default before a push arrives.
- **Command flow.** WebUI/hub issues one command at a time over the hub↔spoke session: `GET_VERSION`, `UPDATE_CONFIG`, `DNS_STATUS`, `DNS_LIST`, `DNS_ADD`, `DNS_DELETE`, `DNS_UPDATE`, `DNS_SYNC`, `DNS_STATS`, `DNS_FORWARDERS`.
- **How records are actually written.** `UnboundManager` keeps exactly **one** managed conf.d file (default `/etc/unbound/conf.d/lm-netbox.conf`, overridable). Every add/update/delete/sync:
  1. reads the current managed records back out of that same file (regex-parses `local-data`/`local-data-ptr` lines — this is what `DNS_LIST` returns),
  2. computes the new full record list in memory,
  3. rewrites the whole file in one shot,
  4. runs `unbound-control reload`.
  Because each write is a single full-file rewrite + single reload, there's no window where Unbound serves a half-updated file. But if step 1 can't read the file (missing, permissions), it silently returns `[]` — so an add/update effectively starts from "no records", and a sync can look like it wiped everything when it actually just couldn't see what was already there.
- **Automatic PTR.** Adding/updating an A or AAAA record also writes a matching `local-data-ptr` line, so reverse lookups stay in sync without a separate step.
- **Stats and forwarders bypass the managed file entirely** — `DNS_STATS` shells out to `unbound-control stats_noreset` (non-destructive counters) and `DNS_FORWARDERS` to `unbound-control list_forwards`, both reading live daemon state, not the conf.d file.
- **NetBox auto-sync loop** (see the section above) and the on-demand Sync button both ultimately call `DNS_SYNC` with the same only-add-missing logic via the shared `build_dns_records` helper — an IP only contributes a record when it has *both* a `dns_name` and a concrete address, so they can never diverge or race each other.
- **Stats source in detail.** `DNS_STATS` parses `unbound-control stats_noreset`'s flat `key=value` output into `total_queries`, `cache_hits`/`cache_misses`/`cache_hit_ratio`, `num_recursive`, `recursion_time_avg`, `prefetch`, `uptime_seconds`, plus a per-query-type breakdown — relayed to the WebUI via `GET /api/dns/stats`.
- **Forwarders in detail.** `DNS_FORWARDERS` parses `unbound-control list_forwards` lines (e.g. `. IN forward 8.8.8.8 8.8.4.4`) into a per-zone list of upstream servers — relayed via `GET /api/dns/forwarders`. Global Admins can add a zone with one or more IPv4/IPv6 upstreams through `POST /api/dns/forwarders`; each worker persists it in `/etc/unbound/conf.d/lm-forwarders.conf` and reloads Unbound. A partial cluster write is rolled back.

## How to use it

- **Add a record:** DNS module → **Records** tab → enter name/type/value(/ttl) → submit. `DNS_ADD` rewrites the conf file and reloads Unbound — the record resolves immediately, no restart needed.
- **Edit a record:** use the update action on an existing entry. `DNS_UPDATE` matches by name **+ type**; if you change the type as well as the value it won't match the old entry and instead adds a new one, leaving the old one behind — delete the old type explicitly if you're changing a record's type.
- **Delete a record:** Records tab → delete action. `DNS_DELETE` matches by name (optionally + type) and rewrites without it.
- **Force an immediate NetBox reconcile** instead of waiting for the periodic loop: press **Sync now** on the Records tab (`POST /api/dns/sync` → `DNS_SYNC`). Only adds NetBox-sourced `dns_name` entries missing from Unbound — never removes or touches records you added by hand.
- **Check resolver health:** **Statistics** tab — total queries, cache-hit ratio, recursion latency, uptime tiles, plus per-type breakdown. Useful for spotting cache-hit-ratio drops or clients hammering with retries.
- **Check upstream resolution:** **Forwarders** tab — confirms which upstream resolvers Unbound forwards non-authoritative queries to, per zone.
- **Confirm the module is alive:** the module tile / `DNS_STATUS` should show Unbound `running` plus a non-zero `record_count` if you have records configured.

## Troubleshooting / common questions

- **"I added a record in NetBox but never touched the DNS module — why is it already in Unbound?"** The NetBox → Unbound auto-sync loop (default every 300s) picked it up: any IP with a `dns_name` set gets added automatically — see the NetBox auto-sync section above. Check `GET /api/dns-dhcp/sync-status` for the last run's timing and result, or just press **Sync now** instead of waiting.
- **"I added/edited a record but the Records tab (or `DNS_LIST`) shows nothing at all."** Confirm at least one DNS Server worker is configured and connected in DNS → Diagnostics.
- **"The DNS module shows offline/red in the WebUI."** The `{agent}-dns` sub-spoke isn't connected to the hub. Check the node's `lm-agent` unit first — the `dns` role rides on it and is loaded in-process, so an agent-wide outage takes DNS down with it. A `dns`-only failure independent of the agent is unusual unless this node uses the rare standalone `lm-dhcp`-style hand-rolled `lm-dns` unit.
- **"Records I added by hand disappeared after a sync."** Sync (both the loop and the button) is only-add-missing — it never deletes. If a manually-added record vanished, check whether someone ran an explicit `DNS_UPDATE`/`DNS_DELETE` on it (those are the only paths that touch existing entries), and remember the managed conf.d file is fully regenerated on every write — anything edited directly on the box outside the DNS module (bypassing Lab Manager entirely) will get clobbered on the next write.
- **"Is this dnsmasq or Unbound?"** Unbound — confirmed by the `unbound-control` CLI dependency and the `status`/`stats_noreset`/`list_forwards`/`reload` verbs it actually issues. There is no dnsmasq involved in this module.
- **"Why is `DNS_UPDATE` described as delete-then-add / non-atomic?"** Functionally it replaces the first record matching name+type (dropping duplicates, adding if no match) and then does one rewrite + one reload — so Unbound itself never serves a half-updated file. The "non-atomic" framing refers to the record-list logic (remove old entry, add new one) rather than two separate live `unbound-control` calls.

## Related pages

[architecture-topology.md](architecture-topology.md), [install-flags.md](install-flags.md).