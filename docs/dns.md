# dns — DNS (Unbound)

DNS spoke managing a local Unbound resolver. Repo: `dns`. `module_type = "dns"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

Manages a local **Unbound** resolver via the `unbound-control` CLI. Minimal repo — no installer, no API_SPEC, no root README.

## What it does

The `dns` module manages DNS records on this node's local **Unbound** resolver, and shows query statistics and configured upstream forwarders for troubleshooting. Records are simple name/type/value entries (A/AAAA get an automatic PTR companion; CNAME and PTR are also supported) — add one by hand, or let it fill in automatically from NetBox.

In the WebUI, open a node's **DNS** module from the sidebar to reach the **Records**, **Statistics**, and **Forwarders** tabs — see the [WebUI](#webui) section below for what each tab shows.

## Entrypoints

`python3 -m src.main` (`DNSControlPlane`); spoke `DNSSpoke(BaseSpoke)`. **No install script** in this repo.

> **Primarily a role now.** DNS runs mainly as the **`dns`** role hosted by the generic agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a sub-spoke `{agent}-dns` (module type `dns`, parent-auto-approved) and loads it in-process via `agent/src/agent_spoke.py::_install_role` (this repo is bundled in-tree; the role loader also does the Unbound host prep). There is no dedicated `lm-dns` unit — the agent role is the standard path; a hand-rolled unit is the only standalone alternative. Config (`UNBOUND_CONTROL` etc.) comes from the hub push (WebUI), not a per-module `.env`.

## Ports / backends

Talks to **Unbound** via the `unbound-control` CLI subprocess (`UnboundManager`, `src/unbound_manager.py`), 5–10s per-call timeouts. Commands actually invoked: `status`, `stats_noreset`, `list_forwards`, `reload`. Individual records are **not** pushed with live `local_data`/`local_data_remove` verbs — they're written into one managed conf.d file (`local-data`/`local-data-ptr` directives) that's fully rewritten and reloaded on every change (see How it works below). No port served; no HTTP at all (the only spoke with neither httpx nor requests — `requirements.txt` is just `websockets, python-dotenv`).

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`, `UNBOUND_CONTROL` (default `unbound-control`).

## Install flags

None (no installer present).

## Key commands / handlers (`dns_spoke.handle_command`)

`GET_VERSION`, `UPDATE_CONFIG` (rebuild manager), `DNS_STATUS`, `DNS_LIST` (parses `local-data` directives from the managed conf file — `<name> <ttl> IN <type> <value>`), `DNS_ADD` (`local_data`), `DNS_DELETE` (`local_data_remove`), `DNS_UPDATE` (delete-then-add, non-atomic), `DNS_SYNC` (`sync_records` — only-add-missing against existing names, added/skipped counts), `DNS_STATS` (`get_stats` via `unbound-control stats_noreset` — total queries, cache hit/miss + ratio, recursion latency, uptime, per-type breakdown; relayed by `GET /api/dns/stats`), `DNS_FORWARDERS` (`list_forwarders` via `unbound-control list_forwards` — per-zone upstream servers; relayed by `GET /api/dns/forwarders`).

## NetBox auto-sync (source of truth)

NetBox is the IPAM source of truth. The hub's `DnsDhcpSyncMixin` (`core/src/dns_dhcp_sync.py`) reconciles Unbound to NetBox on a periodic loop (`run_dns_dhcp_sync_loop`, `global_config.dns_dhcp_sync` `{enabled` default true`, interval` default 300s`}`) — an IP given a `dns_name` in NetBox lands in Unbound without pressing **Sync now**. The loop and the on-demand `POST /api/dns/sync` share the same extraction helper (`build_dns_records`), so button and loop never diverge. Only-add-missing (idempotent); skips quietly when NetBox/DNS spokes are offline. Per-run status at `GET /api/dns-dhcp/sync-status`.

## WebUI

Module view tabs: **Records**, **Statistics** (total-queries / cache-hit-ratio / recursion / uptime tiles + queries-by-type breakdown, `GET /api/dns/stats`), **Forwarders** (per-zone upstream resolvers, `GET /api/dns/forwarders`).

## Key files

`src/main.py`, `src/dns_spoke.py`, `src/unbound_manager.py`, `src/__init__.py` (empty), `.env.template`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- Records normalized with FQDN trailing-dot on add/remove.
- `list_records` swallows any read failure of the managed conf file (missing file, permission denied) and returns `[]` — no error surfaces to the WebUI.
- `DNS_UPDATE` is delete-then-add (non-atomic).
- Backend is **Unbound** (not dnsmasq) — confirmed by the `unbound-control` CLI (`status`/`stats_noreset`/`list_forwards`/`reload`) and the managed `local-data`/`local-data-ptr` conf.d file.

## How it works

- **Where it runs.** Standard path: the **`dns`** role on the generic agent (unit `lm-agent`) opens a sub-spoke `{agent}-dns` (parent-auto-approved) and loads this repo in-process via `agent_spoke.py::_install_role`. Rare alternative: a hand-rolled `lm-dns` unit running `python3 -m src.main` (`DNSControlPlane`) standalone.
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
- **Forwarders in detail.** `DNS_FORWARDERS` parses `unbound-control list_forwards` lines (e.g. `. IN forward 8.8.8.8 8.8.4.4`) into a per-zone list of upstream servers — relayed via `GET /api/dns/forwarders`.

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
- **"I added/edited a record but the Records tab (or `DNS_LIST`) shows nothing at all."** Check that Unbound is actually running on the node hosting the `dns` role, and that `unbound-control` has permission to talk to it. `list_records` swallows any read failure of the managed conf file (missing file, permission denied, Unbound not started) and just returns an empty list — there's no visible error, the symptom is simply "records list is empty." Run `unbound-control status` directly on the box and confirm the account running the `dns` role can read/write the managed conf path (default `/etc/unbound/conf.d/lm-netbox.conf`, or your `UNBOUND_CONF` override).
- **"The DNS module shows offline/red in the WebUI."** The `{agent}-dns` sub-spoke isn't connected to the hub. Check the node's `lm-agent` unit first — the `dns` role rides on it and is loaded in-process, so an agent-wide outage takes DNS down with it. A `dns`-only failure independent of the agent is unusual unless this node uses the rare standalone hand-rolled `lm-dns` unit.
- **"Records I added by hand disappeared after a sync."** Sync (both the loop and the button) is only-add-missing — it never deletes. If a manually-added record vanished, check whether someone ran an explicit `DNS_UPDATE`/`DNS_DELETE` on it (those are the only paths that touch existing entries), and remember the managed conf.d file is fully regenerated on every write — anything edited directly on the box outside the DNS module (bypassing Lab Manager entirely) will get clobbered on the next write.
- **"Is this dnsmasq or Unbound?"** Unbound — confirmed by the `unbound-control` CLI dependency and the `status`/`stats_noreset`/`list_forwards`/`reload` verbs it actually issues. There is no dnsmasq involved in this module.
- **"Why is `DNS_UPDATE` described as delete-then-add / non-atomic?"** Functionally it replaces the first record matching name+type (dropping duplicates, adding if no match) and then does one rewrite + one reload — so Unbound itself never serves a half-updated file. The "non-atomic" framing refers to the record-list logic (remove old entry, add new one) rather than two separate live `unbound-control` calls.

## Related pages

[architecture-topology.md](architecture-topology.md), [install-flags.md](install-flags.md).