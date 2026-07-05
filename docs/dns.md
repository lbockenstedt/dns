# dns — DNS (Unbound)

DNS spoke managing a local Unbound resolver. Repo: `dns`. `module_type = "dns"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

Manages a local **Unbound** resolver via the `unbound-control` CLI. Minimal repo — no installer, no API_SPEC, no README.

## Entrypoints

`python3 -m src.main` (`DNSControlPlane`); spoke `DNSSpoke(BaseSpoke)`. **No install script** in this repo.

## Ports / backends

Manages **Unbound** via `UnboundManager` (`src/unbound_manager.py`): writes managed records to a **persisted** conf.d file (`/etc/unbound/conf.d/lm-netbox.conf`, `unbound_conf` config key) and reloads via `unbound-control` — records survive an Unbound reload/restart. Commands: `DNS_SYNC`, `DNS_LIST`, `DNS_ADD`, `DNS_DELETE`, `DNS_STATUS`. No port served. **Reconciled** to the agent-role (`lm/dns`) implementation so the standalone-install and agent-role paths behave identically (previously this repo used an ephemeral `unbound-control local_data` `DNSManager`).

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`, `UNBOUND_CONTROL` (default `unbound-control`).

## Install flags

None (no installer present).

## Key commands / handlers (`dns_spoke.handle_command`)

`GET_VERSION`, `UPDATE_CONFIG` (rebuild manager), `DNS_STATUS`, `DNS_LIST` (parses `list_local_data` lines `<name> <ttl> IN <type> <value>`), `DNS_ADD` (`local_data`), `DNS_DELETE` (`local_data_remove`), `DNS_UPDATE` (delete-then-add, non-atomic), `DNS_SYNC` (`sync_records` — only-add-missing against existing names, added/skipped counts).

## Key files

`src/main.py`, `src/dns_spoke.py`, `src/unbound_manager.py`, `src/__init__.py` (empty), `.env.template`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- Records normalized with FQDN trailing-dot on add/remove.
- `list_records` swallows `list_local_data` failure and returns `[]`.
- `DNS_UPDATE` is delete-then-add (non-atomic).
- Backend is **Unbound** (not dnsmasq) — confirmed by `unbound-control` + `list_local_data`/`local_data` verbs.

## Related pages

[architecture-topology.md](architecture-topology.md), [install-flags.md](install-flags.md).