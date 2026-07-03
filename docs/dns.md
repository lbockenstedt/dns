# dns — DNS (Unbound)

DNS spoke managing a local Unbound resolver. Repo: `dns`. `module_type = "dns"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

Manages a local **Unbound** resolver via the `unbound-control` CLI. Minimal repo — no installer, no API_SPEC, no README.

## Entrypoints

`python3 -m src.main` (`DNSControlPlane`); spoke `DNSSpoke(BaseSpoke)`. **No install script** in this repo.

## Ports / backends

Talks to **Unbound** via the `unbound-control` CLI subprocess (`DNSManager`, `src/dns_manager.py`), 15s timeout. Commands: `status`, `list_local_data`, `local_data <entry>`, `local_data_remove <fqdn>`. No port served; no HTTP at all (the only spoke with neither httpx nor requests — `requirements.txt` is just `websockets, python-dotenv`).

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`, `UNBOUND_CONTROL` (default `unbound-control`).

## Install flags

None (no installer present).

## Key commands / handlers (`dns_spoke.handle_command`)

`GET_VERSION`, `UPDATE_CONFIG` (rebuild manager), `DNS_STATUS`, `DNS_LIST` (parses `list_local_data` lines `<name> <ttl> IN <type> <value>`), `DNS_ADD` (`local_data`), `DNS_DELETE` (`local_data_remove`), `DNS_UPDATE` (delete-then-add, non-atomic), `DNS_SYNC` (`sync_records` — only-add-missing against existing names, added/skipped counts).

## Key files

`src/main.py`, `src/dns_spoke.py`, `src/dns_manager.py`, `src/__init__.py` (empty), `.env.template`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- Records normalized with FQDN trailing-dot on add/remove.
- `list_records` swallows `list_local_data` failure and returns `[]`.
- `DNS_UPDATE` is delete-then-add (non-atomic).
- Backend is **Unbound** (not dnsmasq) — confirmed by `unbound-control` + `list_local_data`/`local_data` verbs.

## Related pages

[architecture-topology.md](architecture-topology.md), [install-flags.md](install-flags.md).