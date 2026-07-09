import asyncio
import logging
from typing import Any, Dict

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

try:
    from unbound_manager import UnboundManager
except ImportError:  # loaded as a package (src.X) by the sibling entrypoint
    from src.unbound_manager import UnboundManager

logger = logging.getLogger("DNSSpoke")


class DNSSpoke(BaseSpoke):
    """
    Unbound DNS spoke.

    Syncs DNS records from NetBox and exposes CRUD for individual records.
    Records are written to /etc/unbound/conf.d/lm-netbox.conf and Unbound
    is reloaded after every write.

    Commands:
      GET_VERSION       — spoke/version string
      DNS_SYNC          — replace all managed records (list of record dicts)
      DNS_LIST          — return all managed records (parsed from the conf file)
      DNS_ADD           — add a single record (A/AAAA auto-write a PTR companion)
      DNS_UPDATE        — replace first record matching name+type (delete-then-add)
      DNS_DELETE        — delete a record by name (+ optional type)
      DNS_STATUS        — Unbound process status + record count
      DNS_STATS         — unbound-control stats_noreset counters for the WebUI
      DNS_FORWARDERS    — unbound-control list_forwards upstream resolvers
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        conf_path = config.get("unbound_conf", "/etc/unbound/conf.d/lm-netbox.conf")
        self.mgr = UnboundManager(conf_path=conf_path)

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a hub command to the Unbound manager.

        Every ``UnboundManager`` call is offloaded to a worker thread via
        ``asyncio.to_thread``: ``unbound-control`` is a sync subprocess and this
        role shares one event loop with the dhcp + base role sub-spokes, so a
        hung reload/status would otherwise block every in-flight request across
        all three sub-spokes.
        """
        cmd = command_type.upper()

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        # UnboundManager does sync subprocess.run (unbound-control reload/status/
        # stats_noreset/list_forwards, 5-10s timeouts) + sync conf writes. This
        # role runs on the lm-svcs agent's ONE shared event loop alongside the
        # dhcp + base role sub-spokes; a hung unbound-control reload blocks the
        # whole loop and the hub's 5s request_response fires for every in-flight
        # request across all three sub-spokes at once. Offload each mgr call to a
        # worker thread so the loop keeps servicing the other roles + the hub link.
        if cmd == "DNS_SYNC":
            records = data.get("records", [])
            return await asyncio.to_thread(self.mgr.sync, records)

        if cmd == "DNS_LIST":
            records = await asyncio.to_thread(self.mgr.list_records)
            return {"status": "SUCCESS", "records": records}

        if cmd == "DNS_ADD":
            name  = data.get("name")
            rtype = data.get("type", "A")
            value = data.get("value")
            ttl   = int(data.get("ttl", 300))
            if not name or not value:
                return {"status": "ERROR", "message": "name and value are required"}
            return await asyncio.to_thread(self.mgr.add_record, name, rtype, value, ttl)

        if cmd == "DNS_UPDATE":
            name  = data.get("name")
            rtype = data.get("type", "A")
            value = data.get("value")
            ttl   = int(data.get("ttl", 300))
            if not name or not value:
                return {"status": "ERROR", "message": "name and value are required"}
            return await asyncio.to_thread(self.mgr.update_record, name, rtype, value, ttl)

        if cmd == "DNS_DELETE":
            name  = data.get("name")
            rtype = data.get("type")
            if not name:
                return {"status": "ERROR", "message": "name is required"}
            return await asyncio.to_thread(self.mgr.delete_record, name, rtype)

        if cmd == "DNS_STATUS":
            s = await asyncio.to_thread(self.mgr.status)
            return {"status": "SUCCESS", **s}

        if cmd == "DNS_STATS":
            return await asyncio.to_thread(self.mgr.get_stats)

        if cmd == "DNS_FORWARDERS":
            return await asyncio.to_thread(self.mgr.list_forwarders)

        return {"status": "ERROR", "error": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        # Polled by the hub for telemetry — offload the sync unbound-control
        # status subprocess off the shared loop (same reason as handle_command).
        s = await asyncio.to_thread(self.mgr.status)
        return {
            "spoke_id":     self.spoke_id,
            "module":       "dns",
            "unbound":      "running" if s["running"] else "stopped",
            "record_count": s["record_count"],
            "status":       "HEALTHY" if s["running"] else "DEGRADED",
        }

    def get_version(self) -> str:
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
