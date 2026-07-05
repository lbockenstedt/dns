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
      DNS_SYNC          — replace all managed records (list of record dicts)
      DNS_LIST          — return all managed records
      DNS_ADD           — add a single record
      DNS_DELETE        — delete a record by name (+ optional type)
      DNS_STATUS        — Unbound process status + record count
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        conf_path = config.get("unbound_conf", "/etc/unbound/conf.d/lm-netbox.conf")
        self.mgr = UnboundManager(conf_path=conf_path)

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        cmd = command_type.upper()

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "DNS_SYNC":
            records = data.get("records", [])
            return self.mgr.sync(records)

        if cmd == "DNS_LIST":
            return {"status": "SUCCESS", "records": self.mgr.list_records()}

        if cmd == "DNS_ADD":
            name  = data.get("name")
            rtype = data.get("type", "A")
            value = data.get("value")
            ttl   = int(data.get("ttl", 300))
            if not name or not value:
                return {"status": "ERROR", "message": "name and value are required"}
            return self.mgr.add_record(name, rtype, value, ttl)

        if cmd == "DNS_UPDATE":
            name  = data.get("name")
            rtype = data.get("type", "A")
            value = data.get("value")
            ttl   = int(data.get("ttl", 300))
            if not name or not value:
                return {"status": "ERROR", "message": "name and value are required"}
            return self.mgr.update_record(name, rtype, value, ttl)

        if cmd == "DNS_DELETE":
            name  = data.get("name")
            rtype = data.get("type")
            if not name:
                return {"status": "ERROR", "message": "name is required"}
            return self.mgr.delete_record(name, rtype)

        if cmd == "DNS_STATUS":
            return {"status": "SUCCESS", **self.mgr.status()}

        return {"status": "ERROR", "error": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        s = self.mgr.status()
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
