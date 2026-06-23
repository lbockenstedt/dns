import logging
from typing import Any, Dict

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

from .dns_manager import DNSManager

logger = logging.getLogger("DNSSpoke")


class DNSSpoke(BaseSpoke):
    """Unbound DNS integration spoke."""

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        self.manager = DNSManager(
            unbound_control=config.get("UNBOUND_CONTROL", "unbound-control")
        )

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        cmd = command_type.upper()

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "UPDATE_CONFIG":
            self.config = data
            self.manager = DNSManager(
                unbound_control=self.config.get("UNBOUND_CONTROL", "unbound-control")
            )
            return {"status": "SUCCESS", "message": "DNS config updated"}

        if cmd == "DNS_STATUS":
            return await self.manager.status()

        if cmd == "DNS_LIST":
            try:
                records = await self.manager.list_records()
                return {"status": "SUCCESS", "records": records}
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        if cmd == "DNS_ADD":
            name  = data.get("name")
            rtype = data.get("type", "A")
            value = data.get("value")
            ttl   = data.get("ttl", 300)
            if not name or not value:
                return {"status": "ERROR", "message": "name and value are required"}
            return await self.manager.add_record(name, rtype, value, ttl)

        if cmd == "DNS_DELETE":
            name = data.get("name")
            if not name:
                return {"status": "ERROR", "message": "name is required"}
            return await self.manager.delete_record(name)

        if cmd == "DNS_UPDATE":
            name  = data.get("name")
            rtype = data.get("type", "A")
            value = data.get("value")
            ttl   = data.get("ttl", 300)
            if not name or not value:
                return {"status": "ERROR", "message": "name and value are required"}
            await self.manager.delete_record(name)
            return await self.manager.add_record(name, rtype, value, ttl)

        if cmd == "DNS_SYNC":
            records = data.get("records", [])
            try:
                return await self.manager.sync_records(records)
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        logger.warning(f"Unknown command: {command_type}")
        return {"status": "ERROR", "message": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        return await self.manager.status()

    def get_version(self) -> str:
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
