import asyncio
import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger("DNSManager")


class DNSManager:
    """Manages Unbound DNS via the unbound-control CLI."""

    def __init__(self, unbound_control: str = "unbound-control"):
        self.ctl = unbound_control

    async def _run(self, *args: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            self.ctl, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        if proc.returncode != 0:
            raise RuntimeError(stderr.decode().strip() or f"{self.ctl} exited {proc.returncode}")
        return stdout.decode().strip()

    async def status(self) -> Dict[str, Any]:
        try:
            out = await self._run("status")
            return {"status": "HEALTHY", "detail": out.splitlines()[0] if out else "running"}
        except Exception as e:
            return {"status": "UNHEALTHY", "error": str(e)}

    async def list_records(self) -> List[Dict[str, Any]]:
        """Parse `unbound-control list_local_data` output."""
        try:
            out = await self._run("list_local_data")
        except Exception as e:
            logger.warning(f"list_local_data failed: {e}")
            return []
        records = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: <name> <ttl> IN <type> <value>
            parts = line.split()
            if len(parts) >= 5 and parts[2].upper() == "IN":
                records.append({
                    "name":  parts[0].rstrip("."),
                    "ttl":   int(parts[1]) if parts[1].isdigit() else 300,
                    "type":  parts[3].upper(),
                    "value": " ".join(parts[4:]),
                })
        return records

    async def add_record(self, name: str, rtype: str, value: str, ttl: int = 300) -> Dict:
        fqdn = name if name.endswith(".") else name + "."
        entry = f"{fqdn} {ttl} IN {rtype.upper()} {value}"
        try:
            await self._run("local_data", entry)
            return {"status": "SUCCESS", "message": f"Added {rtype} record for {name}"}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    async def delete_record(self, name: str) -> Dict:
        fqdn = name if name.endswith(".") else name + "."
        try:
            await self._run("local_data_remove", fqdn)
            return {"status": "SUCCESS", "message": f"Removed record for {name}"}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    async def sync_records(self, records: List[Dict]) -> Dict:
        """Add all records that don't already exist; skip duplicates."""
        try:
            existing = {r["name"] for r in await self.list_records()}
        except Exception:
            existing = set()
        added, skipped = 0, 0
        for rec in records:
            name = rec.get("name", "")
            if not name:
                skipped += 1
                continue
            if name in existing:
                skipped += 1
                continue
            result = await self.add_record(
                name,
                rec.get("type", "A"),
                rec.get("value", ""),
                rec.get("ttl", 300),
            )
            if result.get("status") == "SUCCESS":
                added += 1
            else:
                skipped += 1
                logger.warning(f"Sync failed for {name}: {result.get('message')}")
        return {"status": "SUCCESS", "added": added, "skipped": skipped}
