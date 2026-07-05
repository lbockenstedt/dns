import subprocess
import logging
import os
import re
import ipaddress

logger = logging.getLogger("UnboundManager")

LM_CONF = "/etc/unbound/conf.d/lm-netbox.conf"
UNBOUND_CONF_DIR = "/etc/unbound/conf.d"


class UnboundManager:
    def __init__(self, conf_path: str = LM_CONF):
        self.conf_path = conf_path
        os.makedirs(os.path.dirname(self.conf_path), exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────

    def sync(self, records: list) -> dict:
        """
        Replace all LM-managed DNS records with the provided list.

        Each record: {"name": "host.example.com", "type": "A", "value": "10.0.1.5", "ttl": 300}
        Forward (A/AAAA) and reverse (PTR) records are both written.
        """
        lines = ["# Managed by Lab Manager — do not edit manually\n", "server:\n"]
        for r in records:
            name = r.get("name", "").strip().rstrip(".")
            rtype = r.get("type", "A").upper()
            value = r.get("value", "").strip()
            ttl = int(r.get("ttl", 300))
            if not name or not value:
                continue

            if rtype in ("A", "AAAA"):
                lines.append(f'    local-data: "{name}. {ttl} IN {rtype} {value}"\n')
                ptr = self._ptr_name(value)
                if ptr:
                    lines.append(f'    local-data-ptr: "{value} {ttl} {name}."\n')

            elif rtype == "CNAME":
                lines.append(f'    local-data: "{name}. {ttl} IN CNAME {value.rstrip(".")}."\n')

            elif rtype == "PTR":
                lines.append(f'    local-data: "{name}. {ttl} IN PTR {value.rstrip(".")}."\n')

        with open(self.conf_path, "w") as f:
            f.writelines(lines)

        count = len(records)
        self._reload()
        logger.info("Synced %d DNS records to Unbound", count)
        return {"status": "SUCCESS", "records_written": count}

    def list_records(self) -> list:
        """Parse the managed conf file and return records."""
        records = []
        if not os.path.exists(self.conf_path):
            return records
        with open(self.conf_path) as f:
            for line in f:
                line = line.strip()
                m = re.match(r'local-data:\s+"(.+?)\.\s+(\d+)\s+IN\s+(\w+)\s+(.+?)"', line)
                if m:
                    records.append({
                        "name":  m.group(1),
                        "ttl":   int(m.group(2)),
                        "type":  m.group(3),
                        "value": m.group(4),
                    })
                m2 = re.match(r'local-data-ptr:\s+"(\S+)\s+(\d+)\s+(.+?)"', line)
                if m2:
                    records.append({
                        "name":  m2.group(1),
                        "ttl":   int(m2.group(2)),
                        "type":  "PTR",
                        "value": m2.group(3).rstrip("."),
                    })
        return records

    def add_record(self, name: str, rtype: str, value: str, ttl: int = 300) -> dict:
        existing = self.list_records()
        existing.append({"name": name, "type": rtype, "value": value, "ttl": ttl})
        return self.sync(existing)

    def update_record(self, name: str, rtype: str, value: str, ttl: int = 300) -> dict:
        """Replace an existing record's value/ttl (matched by name + type).

        Implemented as a filtered re-sync: the first matching record is swapped
        for the new value/ttl, duplicates are dropped, and any non-matching
        records are preserved. If no match exists the record is added. The
        re-sync regenerates the companion PTR for A/AAAA records automatically.
        """
        existing = self.list_records()
        updated: list = []
        replaced = False
        for r in existing:
            if r["name"] == name and r["type"] == rtype:
                if not replaced:
                    updated.append({"name": name, "type": rtype, "value": value, "ttl": ttl})
                    replaced = True
                # drop duplicate matches
            else:
                updated.append(r)
        if not replaced:
            updated.append({"name": name, "type": rtype, "value": value, "ttl": ttl})
        return self.sync(updated)

    def delete_record(self, name: str, rtype: str = None) -> dict:
        existing = self.list_records()
        filtered = [
            r for r in existing
            if not (r["name"] == name and (rtype is None or r["type"] == rtype))
        ]
        return self.sync(filtered)

    def status(self) -> dict:
        try:
            result = subprocess.run(
                ["unbound-control", "status"],
                capture_output=True, text=True, timeout=5
            )
            running = result.returncode == 0
        except Exception:
            running = False
        return {
            "running":      running,
            "record_count": len(self.list_records()),
            "conf_path":    self.conf_path,
        }

    # ── Helpers ───────────────────────────────────────────────────────

    def _reload(self):
        try:
            subprocess.run(["unbound-control", "reload"], check=True, timeout=10)
            logger.info("Unbound reloaded")
        except Exception as e:
            logger.warning("unbound-control reload failed: %s", e)

    def _ptr_name(self, ip: str) -> str:
        try:
            return ipaddress.ip_address(ip).reverse_pointer
        except ValueError:
            return ""
