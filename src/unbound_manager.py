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
        # mtime-keyed memo for list_records(): status/add/update/delete all
        # call list_records (some indirectly via sync), and each call re-reads
        # + regex-parses the whole conf. Cache the parsed list keyed on the
        # conf's st_mtime so it's reused until the file changes; sync() writes
        # the file and clears the memo so the next read re-parses.
        self._records_cache = None      # list
        self._records_cache_mtime = None  # float | None

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
        # We just rewrote the conf — drop the parsed-list memo so the next
        # list_records re-reads the new contents rather than returning stale.
        self._records_cache = None
        self._records_cache_mtime = None
        logger.info("Synced %d DNS records to Unbound", count)
        return {"status": "SUCCESS", "records_written": count}

    def list_records(self) -> list:
        """Parse the managed conf file and return records.

        Memoized on the conf file's mtime: a hit (same mtime as last parse)
        returns the cached list without re-reading/re-parsing — status/add/
        update/delete all flow through here, and the conf only changes when
        sync() rewrites it (which clears the memo)."""
        try:
            mtime = os.stat(self.conf_path).st_mtime
        except FileNotFoundError:
            self._records_cache = None
            self._records_cache_mtime = None
            return []
        if self._records_cache is not None and self._records_cache_mtime == mtime:
            return self._records_cache
        records = []
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
        self._records_cache = records
        self._records_cache_mtime = mtime
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

    # ── Statistics & forwarders ───────────────────────────────────────

    def get_stats(self) -> dict:
        """Unbound query statistics via ``unbound-control stats_noreset``.

        Parses the flat ``key=value`` output into headline metrics (total
        queries, cache hit/miss + ratio, recursion latency, uptime) plus a
        per-record-type query breakdown for the UI — the DNS analog of the
        OPNsense resolver stats. ``stats_noreset`` leaves Unbound's counters
        intact so repeated polls don't zero them.
        """
        try:
            result = subprocess.run(
                ["unbound-control", "stats_noreset"],
                capture_output=True, text=True, timeout=8,
            )
            if result.returncode != 0:
                return {"status": "ERROR", "message": result.stderr.strip() or "unbound-control failed"}
        except Exception as e:
            logger.error("get_stats failed: %s", e)
            return {"status": "ERROR", "message": str(e)}

        raw = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                try:
                    raw[k.strip()] = float(v.strip())
                except ValueError:
                    raw[k.strip()] = v.strip()

        def n(key):
            v = raw.get(key, 0)
            return v if isinstance(v, (int, float)) else 0

        hits   = n("total.num.cachehits")
        misses = n("total.num.cachemiss")
        total  = n("total.num.queries")
        hit_ratio = round(hits / total * 100, 1) if total else 0.0

        query_types = {}
        for k, v in raw.items():
            m = re.match(r"num\.query\.type\.(\w+)$", k)
            if m and isinstance(v, (int, float)) and v:
                query_types[m.group(1)] = int(v)

        return {
            "status": "SUCCESS",
            "global": {
                "total_queries":     int(total),
                "cache_hits":        int(hits),
                "cache_misses":      int(misses),
                "cache_hit_ratio":   hit_ratio,
                "num_recursive":     int(n("total.num.recursivereplies")),
                "recursion_time_avg": round(n("total.recursion.time.avg"), 4),
                "prefetch":          int(n("total.num.prefetch")),
                "uptime_seconds":    int(n("time.up")),
            },
            "query_types": query_types,
        }

    def list_forwarders(self) -> dict:
        """Configured upstream forwarders via ``unbound-control list_forwards``.

        Output lines look like ``. IN forward 8.8.8.8 8.8.4.4`` (zone, class,
        ``forward``, then the upstream servers). Normalized to a per-zone list
        of upstreams for the UI's Upstream Servers panel.
        """
        try:
            result = subprocess.run(
                ["unbound-control", "list_forwards"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                return {"status": "ERROR", "message": result.stderr.strip() or "unbound-control failed"}
        except Exception as e:
            logger.error("list_forwarders failed: %s", e)
            return {"status": "ERROR", "message": str(e)}

        forwarders = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "forward":
                forwarders.append({
                    "zone":      parts[0],
                    "class":     parts[1],
                    "upstreams": parts[3:],
                })
        return {"status": "SUCCESS", "forwarders": forwarders}

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
