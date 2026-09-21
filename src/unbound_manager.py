import subprocess
import logging
import os
import re
import ipaddress
import socket
import struct
import time

logger = logging.getLogger("UnboundManager")

LM_CONF = "/etc/unbound/conf.d/lm-netbox.conf"
UNBOUND_CONF_DIR = "/etc/unbound/conf.d"
LOGGING_CONF = "/etc/unbound/conf.d/lm-logging.conf"
MAIN_CONF = "/etc/unbound/unbound.conf"
BRIDGE_CONF_NAME = "lm-include.conf"
QUERY_LOG = "/var/log/unbound/lm-queries.log"

MAX_TRACKED_NAMES = 5000
TOP_NAMES_LIMIT = 200

_QUERY_LOG_RE = re.compile(
    r"info:\s+(?P<ip>[0-9a-fA-F.:]+)\s+(?P<name>\S+?)\.?\s+(?P<type>\w+)\s+IN\s*$"
)


class UnboundManager:
    def __init__(self, conf_path: str = LM_CONF):
        self.conf_path = conf_path
        self.forwarders_path = os.path.join(
            os.path.dirname(self.conf_path), "lm-forwarders.conf")
        os.makedirs(os.path.dirname(self.conf_path), exist_ok=True)
        self._ensure_conf_included()

        self._query_counts = {}
        self._query_log_offset = 0
        self._query_log_inode = None

    def _ensure_conf_included(self) -> dict:
        """Guarantee Unbound actually PARSES the directory we write into."""
        conf_dir = os.path.dirname(self.conf_path)
        try:
            with open(MAIN_CONF) as fh:
                main_text = fh.read()
        except OSError as e:
            logger.debug("unbound include check: cannot read %s: %s", MAIN_CONF, e)
            return {"ok": False, "reason": "main conf unreadable"}

        include_globs = re.findall(
            r'^\s*include(?:-toplevel)?:\s*"?([^"\s]+)"?', main_text, re.M)

        def _covers(glob_path):
            return os.path.dirname(glob_path.rstrip()) == conf_dir.rstrip("/")

        if any(_covers(g) for g in include_globs):
            return {"ok": True, "action": "already-included"}

        bridge_dirs = [os.path.dirname(g) for g in include_globs
                       if os.path.isdir(os.path.dirname(g))]
        for d in bridge_dirs:
            try:
                for name in os.listdir(d):
                    if not name.endswith(".conf"):
                        continue
                    with open(os.path.join(d, name)) as fh:
                        if any(_covers(g) for g in re.findall(
                                r'^\s*include(?:-toplevel)?:\s*"?([^"\s]+)"?',
                                fh.read(), re.M)):
                            return {"ok": True, "action": "already-bridged"}
            except OSError:
                continue

        if not bridge_dirs:
            logger.warning(
                 "unbound: %s includes no directory we can bridge into; managed "
                 "config in %s may not be loaded", MAIN_CONF, conf_dir)
            return {"ok": False, "reason": "no include dir"}

        bridge = os.path.join(bridge_dirs[0], BRIDGE_CONF_NAME)
        try:
            with open(bridge, "w") as fh:
                fh.write("# Managed by Lab Manager — do not edit manually\n"
                          "# Bridges LM's managed config dir into Unbound, which\n"
                          "# otherwise only parses this directory.\n"
                          'include-toplevel: "%s/*.conf"\n' % conf_dir.rstrip("/"))
        except OSError as e:
            logger.warning("unbound: could not write include bridge %s: %s", bridge, e)
            return {"ok": False, "reason": str(e)}
        logger.warning("unbound: wrote include bridge %s so %s is actually parsed",
                       bridge, conf_dir)
        return {"ok": True, "action": "bridged", "path": bridge}

    def sync(self, records: list) -> dict:
        """Replace all LM-managed DNS records with the provided list."""
        lines = ["# Managed by Lab Manager — do not edit manually\n", "server:\n"]
        count = 0
        for r in records:
            name = r.get("name", "").strip().rstrip(".")
            rtype = r.get("type", "A").upper()
            value = r.get("value", "").strip()
            ttl = int(r.get("ttl", 300))
            if not name or not value:
                continue

            if rtype in ("A", "AAAA"):
                lines.append(f'    local-data: "{name}. {ttl} IN {rtype} {value}"\n')
                count += 1
                ptr = self._ptr_name(value)
                if ptr:
                    lines.append(f'    local-data-ptr: "{value} {ttl} {name}."\n')
                    count += 1

            elif rtype == "CNAME":
                lines.append(f'    local-data: "{name}. {ttl} IN CNAME {value.rstrip(".")}."\n')
                count += 1

            elif rtype == "PTR":
                lines.append(f'    local-data: "{name}. {ttl} IN PTR {value.rstrip(".")}."\n')
                count += 1

        with open(self.conf_path, "w") as f:
            f.writelines(lines)

        reload_result = self._reload()
        if not reload_result["ok"]:
            logger.error("Wrote %d DNS records but unbound-control reload failed: %s",
                         count, reload_result["error"])
            return {"status": "ERROR", "records_written": count,
                    "reloaded": False, "error": reload_result["error"],
                    "message": (f"{count} record(s) written to {self.conf_path} but "
                                f"unbound-control reload failed: "
                                f"{reload_result['error']} — the running resolver "
                                f"is still serving the previous set")}
        logger.info("Synced %d DNS records to Unbound", count)
        return {"status": "SUCCESS", "records_written": count, "reloaded": True}

    def list_records(self) -> list:
        """Parse the managed conf file and return records."""
        records = []
        try:
            with open(self.conf_path) as fh:
                for line in fh:
                    m = re.match(r'\s*local-data:\s*"([^"]+)"', line)
                    if not m:
                        continue
                    entry = m.group(1)
                    parts = entry.split()
                    if len(parts) < 4:
                        continue
                    name = parts[0].rstrip(".")
                    ttl = int(parts[1])
                    rtype = parts[2]
                    value = parts[3].rstrip(".")
                    records.append({"name": name, "type": rtype, "value": value, "ttl": ttl})
        except OSError as e:
            logger.warning("Failed to read conf file: %s", e)
        return records

    def add_record(self, record: dict) -> dict:
        """Add a single DNS record."""
        try:
            current = self.list_records()
            name = record.get("name", "").strip().rstrip(".")
            rtype = record.get("type", "A").upper()
            value = record.get("value", "").strip()
            ttl = int(record.get("ttl", 300))
            if not name or not value:
                return {"status": "ERROR", "message": "name and value required"}

            existing = [r for r in current if r["name"] == name and r["type"] == rtype]
            if existing:
                return {"status": "ERROR", "message": f"record {name} {rtype} already exists"}

            lines = ["# Managed by Lab Manager — do not edit manually\n", "server:\n"]
            for r in current:
                lines.append(f'    local-data: "{r["name"]}. {r["ttl"]} IN {r["type"]} {r["value"]}"\n')
            lines.append(f'    local-data: "{name}. {ttl} IN {rtype} {value}"\n')
            ptr = self._ptr_name(value)
            if ptr:
                lines.append(f'    local-data-ptr: "{value} {ttl} {name}."\n')

            with open(self.conf_path, "w") as f:
                f.writelines(lines)

            reload_result = self._reload()
            if not reload_result["ok"]:
                return {"status": "ERROR", "message": reload_result["error"]}
            return {"status": "SUCCESS", "record": {"name": name, "type": rtype, "value": value}}
        except OSError as e:
            return {"status": "ERROR", "message": str(e)}

    def update_record(self, record: dict) -> dict:
        """Update an existing DNS record."""
        try:
            current = self.list_records()
            name = record.get("name", "").strip().rstrip(".")
            rtype = record.get("type", "A").upper()
            value = record.get("value", "").strip()
            ttl = int(record.get("ttl", 300))
            if not name or not value:
                return {"status": "ERROR", "message": "name and value required"}

            existing = [r for r in current if r["name"] == name and r["type"] == rtype]
            if not existing:
                return {"status": "ERROR", "message": f"record {name} {rtype} not found"}

            lines = ["# Managed by Lab Manager — do not edit manually\n", "server:\n"]
            for r in current:
                if r["name"] == name and r["type"] == rtype:
                    lines.append(f'    local-data: "{name}. {ttl} IN {rtype} {value}"\n')
                    ptr = self._ptr_name(value)
                    if ptr:
                        lines.append(f'    local-data-ptr: "{value} {ttl} {name}."\n')
                else:
                    lines.append(f'    local-data: "{r["name"]}. {r["ttl"]} IN {r["type"]} {r["value"]}"\n')

            with open(self.conf_path, "w") as f:
                f.writelines(lines)

            reload_result = self._reload()
            if not reload_result["ok"]:
                return {"status": "ERROR", "message": reload_result["error"]}
            return {"status": "SUCCESS", "record": {"name": name, "type": rtype, "value": value}}
        except OSError as e:
            return {"status": "ERROR", "message": str(e)}

    def delete_record(self, name: str, rtype: str = "A") -> dict:
        """Delete a DNS record."""
        try:
            current = self.list_records()
            name = name.strip().rstrip(".")
            rtype = rtype.upper()

            existing = [r for r in current if r["name"] == name and r["type"] == rtype]
            if not existing:
                return {"status": "ERROR", "message": f"record {name} {rtype} not found"}

            lines = ["# Managed by Lab Manager — do not edit manually\n", "server:\n"]
            for r in current:
                if r["name"] != name or r["type"] != rtype:
                    lines.append(f'    local-data: "{r["name"]}. {r["ttl"]} IN {r["type"]} {r["value"]}"\n')

            with open(self.conf_path, "w") as f:
                f.writelines(lines)

            reload_result = self._reload()
            if not reload_result["ok"]:
                return {"status": "ERROR", "message": reload_result["error"]}
            return {"status": "SUCCESS", "deleted": f"{name} {rtype}"}
        except OSError as e:
            return {"status": "ERROR", "message": str(e)}

    def status(self) -> dict:
        """Return Unbound service status.

        Preserves the actual systemctl state string (active, inactive, failed,
        activating, etc.) rather than collapsing distinct failure modes into
        'inactive', and reports record count and conf path.
        """
        result = self._run_diag(["systemctl", "is-active", "unbound"])
        raw_state = result["output"].strip() if result["output"] else ""
        if not raw_state:
            raw_state = "failed" if not result["ok"] else "unknown"

        running = (result["ok"] and raw_state == "active")
        return {
            "running": running,
            "status": raw_state,
            "service_state": raw_state,
            "ok": result["ok"],
            "record_count": len(self.list_records()),
            "conf_path": self.conf_path,
        }

    @staticmethod
    def _normalize_forward_zone(zone: str) -> str:
        zone = str(zone or "").strip().lower()
        if zone == ".":
            return zone
        zone = zone.rstrip(".")
        if not zone or len(zone) > 253:
            raise ValueError("zone must be '.' or a valid DNS domain")
        labels = zone.split(".")
        if any(not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", label)
               for label in labels):
            raise ValueError("zone must be '.' or a valid DNS domain")
        return zone + "."

    @staticmethod
    def _normalize_upstreams(upstreams) -> list:
        if isinstance(upstreams, str):
            upstreams = re.split(r"[\s,]+", upstreams.strip())
        values = []
        for raw in upstreams or []:
            raw = str(raw).strip()
            if not raw:
                continue
            try:
                values.append(str(ipaddress.ip_address(raw)))
            except ValueError as exc:
                raise ValueError(f"invalid forwarder address: {raw}") from exc
        if not values:
            raise ValueError("at least one forwarder address is required")
        if len(values) > 8:
            raise ValueError("no more than 8 forwarder addresses are allowed")
        return list(dict.fromkeys(values))

    def _managed_forwarders(self) -> list:
        if not os.path.exists(self.forwarders_path):
            return []
        forwarders = []
        zone_map = {}  # zone -> list of upstreams
        with open(self.forwarders_path, encoding="utf-8") as fh:
            current = None
            for raw in fh:
                line = raw.strip()
                match = re.match(r'name:\s*"([^"]+)"$', line)
                if match:
                    z = match.group(1)
                    if z not in zone_map:
                        zone_map[z] = []
                        forwarders.append({"zone": z, "upstreams": zone_map[z]})
                    current = zone_map[z]
                    continue
                match = re.match(r"forward-addr:\s*(\S+)$", line)
                if match and current is not None:
                    addr = match.group(1)
                    if addr not in current:
                        current.append(addr)
        return forwarders

    def _write_forwarders(self, forwarders: list) -> dict:
        old = None
        if os.path.exists(self.forwarders_path):
            with open(self.forwarders_path, "rb") as fh:
                old = fh.read()
        tmp_path = self.forwarders_path + ".tmp"
        lines = ["# Managed by Lab Manager — do not edit manually\n"]
        for item in forwarders:
            lines.extend([
                "forward-zone:\n",
                f'    name: "{item["zone"]}"\n',
                *[f"    forward-addr: {address}\n"
                  for address in item["upstreams"]],
            ])
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.writelines(lines)
            os.replace(tmp_path, self.forwarders_path)
            result = self._reload()
            if result["ok"]:
                return {"status": "SUCCESS", "reloaded": True}
            if old is None:
                try:
                    os.remove(self.forwarders_path)
                except OSError:
                    pass
            else:
                with open(self.forwarders_path, "wb") as fh:
                    fh.write(old)
            self._reload()
            return {"status": "ERROR", "reloaded": False,
                    "message": result["error"]}
        except Exception as exc:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            return {"status": "ERROR", "reloaded": False,
                    "message": str(exc)}

    def list_forwarders(self) -> dict:
        """List configured forwarders.

        First attempts querying unbound-control list_forwards. If unbound-control
        is not available or not running, falls back to parsing the managed
        forwarders file so configuration remains readable.
        """
        try:
            result = subprocess.run(
                ["unbound-control", "list_forwards"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                forwarders = []
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == "forward":
                        forwarders.append({
                            "zone": parts[0],
                            "class": parts[1],
                            "upstreams": parts[3:],
                        })
                return {"status": "SUCCESS", "forwarders": forwarders}
        except Exception:
            pass

        return {"status": "SUCCESS", "forwarders": self._managed_forwarders()}

    def add_forwarder(self, zone: str = ".", upstreams = None, name: str = None, ips = None) -> dict:
        """Add a forwarder zone, merging upstreams into existing zones atomically."""
        if name is not None:
            zone = name
        if ips is not None:
            upstreams = ips
        try:
            zone = self._normalize_forward_zone(zone)
            upstreams = self._normalize_upstreams(upstreams)
        except ValueError as exc:
            return {"status": "ERROR", "message": str(exc), "changed": False}

        managed = self._managed_forwarders()
        managed_zones = {item["zone"] for item in managed}

        live = self.list_forwarders()
        if isinstance(live, dict) and live.get("status") == "SUCCESS":
            for item in live.get("forwarders") or []:
                raw_zone = item.get("zone") or item.get("name")
                try:
                    norm = self._normalize_forward_zone(raw_zone)
                except ValueError:
                    continue
                if norm == zone and zone not in managed_zones:
                    return {
                        "status": "ERROR",
                        "message": f"Unbound serves forwarder zone {zone} from configuration Lab Manager does not manage",
                        "changed": False,
                    }

        target = None
        for item in managed:
            if item["zone"] == zone:
                target = item
                break

        if target is None:
            merged = upstreams
            changed = True
            managed.append({"zone": zone, "upstreams": merged})
        else:
            current_upstreams = target["upstreams"]
            merged = list(dict.fromkeys(current_upstreams + upstreams))
            if len(merged) > 8:
                return {
                    "status": "ERROR",
                    "message": f"zone {zone} exceeds 8-address limit (has {len(merged)})",
                    "changed": False,
                }
            changed = (merged != current_upstreams)
            target["upstreams"] = merged

        result = self._write_forwarders(managed)
        if result.get("status") != "SUCCESS":
            return {**result, "changed": False}
        return {**result, "zone": zone, "upstreams": merged, "changed": changed}

    def remove_forwarder(self, zone: str = None, name: str = None) -> dict:
        """Remove a forwarder zone."""
        if name is not None:
            zone = name
        try:
            zone = self._normalize_forward_zone(zone)
        except ValueError as exc:
            return {"status": "ERROR", "message": str(exc), "changed": False}
        existing = self._managed_forwarders()
        kept = [item for item in existing if item.get("zone") != zone]
        if len(kept) == len(existing):
            return {"status": "SUCCESS", "changed": False, "zone": zone}
        result = self._write_forwarders(kept)
        return {**result, "changed": result.get("status") == "SUCCESS",
                "zone": zone}

    def _run_diag(self, cmd: list) -> dict:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {"ok": result.returncode == 0, "exit_code": result.returncode,
                    "output": result.stdout, "error": result.stderr}
        except Exception as e:
            return {"ok": False, "exit_code": None, "output": "", "error": str(e)}

    def _local_ipv4s(self):
        result = self._run_diag(["ip", "-o", "-4", "addr", "show", "scope", "global"])
        if not result["ok"]:
            return []
        addresses = []
        for line in result["output"].splitlines():
            match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", line)
            if match and not ipaddress.ip_address(match.group(1)).is_loopback:
                addresses.append(match.group(1))
        return sorted(set(addresses))

    def _dns_probe(self, server, name="localhost"):
        started = time.monotonic()
        txid = time.monotonic_ns() & 0xFFFF
        labels = name.rstrip(".").split(".")
        question = b"".join(
            bytes([len(label)]) + label.encode("ascii") for label in labels
        ) + b"\x00" + struct.pack("!HH", 1, 1)
        packet = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(packet, (server, 53))
            response, _ = sock.recvfrom(4096)
            if len(response) < 12:
                raise ValueError("short DNS response")
            reply_id, flags, _, answers, _, _ = struct.unpack("!HHHHHH", response[:12])
            if reply_id != txid:
                raise ValueError("DNS transaction ID mismatch")
            return {
                "server": server,
                "responded": True,
                "rcode": flags & 0xF,
                "answers": answers,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "error": "",
            }
        except Exception as e:
            return {
                "server": server,
                "responded": False,
                "rcode": None,
                "answers": 0,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "error": str(e),
            }
        finally:
            sock.close()

    def _reload(self) -> dict:
        """Reload Unbound. Returns {"ok": bool, "error": str}."""
        try:
            subprocess.run(["unbound-control", "reload"], check=True, timeout=10)
            logger.info("Unbound reloaded")
            return {"ok": True, "error": ""}
        except Exception as e:
            logger.warning("unbound-control reload failed: %s", e)
            return {"ok": False, "error": str(e)}

    def _ptr_name(self, ip: str) -> str:
        try:
            return ipaddress.ip_address(ip).reverse_pointer
        except ValueError:
            return ""

    def _ensure_query_logging(self) -> bool:
        """Self-enable Unbound query logging on first use."""
        want = (f'server:\n    log-queries: yes\n'
                f'    use-syslog: no\n    logfile: "{QUERY_LOG}"\n')
        try:
            os.makedirs(os.path.dirname(QUERY_LOG), exist_ok=True)
        except Exception as e:
            logger.warning("could not create unbound log dir: %s", e)
        try:
            current = open(LOGGING_CONF).read() if os.path.exists(LOGGING_CONF) else ""
        except Exception:
            current = ""
        if current == want:
            return True
        try:
            with open(LOGGING_CONF, "w") as f:
                f.write(want)
            logger.info("Enabled unbound query logging via %s", LOGGING_CONF)
        except Exception as e:
            logger.warning("failed to write %s: %s", LOGGING_CONF, e)
            return False
        return False

    def _tail_query_log(self) -> None:
        """Incrementally parse newly-appended lines of the unbound query log."""
        try:
            st = os.stat(QUERY_LOG)
        except FileNotFoundError:
            logger.debug("Query log file not found: %s (Unbound may not be running)", QUERY_LOG)
            return
        except Exception as e:
            logger.debug("stat query log failed: %s", e)
            return

        if self._query_log_inode is not None and st.st_ino != self._query_log_inode:
            self._query_log_offset = 0
        self._query_log_inode = st.st_ino
        if st.st_size < self._query_log_offset:
            self._query_log_offset = 0

        try:
            with open(QUERY_LOG, "r", errors="replace") as f:
                f.seek(self._query_log_offset)
                for line in f:
                    m = _QUERY_LOG_RE.search(line)
                    if not m:
                        continue
                    name = m.group("name").lower()
                    rtype = m.group("type").upper()
                    ip = m.group("ip")
                    key = f"{name}|{rtype}|{ip}"
                    if key not in self._query_counts and len(self._query_counts) >= MAX_TRACKED_NAMES:
                        continue
                    self._query_counts[key] = self._query_counts.get(key, 0) + 1
                self._query_log_offset = f.tell()
        except Exception as e:
            logger.warning("failed tailing unbound query log: %s", e)

    def get_query_names(self, search: str = None, limit: int = TOP_NAMES_LIMIT,
                         source_prefixes: list = None) -> list:
        """Per-(name,type) query counters, sorted by count desc."""
        self._tail_query_log()
        needle = (search or "").strip().lower()
        nets = None
        if source_prefixes is not None:
            nets = []
            for p in source_prefixes:
                try:
                    nets.append(ipaddress.ip_network(p, strict=False))
                except ValueError:
                    continue
        grouped = {}
        for key, count in self._query_counts.items():
            name, rtype, ip = key.split("|", 2)
            if needle and needle not in name:
                continue
            if nets is not None:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if not any(addr in n for n in nets):
                    continue
            gkey = f"{name}|{rtype}"
            g = grouped.setdefault(gkey, {"name": name, "type": rtype, "count": 0, "sources": {}})
            g["count"] += count
            g["sources"][ip] = g["sources"].get(ip, 0) + count
        rows = []
        for g in grouped.values():
            sources = sorted(
                ({"ip": ip, "count": c} for ip, c in g["sources"].items()),
                key=lambda s: s["count"], reverse=True,
            )
            rows.append({"name": g["name"], "type": g["type"], "count": g["count"], "sources": sources})
        rows.sort(key=lambda r: r["count"], reverse=True)
        if limit:
            rows = rows[:limit]
        return rows

    def get_stats(self, search: str = None, source_prefixes: list = None) -> dict:
        """Unbound query statistics via unbound-control stats_noreset."""
        reload_error = None

        if not self._ensure_query_logging():
            reload_result = self._reload()
            if not reload_result.get("ok"):
                reload_error = reload_result.get("error", "Unbound is not running")

        query_names = self.get_query_names(search=search, source_prefixes=source_prefixes)
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

        hits = n("total.num.cachehits")
        misses = n("total.num.cachemiss")
        total = n("total.num.queries")
        hit_ratio = round(hits / total * 100, 1) if total else 0.0

        aggregate_types = {}
        threaded_types = {}
        for k, v in raw.items():
            m = re.match(r"(?:total\.)?num\.query\.type\.([A-Za-z0-9_-]+)$", k)
            if m and isinstance(v, (int, float)) and v:
                aggregate_types[m.group(1)] = int(v)
                continue
            m = re.match(
                r"thread\d+\.num\.query\.type\.([A-Za-z0-9_-]+)$", k)
            if m and isinstance(v, (int, float)) and v:
                threaded_types[m.group(1)] = (
                    threaded_types.get(m.group(1), 0) + int(v))
        query_types = aggregate_types or threaded_types

        response = {
            "status": "SUCCESS",
            "global": {
                "total_queries": int(total),
                "cache_hits": int(hits),
                "cache_misses": int(misses),
                "cache_hit_ratio": hit_ratio,
                "num_recursive": int(n("total.num.recursivereplies")),
                "recursion_time_avg": round(n("total.recursion.time.avg"), 4),
                "prefetch": int(n("total.num.prefetch")),
                "uptime_seconds": int(n("time.up")),
            },
            "query_types": query_types,
            "query_names": query_names,
            "query_names_tracked": len(self._query_counts),
        }

        if reload_error:
            response["warning"] = reload_error

        return response

    def diagnostics(self) -> dict:
        """Return actionable Unbound service, config, listener, and query checks."""
        service = self._run_diag(["systemctl", "is-active", "unbound"])
        config = self._run_diag(["unbound-checkconf"])
        control = self._run_diag(["unbound-control", "status"])
        sockets = self._run_diag(["ss", "-H", "-lntup"])
        if not sockets["ok"]:
            sockets = self._run_diag(["ss", "-H", "-lntu"])

        listener_lines = [
            line.strip() for line in sockets["output"].splitlines()
            if re.search(r"(?:\]:|:)53(?:\s|$)", line)
        ]
        lan_addresses = self._local_ipv4s()
        probes = [self._dns_probe("127.0.0.1")]
        probes.extend(self._dns_probe(addr) for addr in lan_addresses)

        root_conf = "/etc/unbound/unbound.conf"
        interfaces = []
        access_controls = []
        try:
            with open(root_conf, encoding="utf-8") as fh:
                for line in fh:
                    m = re.match(r"\s*interface:\s*(\S+)", line)
                    if m:
                        interfaces.append(m.group(1))
                    m = re.match(r"\s*access-control:\s*(\S+\s+\S+)", line)
                    if m:
                        access_controls.append(m.group(1))
        except OSError:
            pass

        has_listener = bool(listener_lines)
        listener_hosts = [self._listener_host(line) for line in listener_lines]
        has_lan_listener = any(
            host and not host.startswith("127.") and host != "::1"
            for host in listener_hosts
        )
        lan_probe_ok = any(
            p["responded"] for p in probes if p["server"] != "127.0.0.1"
        )
        recommendations = []
        if not service["ok"]:
            recommendations.append(
                "Unbound is not active; inspect the service error and restart it.")
        if not config["ok"]:
            recommendations.append(
                "Unbound configuration is invalid; fix the reported checkconf error.")
        if not has_listener:
            recommendations.append(
                "Nothing is listening on TCP/UDP port 53.")
        elif not has_lan_listener:
            recommendations.append(
                "Port 53 is only bound to loopback; configure a LAN listener.")
        if lan_addresses and not lan_probe_ok:
            recommendations.append(
                "The local LAN-address DNS probe received no response; check the "
                "listener owner, Unbound access-control, and host firewall.")

        return {
            "status": "SUCCESS",
            "healthy": (
                service["ok"] and config["ok"] and has_lan_listener
                and (lan_probe_ok if lan_addresses else False)
            ),
            "service": service,
            "config": config,
            "control": control,
            "sockets": {
                "ok": sockets["ok"],
                "error": sockets["error"],
                "listeners": listener_lines,
                "has_port_53_listener": has_listener,
                "has_lan_listener": has_lan_listener,
            },
            "configured_interfaces": interfaces,
            "access_controls": access_controls,
            "local_ipv4s": lan_addresses,
            "probes": probes,
            "recommendations": recommendations,
            "conf_path": self.conf_path,
        }

    @staticmethod
    def _listener_host(line):
        for token in line.split():
            if re.search(r":53$", token):
                host = token.rsplit(":", 1)[0].strip("[]")
                return host.split("%", 1)[0]
        return ""
