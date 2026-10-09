import subprocess
import logging
import os
import re
import ipaddress
import socket
import struct
import time
from collections import deque

logger = logging.getLogger("UnboundManager")

LM_CONF = "/etc/unbound/conf.d/lm-netbox.conf"
UNBOUND_CONF_DIR = "/etc/unbound/conf.d"
LOGGING_CONF = "/etc/unbound/conf.d/lm-logging.conf"
MAIN_CONF = "/etc/unbound/unbound.conf"
BRIDGE_CONF_NAME = "lm-include.conf"
QUERY_LOG = "/var/log/unbound/lm-queries.log"

MAX_TRACKED_NAMES = 5000
# Timestamped per-query events kept for the per-client ("Pi-hole style") view.
MAX_QUERY_EVENTS = 200000
CLIENT_QUERY_LIMIT = 1000
TOP_NAMES_LIMIT = 200

# WebUI day/week/month selector for the "Queries by Destination" breakdown.
# Counts are kept in per-day buckets (see _query_counts) so a window can be
# summed on read; MAX_RETENTION_DAYS caps how much history is kept at all —
# once a bucket is older than that it is pruned regardless of which window
# is currently selected.
RANGE_DAYS = {"day": 1, "week": 7, "month": 30}
MAX_RETENTION_DAYS = 30

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

        # key ("name|TYPE|ip") -> {day_epoch: count}. Bucketing by day (rather
        # than one lifetime counter) is what makes the day/week/month window
        # and the 30-day retention drop possible.
        self._query_counts = {}
        self._query_log_offset = 0
        self._query_log_inode = None
        # (epoch, client_ip, name, type), oldest first.
        self._query_events = deque(maxlen=MAX_QUERY_EVENTS)

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

        # Query logging is on by default: every sync (NetBox auto-sync runs
        # regularly) idempotently guarantees it, not just a WebUI stats view.
        logging_result = self._ensure_query_logging()
        if logging_result.get("restarted"):
            logger.info("Synced %d DNS records to Unbound via restart", count)
            return {"status": "SUCCESS", "records_written": count, "reloaded": True}

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

    def update_forwarder(self, zone: str = ".", upstreams = None, name: str = None, ips = None, old_zone: str = None) -> dict:
        """Update a forwarder zone, replacing upstreams in-place (not merging).

        Parameters:
            zone: Target forwarder domain name (e.g. '.' or 'example.com').
            upstreams: List or iterable of IPv4/IPv6 addresses to forward to.
            name: Alternative alias for `zone`.
            ips: Alternative alias for `upstreams`.
            old_zone: Optional previous zone domain when renaming a forwarder zone.

        Returns:
            Dict containing operation status ('SUCCESS' or 'ERROR'), updated zone,
            upstreams list, and changed boolean indicator.
        """
        if name is not None:
            zone = name
        if ips is not None:
            upstreams = ips
        try:
            zone = self._normalize_forward_zone(zone)
            upstreams = self._normalize_upstreams(upstreams)
            if old_zone is not None:
                old_zone = self._normalize_forward_zone(old_zone)
        except ValueError as exc:
            return {"status": "ERROR", "message": str(exc), "changed": False}

        if len(upstreams) > 8:
            return {
                "status": "ERROR",
                "message": f"zone {zone} exceeds 8-address limit (has {len(upstreams)})",
                "changed": False,
            }

        managed = self._managed_forwarders()
        target_zone = old_zone if old_zone is not None else zone
        target = None
        for item in managed:
            if item.get("zone") == target_zone:
                target = item
                break

        if target is None:
            return {"status": "ERROR", "message": f"forwarder zone {target_zone} not found", "changed": False}

        if old_zone is not None and old_zone != zone:
            if any(item.get("zone") == zone for item in managed):
                return {"status": "ERROR", "message": f"forwarder zone {zone} already exists", "changed": False}
            target["zone"] = zone

        changed = (target.get("upstreams") != upstreams) or (old_zone is not None and old_zone != zone)
        target["upstreams"] = upstreams

        result = self._write_forwarders(managed)
        if result.get("status") != "SUCCESS":
            return {**result, "changed": False}
        return {**result, "zone": target["zone"], "upstreams": upstreams, "changed": changed}

    def remove_forwarder(self, zone: str = None, name: str = None) -> dict:
        """Remove a managed forwarder zone from Unbound configuration.

        Parameters:
            zone: Zone domain to remove (e.g. 'example.com.').
            name: Alternative alias for `zone`.

        Returns:
            Dict with status ('SUCCESS' or 'ERROR'), changed boolean, and zone.
        """
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

    def _restart_unbound(self, reason: str) -> dict:
        """Restart Unbound and report a structured outcome."""
        try:
            subprocess.run(["systemctl", "restart", "unbound"], check=True,
                           capture_output=True, timeout=30)
            logger.info("Unbound restarted (%s)", reason)
            return {"ok": True, "error": ""}
        except Exception as e:
            logger.warning("unbound restart failed (%s): %s", reason, e)
            return {"ok": False, "error": str(e)}

    def _ptr_name(self, ip: str) -> str:
        try:
            return ipaddress.ip_address(ip).reverse_pointer
        except ValueError:
            return ""

    def _ensure_apparmor_log_access(self) -> dict:
        """Let the confined ``unbound`` daemon create/write the query log.

        Debian/Ubuntu ship an AppArmor profile for unbound that does NOT allow
        /var/log/unbound/. With it enforcing, unbound's mknod of QUERY_LOG is
        DENIED, so the logfile directive silently produces nothing (the lines go
        to the journal instead) and the per-destination breakdown stays empty
        forever even though the conf and directory ownership are correct. The
        supported hook is the ``local/`` override. The result distinguishes
        no-op, successful apply/re-apply, and write/apply failures so callers
        do not confuse "nothing to do" with "still broken"."""
        local_dir = "/etc/apparmor.d/local"
        profile = "/etc/apparmor.d/usr.sbin.unbound"
        rule = f"{os.path.dirname(QUERY_LOG)}/** rw,\n"
        if not os.path.isdir(local_dir) or not os.path.exists(profile):
            return {"status": "noop", "changed": False, "restarted": False,
                    "ok": True, "reason": "apparmor-unavailable"}
        override = os.path.join(local_dir, "usr.sbin.unbound")
        try:
            current = open(override).read() if os.path.exists(override) else ""
            changed = False
            if rule not in current:
                with open(override, "a") as f:
                    if current and not current.endswith("\n"):
                        f.write("\n")
                    f.write("# Managed by Lab Manager — unbound query log (DNS stats)\n" + rule)
                changed = True
        except Exception as e:
            logger.warning("could not update AppArmor override %s: %s", override, e)
            return {"status": "failed", "changed": False, "restarted": False,
                    "ok": False, "reason": f"override-write-failed: {e}"}

        rule_present_and_log_exists = rule in current and os.path.exists(QUERY_LOG)
        if rule_present_and_log_exists:
            return {"status": "noop", "changed": False, "restarted": False,
                    "ok": True, "reason": "rule-already-active"}
        try:
            subprocess.run(["apparmor_parser", "-r", profile], check=True,
                           capture_output=True, timeout=30)
            restart = self._restart_unbound("AppArmor query-log access")
            if not restart["ok"]:
                return {"status": "failed", "changed": changed, "restarted": False,
                        "ok": False, "reason": f"apply-failed: {restart['error']}"}
            logger.info("AppArmor: allowed unbound to write %s; profile reloaded, unbound restarted",
                        QUERY_LOG)
            return {"status": "applied", "changed": changed, "restarted": True,
                    "ok": True, "reason": "override-applied"}
        except Exception as e:
            logger.warning("AppArmor override written but reload/restart failed: %s", e)
            return {"status": "failed", "changed": changed, "restarted": False,
                    "ok": False, "reason": f"apply-failed: {e}"}

    def _ensure_query_logging(self) -> dict:
        """Self-enable Unbound query logging on first use."""
        want = (f'server:\n    log-queries: yes\n'
                f'    use-syslog: no\n    logfile: "{QUERY_LOG}"\n')
        try:
            os.makedirs(os.path.dirname(QUERY_LOG), exist_ok=True)
            try:
                import pwd
                pw = pwd.getpwnam("unbound")
                os.chown(os.path.dirname(QUERY_LOG), pw.pw_uid, pw.pw_gid)
            except (KeyError, ImportError, PermissionError):
                pass
        except Exception as e:
            logger.warning("could not create unbound log dir: %s", e)
        try:
            current = open(LOGGING_CONF).read() if os.path.exists(LOGGING_CONF) else ""
        except Exception:
            current = ""
        conf_changed = current != want
        if conf_changed:
            try:
                with open(LOGGING_CONF, "w") as f:
                    f.write(want)
                logger.info("Enabled unbound query logging via %s", LOGGING_CONF)
            except Exception as e:
                logger.warning("failed to write %s: %s", LOGGING_CONF, e)
                return {"status": "failed", "changed": False, "restarted": False,
                        "ok": False, "reason": f"logging-conf-write-failed: {e}"}

        apparmor_result = self._ensure_apparmor_log_access()
        if not apparmor_result["ok"]:
            return {"status": "failed",
                    "changed": bool(conf_changed or apparmor_result["changed"]),
                    "restarted": False, "ok": False,
                    "reason": apparmor_result["reason"]}

        # ``logfile`` is only opened at startup; a reload leaves unbound
        # logging to its old destination, so the log would stay empty.
        if conf_changed and not apparmor_result["restarted"]:
            restart = self._restart_unbound("query logging enabled")
            if not restart["ok"]:
                return {"status": "failed", "changed": True, "restarted": False,
                        "ok": False, "reason": f"restart-failed: {restart['error']}"}
            return {"status": "restarted", "changed": True, "restarted": True,
                    "ok": True, "reason": "logging-conf-written"}

        if apparmor_result["restarted"]:
            return {"status": "restarted",
                    "changed": bool(conf_changed or apparmor_result["changed"]),
                    "restarted": True, "ok": True,
                    "reason": apparmor_result["reason"]}

        return {"status": "unchanged", "changed": False, "restarted": False,
                "ok": True, "reason": "already-enabled"}

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
                    ts = self._line_epoch(line)
                    self._query_events.append((ts, ip, name, rtype))
                    if key not in self._query_counts and len(self._query_counts) >= MAX_TRACKED_NAMES:
                        continue
                    day = int(ts // 86400)
                    bucket = self._query_counts.setdefault(key, {})
                    bucket[day] = bucket.get(day, 0) + 1
                self._query_log_offset = f.tell()
        except Exception as e:
            logger.warning("failed tailing unbound query log: %s", e)
        self._prune_query_counts()

    @staticmethod
    def _line_epoch(line: str) -> float:
        """Epoch of a query-log line: unbound's ``[epoch]`` prefix, or a
        leading ``journalctl -o short-unix`` stamp, else now."""
        m = re.match(r"\s*\[(\d{9,})\]", line) or re.match(r"\s*(\d{9,})(?:\.\d+)?\s", line)
        return float(m.group(1)) if m else time.time()

    def _journal_events(self, minutes: int) -> list:
        """Fallback when the logfile is absent/unwritten: unbound logs to the
        journal in that case (AppArmor denial, logfile not yet applied)."""
        try:
            r = subprocess.run(
                ["journalctl", "-u", "unbound", "--no-pager", "-o", "short-unix",
                 "--since", f"{int(minutes)} min ago"],
                capture_output=True, text=True, timeout=15)
        except Exception as e:
            logger.debug("journalctl fallback failed: %s", e)
            return []
        events = []
        for line in r.stdout.splitlines():
            m = _QUERY_LOG_RE.search(line)
            if m:
                events.append((self._line_epoch(line), m.group("ip"),
                               m.group("name").lower(), m.group("type").upper()))
        return events

    def get_client_queries(self, client: str = None, minutes: int = 10,
                           search: str = None, limit: int = CLIENT_QUERY_LIMIT,
                           source_prefixes: list = None) -> dict:
        """Pi-hole-style per-device query log: every query made by ``client``
        (exact IP, or any client when omitted) in the trailing ``minutes``,
        newest first, plus a per-name summary."""
        self._ensure_query_logging()
        self._tail_query_log()
        try:
            minutes = max(1, min(int(minutes or 10), MAX_RETENTION_DAYS * 1440))
        except (TypeError, ValueError):
            minutes = 10
        cutoff = time.time() - minutes * 60
        source = "logfile"
        events = list(self._query_events)
        if not os.path.exists(QUERY_LOG):
            events = self._journal_events(minutes)
            source = "journal"
        client = (client or "").strip()
        needle = (search or "").strip().lower()
        nets = None
        if source_prefixes is not None:
            nets = []
            for p in source_prefixes:
                try:
                    nets.append(ipaddress.ip_network(p, strict=False))
                except ValueError:
                    continue
        rows = []
        saw_window_event = False
        for ts, ip, name, rtype in events:
            if ts < cutoff:
                continue
            saw_window_event = True
            if client and ip != client:
                continue
            if needle and needle not in name:
                continue
            if nets is not None:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if not any(addr in n for n in nets):
                    continue
            rows.append({"time": ts, "client": ip, "name": name, "type": rtype})
        if os.path.exists(QUERY_LOG) and not saw_window_event:
            events = self._journal_events(minutes)
            source = "journal"
            rows = []
            for ts, ip, name, rtype in events:
                if ts < cutoff:
                    continue
                if client and ip != client:
                    continue
                if needle and needle not in name:
                    continue
                if nets is not None:
                    try:
                        addr = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if not any(addr in n for n in nets):
                        continue
                rows.append({"time": ts, "client": ip, "name": name, "type": rtype})
        rows.sort(key=lambda r: r["time"], reverse=True)
        summary = {}
        for r in rows:
            k = (r["name"], r["type"])
            summary[k] = summary.get(k, 0) + 1
        top = sorted(({"name": n, "type": t, "count": c} for (n, t), c in summary.items()),
                     key=lambda x: x["count"], reverse=True)[:100]
        return {"status": "SUCCESS", "client": client, "minutes": minutes,
                "source": source, "total": len(rows), "queries": rows[:limit or CLIENT_QUERY_LIMIT],
                "top_names": top}

    def _prune_query_counts(self) -> None:
        """Age out day-buckets older than MAX_RETENTION_DAYS so tracked query
        history never grows unbounded and drops on its own, independent of
        whichever day/week/month window the WebUI happens to be viewing."""
        cutoff = int(time.time() // 86400) - MAX_RETENTION_DAYS + 1
        empty_keys = []
        for key, buckets in self._query_counts.items():
            for day in [d for d in buckets if d < cutoff]:
                del buckets[day]
            if not buckets:
                empty_keys.append(key)
        for key in empty_keys:
            del self._query_counts[key]

    def get_query_names(self, search: str = None, limit: int = TOP_NAMES_LIMIT,
                         source_prefixes: list = None, range_days: int = None) -> list:
        """Per-(name,type) query counters, sorted by count desc. ``range_days``
        (1/7/30 for the WebUI's day/week/month selector) sums only the
        trailing N days of buckets; omitted/None sums everything still
        retained (at most MAX_RETENTION_DAYS, enforced by _prune_query_counts)."""
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
        cutoff_day = None
        if range_days:
            cutoff_day = int(time.time() // 86400) - int(range_days) + 1
        grouped = {}
        for key, buckets in self._query_counts.items():
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
            count = sum(c for d, c in buckets.items() if cutoff_day is None or d >= cutoff_day)
            if not count:
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

    def get_stats(self, search: str = None, source_prefixes: list = None,
                  range_days: int = None) -> dict:
        """Unbound query statistics via unbound-control stats_noreset.

        ``range_days`` only narrows the ``query_names`` (per-destination)
        breakdown — the ``global``/``query_types`` counters below come
        straight from unbound-control's own lifetime totals, which Unbound
        itself does not bucket by day."""
        reload_error = None
        logging_result = self._ensure_query_logging()
        restarted = bool(logging_result.get("restarted"))
        if not logging_result.get("ok"):
            if not restarted:
                reload_result = self._reload()
                if not reload_result.get("ok"):
                    reload_error = reload_result.get("error", "Unbound is not running")
            if not reload_error:
                reload_error = logging_result.get("reason", "query logging setup failed")

        query_names = self.get_query_names(search=search, source_prefixes=source_prefixes,
                                            range_days=range_days)
        attempts = 2 if restarted else 1
        last_error = ""
        for attempt in range(attempts):
            try:
                result = subprocess.run(
                    ["unbound-control", "stats_noreset"],
                    capture_output=True, text=True, timeout=8,
                )
            except Exception as e:
                last_error = str(e)
                if attempt + 1 < attempts:
                    time.sleep(0.5)
                    continue
                logger.error("get_stats failed: %s", e)
                return {"status": "ERROR", "message": str(e)}
            if result.returncode == 0:
                break
            last_error = result.stderr.strip() or "unbound-control failed"
            if attempt + 1 < attempts:
                time.sleep(0.5)
                continue
            return {"status": "ERROR", "message": last_error}

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

    def query_log_diagnostics(self) -> dict:
        """Read-only evidence for why the query log / "Queries by Destination"
        / per-client log might be empty. Never changes any state."""
        info = {"query_log": QUERY_LOG, "logging_conf": LOGGING_CONF}
        findings = []

        def tail(path, n=8, size=65536):
            try:
                with open(path, "rb") as fh:
                    fh.seek(0, os.SEEK_END)
                    end = fh.tell()
                    fh.seek(max(0, end - size))
                    return fh.read().decode("utf-8", "replace").splitlines()[-n:]
            except OSError:
                return []

        def stat_of(path):
            try:
                st = os.stat(path)
            except OSError as e:
                return {"exists": False, "error": str(e)}
            owner = group = None
            try:
                import pwd, grp
                owner = pwd.getpwuid(st.st_uid).pw_name
                group = grp.getgrgid(st.st_gid).gr_name
            except Exception:
                pass
            return {"exists": True, "size": st.st_size, "mode": oct(st.st_mode & 0o7777),
                    "owner": owner, "group": group,
                    "age_seconds": round(time.time() - st.st_mtime, 1)}

        info["log_dir"] = stat_of(os.path.dirname(QUERY_LOG))
        info["log_file"] = stat_of(QUERY_LOG)
        log_tail = tail(QUERY_LOG)
        info["log_tail"] = log_tail
        info["log_tail_parsed"] = sum(1 for ln in log_tail if _QUERY_LOG_RE.search(ln))
        try:
            info["logging_conf_content"] = open(LOGGING_CONF).read()
        except OSError as e:
            info["logging_conf_content"] = None
            findings.append(f"{LOGGING_CONF} is missing ({e}); logging was never enabled.")

        conf_dir = os.path.dirname(self.conf_path)
        try:
            main_text = open(MAIN_CONF, encoding="utf-8").read()
        except OSError:
            main_text = ""
        info["conf_dir_included"] = bool(
            re.search(r"^\s*include(?:-toplevel)?:\s*\"?%s" % re.escape(conf_dir),
                      main_text, re.M))
        if not info["conf_dir_included"]:
            findings.append(f"{MAIN_CONF} does not include {conf_dir}/*; lm-logging.conf is never read.")

        # What the RUNNING daemon uses (not just what the file says).
        for opt in ("log-queries", "logfile", "use-syslog"):
            r = self._run_diag(["unbound-control", "get_option", opt])
            info[f"running_{opt.replace('-', '_')}"] = (
                r["output"].strip() if r["ok"] else (r["error"].strip() or "unavailable"))
        cf = self._run_diag(["unbound-checkconf", "-o", "log-queries"])
        info["configured_log_queries"] = cf["output"].strip() if cf["ok"] else (cf["error"].strip() or "unavailable")
        cf = self._run_diag(["unbound-checkconf", "-o", "logfile"])
        info["configured_logfile"] = cf["output"].strip() if cf["ok"] else (cf["error"].strip() or "unavailable")
        ver = self._run_diag(["unbound", "-V"])
        info["unbound_version"] = (ver["output"] or ver["error"]).splitlines()[0] if (ver["output"] or ver["error"]) else ""
        pid = self._run_diag(["systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", "unbound"])
        info["unbound_active_since"] = pid["output"].strip()

        # AppArmor: override present, profile mode, recent denials.
        override = "/etc/apparmor.d/local/usr.sbin.unbound"
        try:
            ov = open(override).read()
        except OSError:
            ov = None
        info["apparmor_profile_present"] = os.path.exists("/etc/apparmor.d/usr.sbin.unbound")
        info["apparmor_override_present"] = ov is not None
        info["apparmor_override_has_rule"] = bool(ov and f"{os.path.dirname(QUERY_LOG)}/**" in ov)
        aa = self._run_diag(["aa-status"])
        info["apparmor_unbound_status"] = ("loaded" if re.search(r"unbound", aa["output"])
                                           else ("aa-status unavailable" if not aa["ok"] else "not loaded"))
        den = self._run_diag(["journalctl", "-k", "--no-pager", "-n", "400", "-o", "cat"])
        info["apparmor_denials"] = [ln.strip() for ln in den["output"].splitlines()
                                    if "DENIED" in ln and "unbound" in ln][-5:]

        # Journal fallback: is unbound logging queries there instead?
        jr = self._run_diag(["journalctl", "-u", "unbound", "--no-pager", "-n", "300", "-o", "cat"])
        jlines = jr["output"].splitlines()
        info["journal_query_lines"] = sum(1 for ln in jlines if _QUERY_LOG_RE.search(ln))
        info["journal_tail"] = [ln for ln in jlines if "info:" in ln or "error" in ln.lower()][-6:]

        # In-memory state of this process.
        info["memory"] = {
            "events": len(self._query_events), "tracked_names": len(self._query_counts),
            "log_offset": self._query_log_offset, "log_inode": self._query_log_inode,
        }

        if info["log_file"].get("exists") and info["log_file"].get("size", 0) == 0:
            findings.append("Query log exists but is empty: unbound is not writing to it "
                            "(check running logfile/log-queries below, and AppArmor).")
        if not info["log_file"].get("exists"):
            findings.append("Query log file does not exist: unbound never created it.")
        if info["apparmor_denials"]:
            findings.append("AppArmor is denying unbound; see denials below.")
        if info["apparmor_profile_present"] and not info["apparmor_override_has_rule"]:
            findings.append("AppArmor profile present but the lm override rule is missing.")
        if str(info.get("running_log_queries", "")).lower() not in ("yes", "unavailable", ""):
            findings.append("Running unbound has log-queries off; it needs a restart (not reload).")
        if info["running_logfile"] and QUERY_LOG not in info["running_logfile"] \
                and info["running_logfile"] != "unavailable":
            findings.append(f"Running unbound logfile is {info['running_logfile']!r}, not {QUERY_LOG}.")
        if info["journal_query_lines"] and not info["log_tail_parsed"]:
            findings.append("Queries are appearing in the journal, not the logfile.")
        if info["log_tail"] and not info["log_tail_parsed"]:
            findings.append("Log has lines but none match the parser regex; see log_tail for the real format.")
        info["findings"] = findings
        return info

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
            "query_logging": self._safe_query_log_diagnostics(),
        }

    def _safe_query_log_diagnostics(self) -> dict:
        try:
            return self.query_log_diagnostics()
        except Exception as e:
            logger.warning("query log diagnostics failed: %s", e)
            return {"error": str(e), "findings": [f"query-log diagnostics failed: {e}"]}

    @staticmethod
    def _listener_host(line):
        for token in line.split():
            if re.search(r":53$", token):
                host = token.rsplit(":", 1)[0].strip("[]")
                return host.split("%", 1)[0]
        return ""
