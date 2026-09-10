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


class UnboundManager:
    def __init__(self, conf_path: str = LM_CONF):
        self.conf_path = conf_path
        self.forwarders_path = os.path.join(
            os.path.dirname(self.conf_path), "lm-forwarders.conf")
        os.makedirs(os.path.dirname(self.conf_path), exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────

    def sync(self, records: list) -> dict:
        """
        Replace all LM-managed DNS records with the provided list.

        Each record: {"name": "host.example.com", "type": "A", "value": "10.0.1.5", "ttl": 300}
        Forward (A/AAAA) and reverse (PTR) records are both written.
        """
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

        # A write that Unbound never reloaded has NOT taken effect: the file on
        # disk says one thing and the running resolver answers another. Report
        # the reload failure instead of a SUCCESS the caller cannot act on —
        # the clustered coordinator relies on this to avoid recording a version
        # a resolver is not actually serving.
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
        """Parse the managed conf file and return records.

        Always opens + parses the conf on every call — the parse is
        sub-millisecond and callers (status/add/update/delete) that also touch
        Unbound already pay a far slower unbound-control shell-out. A previous
        mtime-keyed memo could serve a STALE list when an out-of-band edit
        landed in the same 1-second st_mtime bucket, so it was removed."""
        try:
            os.stat(self.conf_path)
        except FileNotFoundError:
            return []
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
        current = None
        with open(self.forwarders_path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                match = re.match(r'name:\s*"([^"]+)"$', line)
                if match:
                    current = {"zone": match.group(1), "upstreams": []}
                    forwarders.append(current)
                    continue
                match = re.match(r"forward-addr:\s*(\S+)$", line)
                if match and current is not None:
                    current["upstreams"].append(match.group(1))
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
                os.remove(self.forwarders_path)
            else:
                with open(self.forwarders_path, "wb") as fh:
                    fh.write(old)
            self._reload()
            return {"status": "ERROR", "reloaded": False,
                    "message": result["error"]}
        except Exception as exc:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return {"status": "ERROR", "reloaded": False,
                    "message": str(exc)}

    def add_forwarder(self, zone: str, upstreams) -> dict:
        try:
            zone = self._normalize_forward_zone(zone)
            upstreams = self._normalize_upstreams(upstreams)
        except ValueError as exc:
            return {"status": "ERROR", "message": str(exc), "changed": False}
        live = self.list_forwarders()
        if live.get("status") != "SUCCESS":
            return {**live, "changed": False}
        if any(self._normalize_forward_zone(item.get("zone")) == zone
               for item in live.get("forwarders") or []):
            return {"status": "ERROR",
                    "message": f"forwarder zone {zone} already exists",
                    "changed": False}
        result = self._write_forwarders([
            *self._managed_forwarders(),
            {"zone": zone, "upstreams": upstreams},
        ])
        return {**result, "zone": zone, "upstreams": upstreams,
                "changed": result.get("status") == "SUCCESS"}

    def remove_forwarder(self, zone: str) -> dict:
        """Remove an LM-managed forwarding zone. Used for cluster rollback."""
        try:
            zone = self._normalize_forward_zone(zone)
        except ValueError as exc:
            return {"status": "ERROR", "message": str(exc)}
        existing = self._managed_forwarders()
        kept = [item for item in existing if item.get("zone") != zone]
        if len(kept) == len(existing):
            return {"status": "SUCCESS", "changed": False, "zone": zone}
        result = self._write_forwarders(kept)
        return {**result, "changed": result.get("status") == "SUCCESS",
                "zone": zone}

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _run_diag(cmd, timeout=5):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout)
            output = (result.stdout or result.stderr or "").strip()[:2000]
            return {
                "ok": result.returncode == 0,
                "exit_code": result.returncode,
                "output": output,
                "error": "" if result.returncode == 0 else (output or "command failed"),
            }
        except Exception as e:
            return {"ok": False, "exit_code": None, "output": "", "error": str(e)}

    @staticmethod
    def _listener_host(line):
        for token in line.split():
            if re.search(r":53$", token):
                host = token.rsplit(":", 1)[0].strip("[]")
                return host.split("%", 1)[0]
        return ""

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

    @staticmethod
    def _dns_probe(server, name="localhost"):
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
        """Reload Unbound. Returns ``{"ok": bool, "error": str}``.

        Previously swallowed the failure with a WARNING, so a conf write whose
        reload never happened still reported SUCCESS upstream. Callers need the
        distinction: the file changed but the resolver did not."""
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
