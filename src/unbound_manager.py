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
# Unbound's main config. We never edit it in place; we only read it to learn
# which directory it actually parses, and bridge our own dir into that.
MAIN_CONF = "/etc/unbound/unbound.conf"
# Name of the one-line bridge file we drop into the distro's included dir.
BRIDGE_CONF_NAME = "lm-include.conf"
QUERY_LOG = "/var/log/unbound/lm-queries.log"

# unbound-control's stats_noreset is aggregate-only (per-type/rcode/etc.) and
# cannot report counts per queried NAME. The only way to get that is Unbound's
# own query log (`log-queries: yes`), tailed incrementally. Cap the number of
# distinct names tracked in memory so a noisy/adversarial resolver can't grow
# this unbounded; once the cap is hit, stop accepting brand-new names until the
# next reset (an operator can always bump/relax this via get_stats(reset=True)
# or a service restart) rather than silently evicting existing counts.
MAX_TRACKED_NAMES = 5000
# The API response itself is further truncated to the top-N by count so large
# trees don't get shipped to the WebUI on every poll; the in-memory table
# still holds up to MAX_TRACKED_NAMES for search to work against.
TOP_NAMES_LIMIT = 200

# Unbound's actual `log-queries: yes` line (util/net_help.c:log_query_in) is
# emitted via log_info as "<prefix...> <client_ip> <qname> <type> <class>",
# e.g. "[time] unbound[pid:0] info: 172.17.1.5 www.dwx.com. A IN". The client
# IP is the token immediately before the (dotted) qname, and IN is the fixed
# class Unbound logs for normal queries.
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

        # Per-(name,type,source-ip) query counters fed by _tail_query_log().
        # Keyed by "name|TYPE|source_ip" -> count so the per-destination
        # breakdown can also report WHICH client(s) asked for it (needed for
        # per-tenant filtering upstream, keyed on the source IP's subnet).
        # self._query_log_offset is the byte offset we last read up to, so
        # repeated get_stats() polls only parse newly appended lines instead
        # of re-reading the whole log each time.
        self._query_counts = {}       # "name|TYPE|source_ip" -> int
        self._query_log_offset = 0
        self._query_log_inode = None

    def _ensure_conf_included(self) -> dict:
        """Guarantee Unbound actually PARSES the directory we write into.

        We write every managed file (records, forwarders, query logging) to
        ``/etc/unbound/conf.d/``. Debian/Ubuntu's packaged ``unbound.conf``
        includes ``/etc/unbound/unbound.conf.d/*.conf`` — a DIFFERENT directory
        (note the ``unbound.`` prefix). On a host where nothing else bridges the
        two, every file we write is silently ignored: ``sync()`` reports
        SUCCESS and ``unbound-control reload`` succeeds, because both are
        truthfully describing a write and a reload of a config Unbound never
        reads. The resolver then answers recursively for public names while
        every lab record and forwarder is missing — which presents as "DNS is
        broken" with a completely healthy-looking service and a clean sync.

        Rather than edit the packaged ``unbound.conf`` (an apt upgrade would
        revert it, and rewriting a distro file is a poor neighbour), drop a
        one-line bridge file into whichever directory Unbound already includes.
        ``include-toplevel`` is the correct directive: our files declare their
        own top-level clauses (``server:``, ``forward-zone:``).

        Idempotent and best-effort — never raises, so a read-only or unusual
        layout degrades to today's behaviour instead of breaking startup.
        """
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
            """True if this glob pulls in *.conf from our directory."""
            return os.path.dirname(glob_path.rstrip()) == conf_dir.rstrip("/")

        if any(_covers(g) for g in include_globs):
            return {"ok": True, "action": "already-included"}

        # Follow the distro's own include dir(s) and check whether a bridge is
        # already in place there (ours from a previous run, or an operator's).
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

    def _ensure_query_logging(self) -> bool:
        """Self-enable Unbound query logging on first use.

        ``unbound-control stats`` has no per-name counters, so per-destination
        breakdowns require Unbound's own query log. Rather than hand-edit the
        main unbound.conf, drop a managed conf.d snippet (same pattern as
        LM_CONF) enabling ``log-queries``. Returns True if logging is already
        (or now) enabled, False if we had to change the conf (caller should
        reload before the new lines start appearing).
        """
        # Unbound defaults to use-syslog: yes, which makes it IGNORE the
        # logfile directive entirely (see log_init() — syslog wins over a
        # configured filename) — without disabling it here, log-queries/
        # logfile above silently write nothing and get_query_names() stays
        # permanently empty even though this snippet "looks" correct.
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
        """Incrementally parse newly-appended lines of the unbound query log
        into ``self._query_counts``, tracking a byte offset so repeated
        get_stats() calls don't re-read the whole file.

        Handles log rotation: if the file's inode changed (or it shrank),
        treat it as a fresh file and restart from offset 0.
        """
        try:
            st = os.stat(QUERY_LOG)
        except FileNotFoundError:
            return
        except Exception as e:
            logger.debug("stat query log failed: %s", e)
            return

        if self._query_log_inode is not None and st.st_ino != self._query_log_inode:
            self._query_log_offset = 0  # rotated
        self._query_log_inode = st.st_ino
        if st.st_size < self._query_log_offset:
            self._query_log_offset = 0  # truncated/rotated in place

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
                        continue  # cap reached; keep counting names already tracked
                    self._query_counts[key] = self._query_counts.get(key, 0) + 1
                self._query_log_offset = f.tell()
        except Exception as e:
            logger.warning("failed tailing unbound query log: %s", e)

    def get_query_names(self, search: str = None, limit: int = TOP_NAMES_LIMIT,
                         source_prefixes: list = None) -> list:
        """Per-(name,type) query counters, sorted by count desc, each carrying
        its breakdown of source client IPs.

        ``search`` is a case-insensitive substring match against the queried
        name. ``source_prefixes`` (a list of ``ipaddress.ip_network``-parsable
        CIDR strings), when given, scopes both which rows are returned AND
        their counts to only the sources that fall inside those prefixes —
        this is how a tenant's DNS statistics view is restricted to queries
        made by their own devices (mirrors the subnet-based tenant filtering
        used elsewhere, e.g. ``access.filter_items_by_prefixes``). ``limit``
        truncates the *returned* list only — the full counter table (up to
        MAX_TRACKED_NAMES distinct name/type/source entries) is retained in
        memory so repeated/narrower searches don't lose data.
        """
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
        grouped = {}  # "name|TYPE" -> {"name":, "type":, "count":, "sources": {ip: count}}
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
                    continue  # source outside this tenant's subnets
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
        """Unbound query statistics via ``unbound-control stats_noreset``.

        Parses the flat ``key=value`` output into headline metrics (total
        queries, cache hit/miss + ratio, recursion latency, uptime) plus a
        per-record-type query breakdown for the UI — the DNS analog of the
        OPNsense resolver stats. ``stats_noreset`` leaves Unbound's counters
        intact so repeated polls don't zero them.

        Also enables (on first call) and tails Unbound's query log to build a
        per-destination-name breakdown (each with its querying source IPs),
        since stats_noreset has no per-name counters. ``search`` filters that
        breakdown by substring match on the queried name; ``source_prefixes``
        scopes it to only queries whose source IP falls in those CIDRs (used
        for per-tenant filtering — see ``get_query_names``).
        """
        if not self._ensure_query_logging():
            self._reload()  # newly-written logging conf needs a reload to take effect
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
            "query_names": query_names,
            "query_names_tracked": len(self._query_counts),
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
