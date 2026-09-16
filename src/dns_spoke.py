import asyncio
import logging
import os
from typing import Any, Dict, List, Optional

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

try:
    from unbound_manager import UnboundManager
except ImportError:  # loaded as a package (src.X) by the sibling entrypoint
    from src.unbound_manager import UnboundManager

try:
    from dns_cluster import (
        DEFAULT_CLUSTER_CONFIG, DEFAULT_DESIRED_STATE, DNS_WORKER_OPS,
        DnsClusterCoordinator, DnsDesiredState, DnsRecordError,
        DnsStateUnavailable, derive_managed_records, load_cluster_config,
        save_cluster_config,
    )
except ImportError:  # loaded as a package (src.X) by the sibling entrypoint
    from src.dns_cluster import (  # type: ignore
        DEFAULT_CLUSTER_CONFIG, DEFAULT_DESIRED_STATE, DNS_WORKER_OPS,
        DnsClusterCoordinator, DnsDesiredState, DnsRecordError,
        DnsStateUnavailable, derive_managed_records, load_cluster_config,
        save_cluster_config,
    )

logger = logging.getLogger("DNSSpoke")

#: How often the coordinator re-checks every worker's applied record set and
#: re-pushes to any that drifted. Also the reconnect-convergence window: a
#: resolver that reboots is brought back to the desired set within one pass.
RECONCILE_INTERVAL_S = 30.0


class _DisabledTransport:
    """Null transport used when the core cluster module isn't available.

    ``dns`` and ``lm`` deploy independently, so a spoke can be newer than the
    core beside it. Degrading to single-host is correct; crashing is not.
    """

    enabled = False

    def set_members(self, members):
        return []

    def member_ids(self):
        return []

    def member_links(self):
        return []

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        return {"status": "ERROR", "results": {}, "ok": [], "failed": [],
                "message": "cluster transport unavailable"}

    async def call(self, member_id, command, data, timeout=20.0):
        return {"status": "ERROR", "message": "cluster transport unavailable"}


class DNSSpoke(BaseSpoke):
    """
    Unbound DNS spoke.

    Two deployment shapes, one command surface:

    * **Local (default, unchanged).** The spoke manages the Unbound instance on
      its own host. Records are written to /etc/unbound/conf.d/lm-netbox.conf
      and Unbound is reloaded after every write.
    * **Cluster.** Two or more resolver hosts run ``lm-dns-worker`` and dial
      this spoke's ``/ws/agent`` listener. The spoke becomes the authoritative
      owner of a versioned record set and fans every change out to all members —
      see ``dns_cluster.py``. Enabled only when 2+ members are configured, so an
      existing single-host install behaves exactly as before.

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
      DNS_DIAGNOSTICS   — service/config/listener/query health evidence
      DNS_CLUSTER_STATUS    — member stats, convergence, drift, recommendations
      DNS_CLUSTER_CONFIG    — set the resolver member list (+ worker secret)
      DNS_CLUSTER_RECONCILE — force an immediate reconcile pass
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        conf_path = config.get("unbound_conf", "/etc/unbound/conf.d/lm-netbox.conf")
        self.mgr = UnboundManager(conf_path=conf_path)

        self._cluster_config_path = config.get(
            "cluster_config",
            os.getenv("LM_DNS_CLUSTER_CONFIG", DEFAULT_CLUSTER_CONFIG))
        members = config.get("cluster_members")
        if members is None:
            members = load_cluster_config(self._cluster_config_path).get("members", [])
        self.desired = DnsDesiredState(config.get(
            "desired_state",
            os.getenv("LM_DNS_DESIRED_STATE", DEFAULT_DESIRED_STATE)))
        self._transport = self._build_transport(members)
        self.cluster = DnsClusterCoordinator(self._transport, self.desired)
        self._reconcile_task: Optional[asyncio.Task] = None

    # ── Cluster plumbing ────────────────────────────────────────────────────

    def _build_transport(self, members):
        """Wrap the shared coordinator transport around this spoke's listener.

        Imported lazily: the transport lives in the LM ``core`` repo, which
        deploys independently of this one. A core without it leaves the cluster
        disabled instead of crashing a working single-host spoke.
        """
        try:
            try:
                from core.src.messaging.service_cluster import ClusterCoordinator
            except ImportError:
                from messaging.service_cluster import ClusterCoordinator  # type: ignore
        except ImportError:
            logger.info("Cluster transport unavailable in this core build — "
                        "DNS stays single-host")
            return _DisabledTransport()
        return ClusterCoordinator("dns", DNS_WORKER_OPS,
                                  lambda: getattr(self, "control_plane", None),
                                  members=members)

    def cluster_listener_required(self) -> bool:
        """Tells the control plane whether to bind the DNS ``/ws/agent`` port.

        Only a real (2+ member) cluster binds a port — a single-host DNS role
        must never open a listener it has no use for.
        """
        return bool(self.cluster.enabled)

    def start_background_loops(self) -> None:
        """Process-scoped hook invoked by the control plane (standalone spoke or
        the generic agent's ``RoleConnection``). Starts the reconcile loop."""
        if self._reconcile_task and not self._reconcile_task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug("No running loop — DNS reconcile loop not started")
            return
        self._reconcile_task = loop.create_task(self._reconcile_loop())

    def stop_background_loops(self) -> None:
        """Cancel the reconcile loop. Called by the control plane when the role
        is unloaded, so the task does not survive the sub-spoke and keep
        re-pushing to workers a torn-down coordinator no longer owns."""
        task = self._reconcile_task
        self._reconcile_task = None
        if task is not None and not task.done():
            task.cancel()
        return task

    async def _reconcile_loop(self) -> None:
        while True:
            await asyncio.sleep(RECONCILE_INTERVAL_S)
            if not self.cluster.enabled:
                continue
            try:
                result = await self.cluster.reconcile()
                if result.get("reconciled"):
                    logger.info("DNS reconcile re-pushed v%s to %s",
                                result.get("version"), result["reconciled"])
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — a bad pass must not kill the loop
                logger.warning("DNS reconcile pass failed: %s", e)

    async def _apply_cluster_config(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNS_CLUSTER_CONFIG`` — declare which resolver hosts this module owns.

        ``worker_secret`` is write-only: it sets the PSK the workers
        authenticate with and is never echoed back. Enabling a cluster for the
        first time REQUIRES one — the spoke will not mint a value the operator
        can never read and therefore could never give to the workers.

        Topology changes are candidate-first: the previous member list is
        restored in memory on any failure, so a rejected save never leaves the
        live coordinator on a topology it did not persist.

        On the transition single-host → cluster the current managed record set is
        ADOPTED as v1 before the listener comes up, so the first reconcile pass
        cannot push an empty default over resolvers that are already answering.
        """
        raw = data.get("members")
        if raw is None:
            return {"status": "ERROR", "message": "members is required"}
        if not isinstance(raw, list):
            return {"status": "ERROR", "message": "members must be a list"}
        # ONE critical section for validate → persist → rebind → seed → stand
        # down, sharing the lock every apply/reconcile takes: a topology edit
        # must never interleave with a record fan-out.
        async with self.cluster.transaction():
            return await self._apply_cluster_config_locked(raw, data)

    async def _apply_cluster_config_locked(self, raw, data) -> Dict[str, Any]:
        previous_members = [dict(m) for m in self._transport.members]
        was_enabled = self.cluster.enabled

        members = self._transport.set_members(raw)
        if raw and not members:
            self._transport.set_members(previous_members)
            return {"status": "ERROR",
                    "message": "no usable members — each needs a non-empty id"}

        cp = getattr(self, "control_plane", None)
        secret = str(data.get("worker_secret") or "").strip()
        enabling = len(members) >= 2
        have_secret = bool(getattr(cp, "agent_secret", "") or "")
        if enabling and not secret and not have_secret:
            self._transport.set_members(previous_members)
            return {"status": "ERROR", "secret_required": True,
                    "message": ("A worker secret is required to enable the DNS "
                                "resolver cluster. Supply the same value here and "
                                "to each resolver's installer (--worker-secret); "
                                "it is stored write-only and never displayed "
                                "again.")}

        if self.cluster.state_error:
            self._transport.set_members(previous_members)
            return {"status": "ERROR", "state_unavailable": True,
                    "message": self.cluster.state_error}

        removing = [m["id"] for m in previous_members
                    if m.get("id") not in {n["id"] for n in members}]
        try:
            save_cluster_config(self._cluster_config_path, members)
        except Exception as e:  # noqa: BLE001
            self._transport.set_members(previous_members)
            return {"status": "ERROR",
                    "message": f"could not persist cluster config: {e}"}

        # Stage the PSK: capture the one in force so any later failure can put
        # it back. Overwriting it and then rolling the topology back left every
        # already-provisioned resolver unable to authenticate.
        previous_secret = None
        if secret and cp is not None and hasattr(cp, "set_agent_secret"):
            if hasattr(cp, "snapshot_agent_secret"):
                previous_secret = cp.snapshot_agent_secret()
            cp.set_agent_secret(secret)

        def _restore_secret():
            if previous_secret is not None and hasattr(cp, "restore_agent_secret"):
                cp.restore_agent_secret(previous_secret)

        listener = {"ok": True, "serving": False, "endpoint": "", "error": ""}
        if cp is not None and hasattr(cp, "ensure_cluster_listener"):
            listener = await cp.ensure_cluster_listener() or listener
            if isinstance(listener, bool):        # older core: no readiness
                listener = {"ok": listener, "serving": listener,
                            "endpoint": "", "error": ""}
        if enabling and not listener.get("ok"):
            # The workers can never reach a listener that did not start, so
            # reporting SUCCESS here would be a lie the operator only discovers
            # when nothing converges.
            self._transport.set_members(previous_members)
            _restore_secret()
            try:
                save_cluster_config(self._cluster_config_path, previous_members)
            except Exception:  # noqa: BLE001
                pass
            return {"status": "ERROR", "listener": listener,
                    "message": (f"the DNS cluster listener did not start: "
                                f"{listener.get('error') or 'unknown error'}")}

        seeded = {}
        if enabling and not was_enabled:
            try:
                seeded = await self._seed_desired_state()
            except DnsStateUnavailable as e:
                # The seed could not be recorded: roll the topology back rather
                # than run a cluster whose authoritative set is unknown.
                self._transport.set_members(previous_members)
                _restore_secret()
                try:
                    save_cluster_config(self._cluster_config_path,
                                        previous_members)
                except Exception:  # noqa: BLE001
                    pass
                return {"status": "ERROR", "state_unavailable": True,
                        "message": (f"could not adopt the existing record set: "
                                    f"{e} — the cluster was not enabled")}
            if seeded.get("status") == "ERROR":
                # Divergent resolvers: adopting either set would erase the
                # other's unique records. Leave the module single-host until an
                # operator reconciles them.
                self._transport.set_members(previous_members)
                _restore_secret()
                try:
                    save_cluster_config(self._cluster_config_path,
                                        previous_members)
                except Exception:  # noqa: BLE001
                    pass
                return {"status": "ERROR", "seed": seeded,
                        "divergent": True, "message": seeded["message"]}

        stood_down, unreachable = await self._standdown_removed(removing)
        result = {"status": "SUCCESS", "members": members,
                  "cluster_enabled": self.cluster.enabled,
                  "seed": seeded,
                  "listener": {**self._listener_hint(), **listener}}
        if removing:
            result["removed"] = removing
            result["removed_stood_down"] = stood_down
            result["removed_unreachable"] = unreachable
            if unreachable:
                result["status"] = "PARTIAL"
                result["message"] = (
                    "Topology saved, but these removed resolver(s) could not be "
                    "deconfigured and still hold their cluster marker: "
                    + ", ".join(unreachable)
                    + ". Stop lm-dns-worker on them (their records are left in "
                      "place so they keep answering).")
        return result

    async def _seed_desired_state(self) -> Dict[str, Any]:
        """Adopt the records already being served as the cluster's v1."""
        try:
            local = await asyncio.to_thread(self.mgr.list_records)
        except Exception as e:  # noqa: BLE001 — an agent-hosted module may have
            # no local Unbound at all; the members are then asked instead.
            logger.info("No local managed records to adopt (%s)", e)
            local = []
        # Already inside the coordinator transaction (see
        # _apply_cluster_config_locked), so do not re-take the lock.
        return await self.cluster.seed(derive_managed_records(local), locked=True)

    async def _standdown_removed(self, removed):
        """Ask removed resolvers to drop their cluster marker; report failures."""
        stood_down, unreachable = [], []
        for member_id in removed or []:
            reply = await self._transport.call(member_id, "DNSW_STANDDOWN", {},
                                               timeout=20.0)
            if isinstance(reply, dict) and reply.get("status") == "SUCCESS":
                stood_down.append(member_id)
            else:
                unreachable.append(member_id)
        return stood_down, unreachable

    def _listener_hint(self) -> Dict[str, Any]:
        cp = getattr(self, "control_plane", None)
        return {"port": int(os.environ.get("LM_DNS_AGENT_PORT", "8769")),
                "path": "/ws/agent",
                "serving": bool(getattr(cp, "_agent_server_task", None))}

    async def _cluster_status(self) -> Dict[str, Any]:
        await self.cluster.refresh_state()
        return {"status": "SUCCESS", **self.cluster.cluster_report()}

    async def _cluster_diagnostics(self) -> Dict[str, Any]:
        """Per-member diagnostics + the convergence view.

        The top-level evidence keys are carried from ONE named member
        (``diagnostics_source``) so the existing Diagnostics panels keep
        rendering real data, while ``members`` holds every resolver's own
        evidence and ``healthy`` requires all of them AND convergence.
        """
        await self.cluster.refresh_state()
        report = self.cluster.cluster_report()
        fan = await self._transport.fanout("DNSW_DIAGNOSTICS", {}, timeout=25.0)
        per_member: Dict[str, Any] = {}
        for member_id, reply in (fan.get("results") or {}).items():
            per_member[member_id] = reply if isinstance(reply, dict) else {
                "status": "ERROR", "message": "malformed reply"}

        source = next((m["id"] for m in report["members"]
                       if (per_member.get(m["id"]) or {}).get("status") == "SUCCESS"), "")
        base: Dict[str, Any] = dict(per_member.get(source) or {})
        base.pop("member_id", None)
        recommendations: List[str] = []
        for member_id, diag in per_member.items():
            if diag.get("status") != "SUCCESS":
                recommendations.append(
                    f"[{member_id}] diagnostics unavailable: "
                    f"{diag.get('message') or 'no response'}")
                continue
            for rec in diag.get("recommendations") or []:
                recommendations.append(f"[{member_id}] {rec}")
        recommendations.extend(report["recommendations"])

        members_healthy = bool(per_member) and all(
            d.get("status") == "SUCCESS" and d.get("healthy")
            for d in per_member.values())
        return {
            **base,
            "status": "SUCCESS",
            "healthy": bool(members_healthy and report["converged"]),
            "diagnostics_source": source,
            "cluster": report,
            "members": per_member,
            "recommendations": recommendations,
        }

    async def _cluster_stats(self, search: str = None, source_prefixes: list = None) -> Dict[str, Any]:
        """Cluster stats: per-member counters plus the summed headline totals."""
        payload = {}
        if search:
            payload["search"] = search
        if source_prefixes:
            payload["source_prefixes"] = source_prefixes
        fan = await self._transport.fanout("DNSW_STATS", payload, timeout=20.0)
        per_member: Dict[str, Any] = {}
        totals = {"total_queries": 0, "cache_hits": 0, "cache_misses": 0,
                  "num_recursive": 0, "prefetch": 0}
        for member_id, reply in (fan.get("results") or {}).items():
            per_member[member_id] = reply
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS":
                continue
            g = reply.get("global") or {}
            for key in totals:
                totals[key] += int(g.get(key) or 0)
        total = totals["total_queries"]
        totals["cache_hit_ratio"] = (round(totals["cache_hits"] / total * 100, 1)
                                     if total else 0.0)
        merged_types: Dict[str, int] = {}
        # query_names is merged across members by (name, type): different
        # resolvers in the same cluster serve the same desired record set, so
        # a name queried against multiple members should show a combined
        # count rather than one arbitrary member's view. Per-source counts are
        # merged the same way so the "who queried this" breakdown stays
        # accurate across the cluster.
        merged_names: Dict[tuple, dict] = {}
        for reply in per_member.values():
            if isinstance(reply, dict) and reply.get("status") == "SUCCESS":
                for qtype, count in (reply.get("query_types") or {}).items():
                    merged_types[qtype] = merged_types.get(qtype, 0) + int(count or 0)
                for entry in reply.get("query_names") or []:
                    key = (entry.get("name"), entry.get("type"))
                    g = merged_names.setdefault(key, {"count": 0, "sources": {}})
                    g["count"] += int(entry.get("count") or 0)
                    for s in entry.get("sources") or []:
                        ip = s.get("ip")
                        g["sources"][ip] = g["sources"].get(ip, 0) + int(s.get("count") or 0)
        query_names = sorted(
            ({"name": n, "type": t, "count": g["count"],
              "sources": sorted(
                  ({"ip": ip, "count": c} for ip, c in g["sources"].items()),
                  key=lambda s: s["count"], reverse=True)}
             for (n, t), g in merged_names.items()),
            key=lambda r: r["count"], reverse=True,
        )
        return {"status": "SUCCESS", "global": totals, "query_types": merged_types,
                "query_names": query_names, "cluster": True, "members": per_member}

    async def _cluster_forwarders(self) -> Dict[str, Any]:
        """Upstream forwarders per resolver.

        Forwarders are per-resolver configuration and the coordinator box may
        not run Unbound at all, so this is an allowlisted worker op fanned out
        and aggregated — never the coordinator's own ``unbound-control``.
        Entries are tagged with the member they came from; a member that failed
        is surfaced in ``member_errors`` rather than silently shrinking the
        list."""
        fan = await self._transport.fanout("DNSW_FORWARDERS", {}, timeout=20.0)
        forwarders: List[Dict[str, Any]] = []
        per_member: Dict[str, Any] = {}
        errors: Dict[str, str] = {}
        for member_id, reply in (fan.get("results") or {}).items():
            per_member[member_id] = reply
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS":
                errors[member_id] = ((reply or {}).get("message")
                                     or (reply or {}).get("error")
                                     or "no response")
                continue
            for entry in reply.get("forwarders") or []:
                if isinstance(entry, dict):
                    forwarders.append({**entry, "member_id": member_id})
        return {"status": "SUCCESS", "forwarders": forwarders, "cluster": True,
                "members": per_member, "member_errors": errors}

    async def _cluster_add_forwarder(self, data: Dict[str, Any]) -> Dict[str, Any]:
        fan = await self._transport.fanout(
            "DNSW_FORWARDER_ADD", data, timeout=20.0)
        if not fan.get("failed"):
            return {"status": "SUCCESS", "zone": data.get("zone"),
                    "upstreams": data.get("upstreams"), "members": fan["results"]}
        ambiguous = [
            member_id for member_id in (fan.get("failed") or [])
            if "changed" not in (fan.get("results", {}).get(member_id) or {})
        ]
        rollback_ids = [*(fan.get("ok") or []), *ambiguous]
        rollback = {"status": "SUCCESS", "ok": [], "failed": [], "results": {}}
        if rollback_ids:
            rollback = await self._transport.fanout(
                "DNSW_FORWARDER_REMOVE", {"zone": data.get("zone")},
                timeout=20.0, member_ids=rollback_ids)
        failed = ", ".join(fan.get("failed") or [])
        # Without the members' own messages this reads "not added to all
        # resolvers (<uuid>, <uuid>)" and nothing else, so the actual cause
        # ("already forwards to ...", a bad address, a reload failure) is only
        # recoverable by reading each resolver's log by hand.
        reasons = []
        for member_id in (fan.get("failed") or []):
            reason = str(((fan.get("results") or {}).get(member_id)
                          or {}).get("message") or "").strip()
            if reason and reason not in reasons:
                reasons.append(reason)
        message = f"forwarder was not added to all resolvers ({failed})"
        if reasons:
            message += ": " + "; ".join(reasons)
        if rollback.get("failed"):
            message += "; rollback also failed on " + ", ".join(rollback["failed"])
        return {"status": "ERROR", "message": message,
                "members": fan["results"], "rollback": rollback}

    async def _cluster_status_summary(self) -> Dict[str, Any]:
        """DNS_STATUS in cluster mode — never one host's answer for the pair."""
        await self.cluster.refresh_state()
        report = self.cluster.cluster_report()
        running = [m["id"] for m in report["members"] if m.get("unbound_running")]
        return {
            "status": "SUCCESS",
            "running": bool(running) and len(running) == report["member_count"],
            "record_count": self.desired.snapshot()["record_count"],
            "conf_path": self.mgr.conf_path,
            "cluster": report,
        }

    # ── Command dispatch ────────────────────────────────────────────────────

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a hub command to the Unbound manager (or to the cluster).

        Every ``UnboundManager`` call is offloaded to a worker thread via
        ``asyncio.to_thread``: ``unbound-control`` is a sync subprocess and this
        role shares one event loop with the dhcp + base role sub-spokes, so a
        hung reload/status would otherwise block every in-flight request across
        all three sub-spokes. Cluster calls are already async (websocket RPC).
        """
        cmd = command_type.upper()

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "DNS_CLUSTER_CONFIG":
            return await self._apply_cluster_config(data)

        if cmd == "DNS_CLUSTER_STATUS":
            if self.cluster.state_error:
                return {"status": "ERROR", "enabled": True,
                        "state_unavailable": True,
                        "message": self.cluster.state_error}
            if not self.cluster.enabled:
                return {"status": "SUCCESS", "enabled": False, "members": [],
                        "member_count": 0,
                        "reason": "fewer than two resolver members configured"}
            return await self._cluster_status()

        if cmd == "DNS_CLUSTER_RECONCILE":
            if not self.cluster.enabled:
                return {"status": "ERROR", "message": "DNS cluster is not enabled"}
            return await self.cluster.reconcile()

        # ── Clustered path: the coordinator owns the record set ──────────────
        if self.cluster.enabled:
            try:
                if cmd == "DNS_SYNC":
                    return await self.cluster.apply_records(data.get("records", []))
                if cmd == "DNS_DELETE":
                    if not data.get("name"):
                        return {"status": "ERROR", "message": "name is required"}
                    return await self.cluster.mutate("delete", data)
                if cmd in ("DNS_ADD", "DNS_UPDATE"):
                    if not data.get("name") or not data.get("value"):
                        return {"status": "ERROR",
                                "message": "name and value are required"}
                    return await self.cluster.mutate(
                        "add" if cmd == "DNS_ADD" else "update", data)
            except DnsRecordError as e:
                return {"status": "ERROR", "message": str(e)}
            except DnsStateUnavailable as e:
                # Fail closed: the authoritative record set is untrustworthy, so
                # no resolver is touched until an operator repairs it.
                return {"status": "ERROR", "message": str(e),
                        "state_unavailable": True}
            if cmd == "DNS_LIST":
                return {"status": "SUCCESS", "records": list(self.desired.records),
                        "cluster": True, "version": self.desired.version}
            if cmd == "DNS_STATUS":
                return await self._cluster_status_summary()
            if cmd == "DNS_DIAGNOSTICS":
                return await self._cluster_diagnostics()
            if cmd == "DNS_STATS":
                return await self._cluster_stats(search=data.get("search"),
                                                 source_prefixes=data.get("source_prefixes"))
            if cmd == "DNS_FORWARDERS":
                return await self._cluster_forwarders()
            if cmd == "DNS_FORWARDER_ADD":
                return await self._cluster_add_forwarder(data)

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

        if cmd == "DNS_DIAGNOSTICS":
            return await asyncio.to_thread(self.mgr.diagnostics)

        if cmd == "DNS_STATS":
            search = data.get("search")
            source_prefixes = data.get("source_prefixes")
            return await asyncio.to_thread(self.mgr.get_stats, search, source_prefixes)

        if cmd == "DNS_FORWARDERS":
            return await asyncio.to_thread(self.mgr.list_forwarders)

        if cmd == "DNS_FORWARDER_ADD":
            return await asyncio.to_thread(
                self.mgr.add_forwarder,
                data.get("zone", "."),
                data.get("upstreams", []),
            )

        return {"status": "ERROR", "error": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        # Polled by the hub for telemetry — offload the sync unbound-control
        # status subprocess off the shared loop (same reason as handle_command).
        if self.cluster.enabled:
            report = self.cluster.cluster_report()
            reachable = report["member_count"] - len(report["unreachable"])
            return {
                "spoke_id":     self.spoke_id,
                "module":       "dns",
                "unbound":      "cluster",
                "record_count": self.desired.snapshot()["record_count"],
                "cluster": {
                    "members":   report["member_count"],
                    "connected": reachable,
                    "converged": report["converged"],
                    "state":     report["state"],
                    "version":   self.desired.version,
                },
                # Converged AND fully reachable is the only healthy state — a
                # half-applied record set must never render green.
                "status": ("HEALTHY"
                           if report["converged"] and reachable == report["member_count"]
                           else "DEGRADED"),
            }
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
