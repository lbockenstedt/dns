"""``lm-dns-worker`` — the resolver-host half of a clustered DNS deployment.

Runs on each Unbound host and dials its coordinator's ``/ws/agent`` listener
(the ``dns`` module spoke). It is intentionally NOT a generic agent: the op
table below is the complete set of things this process can be asked to do. There
is no ``RUN_COMMAND``, no ``WRITE_FILE``, no caller-supplied path — the conf path
is fixed at start from local config, and the only writable content is a record
set that the coordinator already validated and that this worker re-validates
before touching disk.

Applied state (``version`` + ``digest``) is persisted next to the conf so the
coordinator can tell a rebooted resolver from a drifted one.
"""

import argparse
import asyncio
import json
import logging
import os
import time
from typing import Any, Dict

try:
    from unbound_manager import UnboundManager
except ImportError:  # loaded as a package (src.X)
    from src.unbound_manager import UnboundManager

try:
    from dns_cluster import (
        derive_managed_records, digest_of_parsed, records_digest, validate_records)
except ImportError:  # loaded as a package (src.X)
    from src.dns_cluster import (  # type: ignore
        derive_managed_records, digest_of_parsed, records_digest, validate_records)

logger = logging.getLogger("DNSWorker")

DEFAULT_CONF = "/etc/unbound/conf.d/lm-netbox.conf"
DEFAULT_STATE = "/var/lib/lm-dns-worker/applied.json"
DEFAULT_COORDINATOR_PORT = 8769


class DnsWorkerOps:
    """The fixed operation table exposed to the coordinator."""

    def __init__(self, mgr: UnboundManager, state_path: str = DEFAULT_STATE):
        self.mgr = mgr
        self.state_path = state_path
        self.applied: Dict[str, Any] = self._load_applied()

    # ── Applied-state bookkeeping ───────────────────────────────────────────

    def _load_applied(self) -> Dict[str, Any]:
        try:
            with open(self.state_path) as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except FileNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not read applied state %s: %s", self.state_path, e)
        return {"version": None, "digest": None, "record_count": 0, "at": 0}

    def _save_applied(self, version: Any, digest: str, count: int) -> None:
        self.applied = {"version": version, "digest": digest,
                        "record_count": count, "at": time.time()}
        try:
            directory = os.path.dirname(self.state_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp = self.state_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(self.applied, fh)
            os.replace(tmp, self.state_path)
        except Exception as e:  # noqa: BLE001 — a lost memo is recoverable, a
            # crash here is not: the records are already on disk.
            logger.warning("Could not persist applied state %s: %s",
                           self.state_path, e)

    # ── Operations ──────────────────────────────────────────────────────────

    def apply(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_APPLY`` — write + reload one versioned record set.

        Re-validates and re-digests locally. A payload whose digest does not
        match its own records is rejected: it means the frame was built by
        something that is not the coordinator's desired state, and applying it
        would make the cluster's convergence check meaningless.
        """
        version = data.get("version")
        claimed = str(data.get("digest") or "")
        try:
            records = validate_records(data.get("records") or [])
        except ValueError as e:
            return {"status": "ERROR", "message": f"invalid record set: {e}"}
        digest = records_digest(records)
        if claimed and claimed != digest:
            return {"status": "ERROR",
                    "message": (f"record-set digest mismatch (coordinator "
                                f"{claimed[:12]}…, local {digest[:12]}…)")}
        result = self.mgr.sync(records)
        # ``sync`` now reports a reload failure instead of swallowing it: the
        # conf file changed but the RUNNING resolver did not. Record the applied
        # version only after a confirmed reload, so the coordinator sees this
        # member as drifted (and reconciles it) rather than believing it is on a
        # version it is not serving.
        if result.get("status") != "SUCCESS" or result.get("reloaded") is False:
            return {"status": "ERROR", "reloaded": bool(result.get("reloaded")),
                    "records_written": result.get("records_written", 0),
                    "message": (result.get("message") or result.get("error")
                                or "unbound sync failed")}
        self._save_applied(version, digest, len(records))
        return {"status": "SUCCESS", "version": version, "digest": digest,
                "record_count": len(records), "reloaded": True,
                "records_written": result.get("records_written", 0)}

    def state(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_STATE`` — what this resolver is ACTUALLY serving right now.

        The digest is computed from the managed conf file on disk, not from the
        applied-state marker this worker wrote about itself. Those diverge in
        exactly the cases that matter: someone edited the conf out of band, a
        write partially landed, or the marker survived a conf that did not. A
        digest sourced from the marker would report "converged" for a resolver
        serving something else entirely.

        ``records`` carries the derived set so a coordinator being enabled for
        the first time can adopt what is already live (see ``seed``).
        """
        parsed = self.mgr.list_records()
        derived = derive_managed_records(parsed)
        return {"status": "SUCCESS",
                "version": self.applied.get("version"),
                "digest": digest_of_parsed(parsed),
                "recorded_digest": self.applied.get("digest"),
                "records": derived,
                "record_count": len(derived),
                "applied_at": self.applied.get("at"),
                "running": bool(self.mgr.status().get("running"))}

    def standdown(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_STANDDOWN`` — leave the cluster cleanly.

        Issued when the operator removes this resolver from the topology. Clears
        the applied-version marker so the worker no longer claims membership.
        The RECORDS are deliberately left in place: deleting them would
        blackhole DNS for every client still pointed at this host."""
        self.applied = {"version": None, "digest": None, "record_count": 0,
                        "at": time.time()}
        try:
            if os.path.exists(self.state_path):
                os.remove(self.state_path)
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR",
                    "message": f"could not clear the applied-state marker: {e}"}
        return {"status": "SUCCESS", "changed": True,
                "message": "left the cluster; records left in place"}

    def status(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "SUCCESS", **self.mgr.status()}

    def diagnostics(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        return self.mgr.diagnostics()

    def stats(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        return self.mgr.get_stats()

    def forwarders(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_FORWARDERS`` — this resolver's own upstream forwarders.

        Forwarders are per-resolver configuration, so the coordinator asks each
        member rather than reporting its own box's (which may not even run
        Unbound)."""
        return self.mgr.list_forwarders()

    def add_forwarder(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self.mgr.add_forwarder(
            data.get("zone", "."), data.get("upstreams", []))

    def remove_forwarder(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return self.mgr.remove_forwarder(data.get("zone", ""))

    def op_table(self) -> Dict[str, Any]:
        return {
            "DNSW_APPLY": self.apply,
            "DNSW_STATE": self.state,
            "DNSW_STATUS": self.status,
            "DNSW_DIAGNOSTICS": self.diagnostics,
            "DNSW_STATS": self.stats,
            "DNSW_FORWARDERS": self.forwarders,
            "DNSW_FORWARDER_ADD": self.add_forwarder,
            "DNSW_FORWARDER_REMOVE": self.remove_forwarder,
            "DNSW_STANDDOWN": self.standdown,
        }


def build_worker(member_id: str, coordinator_url: str, secret: str,
                 conf_path: str = DEFAULT_CONF,
                 state_path: str = DEFAULT_STATE):
    """Wire the op table into the shared cluster worker transport."""
    try:
        from core.src.messaging.service_cluster import ServiceWorkerClient
    except ImportError:
        from messaging.service_cluster import ServiceWorkerClient  # type: ignore
    ops = DnsWorkerOps(UnboundManager(conf_path=conf_path), state_path=state_path)
    # default_port drives the URL normalization, which REJECTS a plaintext
    # ws:// to a remote coordinator (the PSK rides in the handshake).
    return ServiceWorkerClient(member_id, coordinator_url, secret,
                               ops.op_table(), hostname=os.uname().nodename,
                               default_port=DEFAULT_COORDINATOR_PORT)


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab Manager DNS cluster worker")
    parser.add_argument("--id", default=os.getenv("LM_DNS_MEMBER_ID", ""),
                        help="cluster member id (must match the module's member list)")
    parser.add_argument("--coordinator", default=os.getenv("LM_DNS_COORDINATOR", ""),
                        help="wss://<dns-module-host>:8769/ws/agent")
    parser.add_argument("--secret", default=os.getenv("LM_DNS_WORKER_SECRET", ""),
                        help="shared worker secret (matches the module's agent_secret)")
    parser.add_argument("--conf", default=os.getenv("UNBOUND_CONF", DEFAULT_CONF))
    parser.add_argument("--state", default=os.getenv("LM_DNS_WORKER_STATE", DEFAULT_STATE))
    args = parser.parse_args()
    if not args.id:
        parser.error("--id is required (or LM_DNS_MEMBER_ID in the environment)")
    if not args.coordinator or not args.secret:
        parser.error("--coordinator and --secret are required "
                     "(or LM_DNS_COORDINATOR / LM_DNS_WORKER_SECRET)")
    logging.basicConfig(
        level=logging.INFO, force=True,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    worker = build_worker(args.id, args.coordinator, args.secret,
                          conf_path=args.conf, state_path=args.state)
    asyncio.run(worker.run())


if __name__ == "__main__":
    main()
