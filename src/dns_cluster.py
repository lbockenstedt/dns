"""Two-resolver DNS cluster: desired state, fan-out, convergence, reconcile.

One ``dns`` spoke (the **coordinator**) owns the authoritative record set and
drives N Unbound hosts (the **workers**). The coordinator — not any individual
resolver — is the source of truth:

* Every mutation (``DNS_SYNC`` / ``DNS_ADD`` / ``DNS_UPDATE`` / ``DNS_DELETE``)
  is applied to an in-memory desired state, **validated**, versioned, digested,
  persisted, and only then fanned out to every member.
* A member that fails or is offline does NOT downgrade the desired state. The
  fan-out reports ``PARTIAL`` (never ``SUCCESS``) and the reconcile pass drives
  the laggard forward once it is reachable again — which is also what converges
  a worker that reconnects after a reboot.
* Convergence is measured, not assumed: each worker reports the version + digest
  it actually has on disk, and :meth:`DnsClusterCoordinator.cluster_report`
  compares that against the desired digest to surface drift.

Records are validated against **directive injection** before they ever reach a
worker. Unbound config is line-oriented and quote-delimited
(``local-data: "name. ttl IN A 10.0.0.1"``), so an unvalidated value containing a
quote or newline could append arbitrary ``server:`` directives to the resolver's
config. :func:`validate_records` rejects those outright rather than escaping
them — a record that needs a quote or a newline is not a record.

Without 2+ configured members this module is inert: the spoke keeps its original
single-host local behavior.
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("DNSCluster")

#: Worker operations the coordinator may ever issue. Fixed at import; never
#: derived from a request. See ``dns_worker.py`` for the implementations.
DNS_WORKER_OPS = (
    "DNSW_APPLY",        # apply a versioned desired-state record set
    "DNSW_STATE",        # report applied version/digest/record count
    "DNSW_STATUS",       # unbound running + record count
    "DNSW_DIAGNOSTICS",  # full local diagnostics evidence
    "DNSW_STATS",        # unbound-control stats_noreset counters
    "DNSW_FORWARDERS",   # unbound-control list_forwards upstream resolvers
    "DNSW_STANDDOWN",    # leave the cluster: forget the applied-version marker
)

RECORD_TYPES = ("A", "AAAA", "CNAME", "PTR")

#: A single DNS label/name. Deliberately strict: letters, digits, hyphen,
#: underscore (SRV/DKIM style), dots as separators, optional trailing dot.
#: No quotes, whitespace, newlines, backslashes or ``;`` — the exact characters
#: that would let a value break out of the ``local-data: "…"`` string.
_NAME_RE = re.compile(r"^(?!-)[A-Za-z0-9_*-]{1,63}(?<!-)"
                      r"(?:\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$")

MIN_TTL = 1
MAX_TTL = 604800


#: Where the coordinator persists its member list. Local to the spoke because
#: the hub is a relay, not a brain: the operator's intent arrives as a
#: ``DNS_CLUSTER_CONFIG`` command and the spoke owns it from there.
DEFAULT_CLUSTER_CONFIG = "/etc/lm-dns/cluster.json"
DEFAULT_DESIRED_STATE = "/var/lib/lm-dns/desired.json"


class DnsRecordError(ValueError):
    """A record failed validation and must not reach any resolver."""


class DnsStateUnavailable(RuntimeError):
    """The authoritative desired state could not be read or written.

    Fail CLOSED: without trustworthy persisted state the coordinator cannot know
    what version the resolvers should be on, so it must refuse to mutate or
    reconcile rather than fan out a set it may not be able to remember.
    """


def load_cluster_config(path: str) -> Dict[str, Any]:
    """Read the persisted member list. Missing/garbage file → cluster off."""
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {"members": []}
    except Exception as e:  # noqa: BLE001
        logger.warning("Could not read DNS cluster config %s: %s", path, e)
        return {"members": []}
    if not isinstance(data, dict):
        return {"members": []}
    members = data.get("members")
    return {"members": members if isinstance(members, list) else []}


def save_cluster_config(path: str, members: List[Dict[str, str]]) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump({"members": members}, fh, indent=2)
    os.replace(tmp, path)


def _clean(value: Any) -> str:
    return str(value if value is not None else "").strip()


def validate_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return the canonical form of one record, or raise :class:`DnsRecordError`.

    Canonical means: name lowercased without the trailing dot, type uppercased,
    IP values normalized through :mod:`ipaddress` (so ``10.00.1.5`` and
    ``10.0.1.5`` cannot masquerade as two different records), TTL an int in
    range. Canonicalization is what makes the digest stable — two coordinators
    given the same intent produce the same digest.
    """
    if not isinstance(record, dict):
        raise DnsRecordError(f"record must be an object, got {type(record).__name__}")
    name = _clean(record.get("name")).rstrip(".").lower()
    rtype = _clean(record.get("type") or "A").upper()
    value = _clean(record.get("value"))
    if not name:
        raise DnsRecordError("record name is required")
    if not value:
        raise DnsRecordError(f"record '{name}' has no value")
    if rtype not in RECORD_TYPES:
        raise DnsRecordError(
            f"record '{name}' has unsupported type '{rtype}' "
            f"(allowed: {', '.join(RECORD_TYPES)})")
    if not _NAME_RE.match(name):
        raise DnsRecordError(
            f"record name '{name}' is not a valid DNS name — quotes, whitespace, "
            f"newlines and config punctuation are rejected to prevent Unbound "
            f"directive injection")

    if rtype in ("A", "AAAA"):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise DnsRecordError(f"record '{name}' type {rtype} value "
                                 f"'{value}' is not an IP address")
        if rtype == "A" and ip.version != 4:
            raise DnsRecordError(f"record '{name}' type A value '{value}' is IPv6")
        if rtype == "AAAA" and ip.version != 6:
            raise DnsRecordError(f"record '{name}' type AAAA value '{value}' is IPv4")
        value = str(ip)
    else:
        target = value.rstrip(".").lower()
        if not _NAME_RE.match(target):
            raise DnsRecordError(
                f"record '{name}' type {rtype} target '{value}' is not a valid "
                f"DNS name — quotes, whitespace and newlines are rejected to "
                f"prevent Unbound directive injection")
        value = target

    raw_ttl = record.get("ttl", 300)
    try:
        ttl = int(raw_ttl)
    except (TypeError, ValueError):
        raise DnsRecordError(f"record '{name}' has non-numeric ttl {raw_ttl!r}")
    if not MIN_TTL <= ttl <= MAX_TTL:
        raise DnsRecordError(
            f"record '{name}' ttl {ttl} outside {MIN_TTL}-{MAX_TTL}")
    return {"name": name, "type": rtype, "value": value, "ttl": ttl}


def validate_records(records: Iterable[Any]) -> List[Dict[str, Any]]:
    """Validate + canonicalize + de-duplicate a whole record set.

    All-or-nothing: one bad record raises and NOTHING is applied. A partially
    accepted set would put the two resolvers in a state neither the operator nor
    the digest can explain.
    """
    out: List[Dict[str, Any]] = []
    seen = set()
    for record in records or []:
        clean = validate_record(record)
        key = (clean["name"], clean["type"], clean["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(clean)
    return sort_records(out)


def sort_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deterministic ordering so the digest is input-order-independent."""
    return sorted(records, key=lambda r: (r["name"], r["type"], r["value"], r["ttl"]))


def derive_managed_records(parsed: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Reconstruct the coordinator-level record set from a parsed conf file.

    ``UnboundManager.sync`` writes a companion ``local-data-ptr`` for every
    A/AAAA record, so ``list_records()`` returns MORE entries than the desired
    set that produced it. Digesting the raw parse could therefore never match
    the coordinator's digest. This drops exactly those auto-generated companions
    — a PTR whose name is an A/AAAA record's value and whose value is that
    record's name — and leaves explicit PTR records alone.

    This is what makes ``DNSW_STATE`` a hash of what Unbound is ACTUALLY serving
    rather than of a metadata file the worker wrote about itself.
    """
    records = [r for r in (parsed or []) if isinstance(r, dict)]
    auto_ptr = set()
    for r in records:
        if str(r.get("type", "")).upper() in ("A", "AAAA"):
            name = str(r.get("name", "")).rstrip(".").lower()
            value = str(r.get("value", "")).strip()
            auto_ptr.add((value, name))
    out = []
    for r in records:
        rtype = str(r.get("type", "")).upper()
        if rtype == "PTR":
            key = (str(r.get("name", "")).strip(),
                   str(r.get("value", "")).rstrip(".").lower())
            if key in auto_ptr:
                continue
        out.append(r)
    return out


def digest_of_parsed(parsed: Iterable[Dict[str, Any]]) -> str:
    """Canonical digest of a resolver's live managed record set.

    Invalid leftovers (hand-edited lines the parser produced but validation
    rejects) are dropped rather than raising: the point is a comparable
    fingerprint of what is actually served, and an unparseable remnant simply
    makes the digest differ from the desired one — which is the correct answer.
    """
    clean = []
    for record in derive_managed_records(parsed):
        try:
            clean.append(validate_record(record))
        except DnsRecordError:
            continue
    return records_digest(sort_records(clean))


def records_digest(records: List[Dict[str, Any]]) -> str:
    """SHA-256 over the canonical record set — the convergence fingerprint."""
    canonical = json.dumps(sort_records(list(records)), sort_keys=True,
                           separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DnsDesiredState:
    """Versioned, digested, persisted authoritative record set.

    Persistence matters: after a coordinator restart the workers still hold
    version N. Reloading the desired state means the coordinator recognizes them
    as converged instead of re-pushing (and re-versioning) an identical set on
    every restart.
    """

    def __init__(self, state_path: str = ""):
        self.state_path = state_path
        self.version = 0
        self.records: List[Dict[str, Any]] = []
        self.digest = records_digest([])
        self.updated_at = 0.0
        #: Set when the persisted state exists but could not be trusted. While
        #: set, EVERY mutation and reconcile is refused — see
        #: ``DnsClusterCoordinator``. Starting clean would silently republish an
        #: empty record set to both resolvers.
        self.broken = ""
        self._load()

    def _load(self) -> None:
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path) as fh:
                data = json.load(fh)
            records = validate_records(data.get("records") or [])
            digest = records_digest(records)
        except Exception as e:  # noqa: BLE001
            # Unreadable / undecodable / invalid records: the file EXISTS, so
            # something is there we cannot interpret. Fail closed.
            self.broken = (f"desired state at {self.state_path} could not be "
                           f"read: {e}")
            logger.error("%s — DNS cluster mutations and reconcile are blocked "
                         "until it is repaired or removed", self.broken)
            return
        if digest != data.get("digest"):
            # A hand-edited/corrupt state file whose digest doesn't match its
            # own records is not authoritative. Refuse to act on it AND refuse
            # to overwrite it silently.
            self.broken = (f"desired state at {self.state_path} is corrupt: its "
                           f"recorded digest does not match its records")
            logger.error("%s — DNS cluster mutations and reconcile are blocked "
                         "until it is repaired or removed", self.broken)
            return
        self.version = int(data.get("version") or 0)
        self.records = records
        self.digest = digest
        self.updated_at = float(data.get("updated_at") or 0.0)

    def _require_usable(self) -> None:
        if self.broken:
            raise DnsStateUnavailable(self.broken)

    def _persist(self, payload: Dict[str, Any]) -> None:
        """Atomically write the CANDIDATE state. Raises on any failure.

        The caller promotes in memory only after this returns, so a coordinator
        that cannot durably record a version never pushes it to a resolver —
        otherwise a restart would forget a version the workers are already on
        and re-push a lower one.
        """
        if not self.state_path:
            return
        try:
            directory = os.path.dirname(self.state_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp = self.state_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(payload, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.state_path)
        except Exception as e:  # noqa: BLE001
            raise DnsStateUnavailable(
                f"could not persist DNS desired state to {self.state_path}: {e}")

    def set_records(self, records: Iterable[Any]) -> Tuple[int, bool]:
        """Replace the record set. Returns ``(version, changed)``.

        Persist-then-promote: the candidate is written to disk FIRST and the
        in-memory state advances only once that succeeded, so a failed write
        raises :class:`DnsStateUnavailable` and leaves the coordinator exactly
        where it was — no worker apply follows.

        An unchanged set does NOT bump the version — otherwise every periodic
        NetBox re-sync would invent a new version and make every worker look
        momentarily stale.
        """
        self._require_usable()
        clean = validate_records(records)
        digest = records_digest(clean)
        if digest == self.digest and self.version:
            return self.version, False
        candidate_version = self.version + 1
        updated_at = time.time()
        self._persist({"version": candidate_version, "digest": digest,
                       "record_count": len(clean), "updated_at": updated_at,
                       "records": clean})
        self.records = clean
        self.digest = digest
        self.version = candidate_version
        self.updated_at = updated_at
        return self.version, True

    def add(self, record: Dict[str, Any]) -> Tuple[int, bool]:
        self._require_usable()
        clean = validate_record(record)
        merged = [r for r in self.records
                  if not (r["name"] == clean["name"] and r["type"] == clean["type"]
                          and r["value"] == clean["value"])]
        merged.append(clean)
        return self.set_records(merged)

    def update(self, record: Dict[str, Any]) -> Tuple[int, bool]:
        """Replace every record matching name+type with the new value/ttl."""
        self._require_usable()
        clean = validate_record(record)
        merged = [r for r in self.records
                  if not (r["name"] == clean["name"] and r["type"] == clean["type"])]
        merged.append(clean)
        return self.set_records(merged)

    def delete(self, name: str, rtype: Optional[str] = None) -> Tuple[int, bool]:
        self._require_usable()
        target = _clean(name).rstrip(".").lower()
        wanted = _clean(rtype).upper() or None
        merged = [r for r in self.records
                  if not (r["name"] == target
                          and (wanted is None or r["type"] == wanted))]
        return self.set_records(merged)

    def snapshot(self, include_records: bool = False) -> Dict[str, Any]:
        out = {"version": self.version, "digest": self.digest,
               "record_count": len(self.records), "updated_at": self.updated_at}
        if include_records:
            out["records"] = self.records
        return out

    def apply_payload(self) -> Dict[str, Any]:
        """The exact frame body every worker receives for one commit."""
        return {"version": self.version, "digest": self.digest,
                "records": self.records}


class DnsClusterCoordinator:
    """Fan-out + convergence over :class:`~messaging.service_cluster.ClusterCoordinator`.

    ``transport`` is anything exposing the ``ClusterCoordinator`` surface
    (``enabled``, ``member_ids``, ``member_links``, ``fanout``, ``call``); the
    spoke injects the real one, tests inject a fake. Keeping the transport
    behind that narrow interface is what lets the convergence logic be tested
    without a websocket.
    """

    def __init__(self, transport, desired: DnsDesiredState):
        self.transport = transport
        self.desired = desired
        #: member_id → last reported {"version", "digest", "record_count"}
        self.reported: Dict[str, Dict[str, Any]] = {}
        self.last_commit: Dict[str, Any] = {}
        #: Serializes every mutation + commit + reconcile. Without it a
        #: concurrent add and reconcile can interleave their fan-outs and leave
        #: the two resolvers on DIFFERENT versions with the coordinator
        #: believing both landed. Created lazily: the coordinator is built at
        #: spoke construction, which is outside any running loop.
        self._lock: Optional[asyncio.Lock] = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def transaction(self):
        """The SAME lock every apply/mutation/reconcile takes.

        Exposed so the spoke can run a topology change (validate → persist →
        rebind → stand down removed members) as one critical section with the
        record fan-outs. Without it a topology edit could land between an
        apply's validate and its commit, and the fan-out would target a member
        list that no longer exists."""
        return self._get_lock()

    @property
    def enabled(self) -> bool:
        return bool(getattr(self.transport, "enabled", False))

    @property
    def state_error(self) -> str:
        """Non-empty when the persisted desired state is untrustworthy."""
        return self.desired.broken

    # ── Seeding ─────────────────────────────────────────────────────────────

    async def seed(self, local_records: Iterable[Dict[str, Any]],
                   locked: bool = False) -> Dict[str, Any]:
        """Adopt the records already being served as v1.

        Called once, when a single-host module is first turned into a cluster.
        The coordinator has no committed state yet, so without this the first
        write (or the first reconcile pass) would push an EMPTY set over
        resolvers that are already answering.

        **Divergence is never resolved by guessing.** Every populated source
        (the coordinator's own managed conf and each reachable member) must
        agree exactly, or the seed ABORTS with a per-source report. Picking the
        "largest" set would silently erase records unique to the smaller one —
        the resolvers are authoritative for real clients, and a merge could
        equally well resurrect records an operator deliberately removed on one
        node. Two shapes are explicitly safe and adopted without complaint:
        every populated source identical, and exactly one populated source (the
        rest empty).

        Persisting is transactional (``set_records`` writes before promoting),
        so a seed that cannot be recorded raises and leaves the cluster
        un-enabled rather than half-seeded. Idempotent: a coordinator that
        already has a committed version does nothing.

        ``locked=True`` when the caller already holds the transaction lock.
        """
        if locked:
            return await self._seed_locked(local_records)
        async with self._get_lock():
            return await self._seed_locked(local_records)

    async def _seed_locked(self, local_records) -> Dict[str, Any]:
        if self.desired.version:
            return {"status": "SUCCESS", "seeded": False,
                    "reason": "a record set is already committed",
                    "version": self.desired.version}

        sources = {}
        local = [r for r in (local_records or []) if isinstance(r, dict)]
        if local:
            sources["coordinator"] = local
        sources.update(await self._member_record_sets())

        if not sources:
            return {"status": "SUCCESS", "seeded": False,
                    "reason": "no existing records found to adopt", "version": 0}

        fingerprints = {}
        for name, records in sources.items():
            try:
                fingerprints[name] = records_digest(validate_records(records))
            except DnsRecordError as e:
                # A source we cannot even canonicalize is a divergence we must
                # not paper over.
                fingerprints[name] = f"invalid: {e}"
        distinct = set(fingerprints.values())
        if len(distinct) > 1:
            detail = {name: {"digest": digest, "record_count": len(sources[name])}
                      for name, digest in fingerprints.items()}
            logger.error("DNS cluster seed aborted — divergent record sets: %s",
                         detail)
            return {"status": "ERROR", "seeded": False, "divergent": True,
                    "sources": detail, "version": 0,
                    "message": (
                        "The resolvers are not serving the same records, so "
                        "adopting either one would erase records unique to the "
                        "other. Reconcile them by hand (or empty all but one) "
                        "and enable the cluster again. Sources: "
                        + "; ".join(f"{name}={info['record_count']} record(s)"
                                    for name, info in sorted(detail.items())))}

        source = "coordinator" if "coordinator" in sources else sorted(sources)[0]
        version, _changed = self.desired.set_records(sources[source])
        logger.info("DNS cluster seeded from %s with %d record(s) as v%s "
                    "(%d source(s) in agreement)", source,
                    len(self.desired.records), version, len(sources))
        return {"status": "SUCCESS", "seeded": True, "source": source,
                "sources_in_agreement": sorted(sources),
                "version": version, "record_count": len(self.desired.records)}

    async def _member_record_sets(self) -> Dict[str, List[Dict[str, Any]]]:
        """Each reachable member's NON-EMPTY live record set.

        An empty member contributes nothing: "one populated, the rest empty" is
        the ordinary first-enablement shape and must stay safe."""
        try:
            fan = await self.transport.fanout("DNSW_STATE", {}, timeout=15.0)
        except Exception as e:  # noqa: BLE001
            logger.warning("DNS seed: could not read member state: %s", e)
            return {}
        out = {}
        for member_id, reply in (fan.get("results") or {}).items():
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS":
                continue
            records = reply.get("records")
            if isinstance(records, list) and records:
                out[member_id] = records
        return out

    # ── Commit ──────────────────────────────────────────────────────────────

    async def commit(self, timeout: float = 30.0) -> Dict[str, Any]:
        """Push the current desired state to EVERY member.

        The reply is ``SUCCESS`` only when every member confirmed the exact
        desired digest. Anything less is ``PARTIAL`` (some applied) or ``ERROR``
        (none did) — a worker that answers ``SUCCESS`` with the *wrong* digest is
        counted as a failure, because it did not end up in the desired state.
        """
        payload = self.desired.apply_payload()
        result = await self.transport.fanout("DNSW_APPLY", payload, timeout=timeout)
        results = result.get("results") or {}
        applied, failed, errors = [], [], {}
        for member_id in self.transport.member_ids():
            reply = results.get(member_id) or {}
            # A worker only answers SUCCESS after a CONFIRMED reload (see
            # DnsWorkerOps.apply), so a matching digest here means the resolver
            # is actually serving the set — not merely holding it on disk.
            ok = (reply.get("status") == "SUCCESS"
                  and reply.get("digest") == payload["digest"]
                  and reply.get("reloaded") is not False)
            if ok:
                applied.append(member_id)
                self.reported[member_id] = {
                    "version": reply.get("version"),
                    "digest": reply.get("digest"),
                    "recorded_digest": reply.get("digest"),
                    "record_count": reply.get("record_count"),
                    "at": time.time(),
                }
            else:
                failed.append(member_id)
                message = reply.get("message") or reply.get("error") or ""
                if not message and reply.get("status") == "SUCCESS":
                    message = (f"worker reported digest "
                               f"{str(reply.get('digest'))[:12]}… "
                               f"but desired is {payload['digest'][:12]}…")
                errors[member_id] = message or "no response"
                # Its last known state is now unknown-stale; drop the memo so
                # the report shows "unknown" instead of a comforting lie.
                self.reported.pop(member_id, None)

        if not failed:
            status = "SUCCESS"
        elif applied:
            status = "PARTIAL"
        else:
            status = "ERROR"
        self.last_commit = {
            "status": status, "version": self.desired.version,
            "digest": self.desired.digest, "applied": applied,
            "failed": failed, "errors": errors, "at": time.time(),
        }
        if status != "SUCCESS":
            logger.warning("DNS cluster commit v%s %s — applied=%s failed=%s",
                           self.desired.version, status, applied, failed)
        return dict(self.last_commit)

    def _commit_response(self, commit: Dict[str, Any]) -> Dict[str, Any]:
        """Translate a commit verdict into the spoke's hub-facing reply."""
        out = {
            "status": commit["status"],
            "cluster": True,
            "version": commit["version"],
            "digest": commit["digest"],
            "records_written": len(self.desired.records),
            "members_applied": commit["applied"],
            "members_failed": commit["failed"],
            "member_errors": commit["errors"],
        }
        if commit["status"] != "SUCCESS":
            failed = ", ".join(commit["failed"]) or "unknown"
            out["message"] = (
                f"DNS record set v{commit['version']} applied to "
                f"{len(commit['applied'])}/{len(commit['applied']) + len(commit['failed'])} "
                f"resolvers; not applied on: {failed}")
        return out

    async def apply_records(self, records: Iterable[Any]) -> Dict[str, Any]:
        """Replace the whole record set and commit it (the DNS_SYNC path).

        Serialized: the persist + fan-out are one transaction, so a concurrent
        mutation cannot slip a different version between them.
        """
        async with self._get_lock():
            self.desired.set_records(records)   # persists BEFORE any fan-out
            return self._commit_response(await self.commit())

    async def mutate(self, action: str, record: Dict[str, Any]) -> Dict[str, Any]:
        """Single-record add/update/delete against the desired state + commit."""
        async with self._get_lock():
            if action == "add":
                self.desired.add(record)
            elif action == "update":
                self.desired.update(record)
            elif action == "delete":
                self.desired.delete(record.get("name", ""), record.get("type"))
            else:
                raise ValueError(f"unknown mutation: {action}")
            return self._commit_response(await self.commit())

    # ── Convergence ─────────────────────────────────────────────────────────

    async def refresh_state(self, timeout: float = 10.0) -> Dict[str, Any]:
        """Ask every member what it has on disk AND what it confirmed applying."""
        result = await self.transport.fanout("DNSW_STATE", {}, timeout=timeout)
        for member_id, reply in (result.get("results") or {}).items():
            if isinstance(reply, dict) and reply.get("status") == "SUCCESS":
                self.reported[member_id] = {
                    "version": reply.get("version"),
                    # What Unbound's conf file currently holds.
                    "digest": reply.get("digest"),
                    # What the worker CONFIRMED applying (written only after a
                    # successful reload). A conf write whose reload failed
                    # leaves this behind while the disk digest already matches.
                    "recorded_digest": reply.get("recorded_digest"),
                    "record_count": reply.get("record_count"),
                    "running": reply.get("running"),
                    "at": time.time(),
                }
            else:
                self.reported.pop(member_id, None)
        return result

    def member_converged(self, member_id: str) -> bool:
        """True only when a member is BOTH holding and SERVING the desired set.

        Three facts must line up, because each one alone has a false-positive:

        * the live conf digest — what Unbound would serve on its next reload;
        * the recorded (applied) digest — written only after a CONFIRMED reload,
          so a failed reload cannot pass;
        * the applied version — catches a worker that re-applied an older set
          whose digest happens to match a stale desired value.
        """
        state = self.reported.get(member_id) or {}
        return bool(state.get("digest") == self.desired.digest
                    and state.get("recorded_digest") == self.desired.digest
                    and state.get("version") == self.desired.version)

    def member_convergence(self, member_id: str) -> str:
        """``converged`` / ``pending-reload`` / ``drifted`` / ``unknown``."""
        state = self.reported.get(member_id)
        if not state:
            return "unknown"
        if self.member_converged(member_id):
            return "converged"
        if (state.get("digest") == self.desired.digest
                and state.get("recorded_digest") != self.desired.digest):
            # The file is right, the running resolver is not.
            return "pending-reload"
        return "drifted"

    def cluster_report(self) -> Dict[str, Any]:
        """Cluster/member stats, convergence, drift and recommendations.

        Pure — no I/O — so the Diagnostics page can render it from the last
        refresh and tests can assert every branch.
        """
        desired = self.desired.snapshot()
        links = list(self.transport.member_links())
        members = []
        converged_ids, drifted_ids, unreachable_ids = [], [], []
        for link in links:
            state = self.reported.get(link["id"])
            member = dict(link)
            member["applied_version"] = (state or {}).get("version")
            member["applied_digest"] = (state or {}).get("digest")
            member["record_count"] = (state or {}).get("record_count")
            member["unbound_running"] = (state or {}).get("running")
            member["recorded_digest"] = (state or {}).get("recorded_digest")
            if not link["connected"]:
                member["convergence"] = "unreachable"
                unreachable_ids.append(link["id"])
            else:
                convergence = self.member_convergence(link["id"])
                member["convergence"] = convergence
                if convergence == "converged":
                    converged_ids.append(link["id"])
                else:
                    drifted_ids.append(link["id"])
            members.append(member)

        total = len(members)
        converged = len(converged_ids) == total and total > 0
        if converged:
            state_label = "converged"
        elif converged_ids:
            state_label = "partial"
        else:
            state_label = "diverged"

        recommendations: List[str] = []
        if total < 2:
            recommendations.append(
                "Fewer than two DNS resolver members are configured; the cluster "
                "has no redundancy.")
        for member_id in unreachable_ids:
            recommendations.append(
                f"Resolver '{member_id}' is not connected to the DNS module; "
                f"check the lm-dns-worker service and its coordinator URL.")
        for member_id in drifted_ids:
            state = self.reported.get(member_id) or {}
            have = state.get("version")
            if self.member_convergence(member_id) == "pending-reload":
                recommendations.append(
                    f"Resolver '{member_id}' has the desired record set on disk "
                    f"but never confirmed an Unbound reload, so it is still "
                    f"ANSWERING the previous set; it will be re-pushed on the "
                    f"next reconcile pass. Check unbound-control on that host.")
            else:
                recommendations.append(
                    f"Resolver '{member_id}' has record set "
                    f"v{have if have is not None else '?'} but the desired set is "
                    f"v{desired['version']}; it will be re-pushed on the next "
                    f"reconcile pass.")
        for member in members:
            if member["connected"] and member["unbound_running"] is False:
                recommendations.append(
                    f"Unbound is not running on '{member['id']}'; records are "
                    f"written but the resolver is not answering queries.")
        last = self.last_commit
        if last and last.get("status") == "PARTIAL":
            recommendations.append(
                f"The last commit (v{last.get('version')}) only reached "
                f"{len(last.get('applied') or [])} of {total} resolvers — the "
                f"cluster is serving two different record sets until it "
                f"reconciles.")

        return {
            "enabled": True,
            "state": state_label,
            "converged": converged,
            "desired": desired,
            "members": members,
            "member_count": total,
            "converged_count": len(converged_ids),
            "drifted": drifted_ids,
            "unreachable": unreachable_ids,
            "last_commit": dict(last) if last else {},
            "recommendations": recommendations,
        }

    async def reconcile(self) -> Dict[str, Any]:
        """Bring every connected member back to the desired state.

        Called on a timer, so it also covers the reconnect case: a resolver that
        rebooted (or was replaced) reports a stale/absent version on its first
        ``DNSW_STATE`` and is re-pushed automatically. Idempotent — a fully
        converged cluster does no work.

        Refuses to run while the desired state is untrustworthy: re-pushing a
        set we could not read (or an empty one we invented) is worse than
        leaving the resolvers on what they have.
        """
        if not self.enabled:
            return {"status": "SKIPPED", "reason": "cluster not enabled"}
        if self.state_error:
            return {"status": "ERROR", "reconciled": [], "failed": [],
                    "version": self.desired.version, "message": self.state_error}
        if self.desired.version == 0:
            # Nothing has ever been committed. Fanning out the empty default
            # would wipe whatever the resolvers are already serving — the
            # cluster is seeded from the live records on enablement instead.
            return {"status": "SKIPPED", "reconciled": [], "failed": [],
                    "version": 0,
                    "reason": "no committed record set yet — nothing to reconcile"}
        async with self._get_lock():
            return await self._reconcile_locked()

    async def _reconcile_locked(self) -> Dict[str, Any]:
        await self.refresh_state()
        # Not converged == needs a re-push. That deliberately includes
        # "pending-reload" (conf on disk, reload never confirmed): re-issuing
        # DNSW_APPLY is exactly what retries the reload.
        stale = [m["id"] for m in self.transport.member_links()
                 if m["connected"] and not self.member_converged(m["id"])]
        if not stale:
            return {"status": "SUCCESS", "reconciled": [],
                    "version": self.desired.version}
        logger.info("DNS cluster reconcile: re-pushing v%s to %s",
                    self.desired.version, stale)
        payload = self.desired.apply_payload()
        result = await self.transport.fanout("DNSW_APPLY", payload,
                                             member_ids=stale)
        repaired = []
        for member_id in stale:
            reply = (result.get("results") or {}).get(member_id) or {}
            if (reply.get("status") == "SUCCESS"
                    and reply.get("digest") == payload["digest"]
                    and reply.get("reloaded") is not False):
                repaired.append(member_id)
                self.reported[member_id] = {
                    "version": reply.get("version"),
                    "digest": reply.get("digest"),
                    "recorded_digest": reply.get("digest"),
                    "record_count": reply.get("record_count"),
                    "at": time.time(),
                }
        failed = [m for m in stale if m not in repaired]
        return {
            "status": "SUCCESS" if not failed else ("PARTIAL" if repaired else "ERROR"),
            "reconciled": repaired, "failed": failed,
            "version": self.desired.version,
        }
