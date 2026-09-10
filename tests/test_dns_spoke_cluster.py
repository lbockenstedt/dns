"""``DNSSpoke`` cluster wiring: single-host behavior is preserved, clustered
writes go to every resolver, and configuration is persisted.

The first test is the regression gate for every existing single-host install:
with no members configured the spoke must still drive its LOCAL
``UnboundManager`` exactly as before.
"""

import asyncio
import json

import pytest

from dns_spoke import DNSSpoke


class FakeMgr:
    def __init__(self):
        self.calls = []
        self.conf_path = "/tmp-unused/lm-netbox.conf"
        self.records = [{"name": "local.example.com", "type": "A",
                         "value": "10.0.9.9", "ttl": 300}]

    def sync(self, records):
        self.calls.append(("sync", list(records)))
        return {"status": "SUCCESS", "records_written": len(records)}

    def list_records(self):
        self.calls.append(("list_records",))
        return [dict(r) for r in self.records]

    def add_record(self, name, rtype, value, ttl):
        self.calls.append(("add_record", name, rtype, value, ttl))
        return {"status": "SUCCESS"}

    def update_record(self, name, rtype, value, ttl):
        self.calls.append(("update_record", name, rtype, value, ttl))
        return {"status": "SUCCESS"}

    def delete_record(self, name, rtype=None):
        self.calls.append(("delete_record", name, rtype))
        return {"status": "SUCCESS"}

    def status(self):
        self.calls.append(("status",))
        return {"running": True, "record_count": 1, "conf_path": self.conf_path}

    def diagnostics(self):
        self.calls.append(("diagnostics",))
        return {"status": "SUCCESS", "healthy": True, "recommendations": []}

    def get_stats(self):
        self.calls.append(("get_stats",))
        return {"status": "SUCCESS", "global": {}, "query_types": {}}

    def list_forwarders(self):
        self.calls.append(("list_forwarders",))
        return {"status": "SUCCESS", "forwarders": [
            {"zone": ".", "class": "IN", "upstreams": ["1.1.1.1"]}]}


class FakeTransport:
    def __init__(self, members):
        self.members = list(members)
        self.sent = []
        self.fail_ops = set()          # {(member_id, command)}
        self.stood_down = []
        self.standdown_fails = set()
        self.member_records = {}       # member_id -> records DNSW_STATE reports

    @property
    def enabled(self):
        return len(self.members) >= 2

    def set_members(self, members):
        self.members = [{"id": (m if isinstance(m, str) else m.get("id")),
                         "host": "" if isinstance(m, str) else m.get("host", ""),
                         "role": ""}
                        for m in members if (m if isinstance(m, str) else m.get("id"))]
        return self.members

    def member_ids(self):
        return [m["id"] for m in self.members]

    def member_links(self):
        return [{"id": m["id"], "host": m["host"], "role": "", "connected": True,
                 "pending_approval": False, "last_seen": 1.0,
                 "seconds_since_seen": 0.5, "version": "1.0"}
                for m in self.members]

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        targets = list(member_ids) if member_ids is not None else self.member_ids()
        self.sent.append((command, data, tuple(targets)))
        results = {}
        for m in targets:
            if (m, command) in self.fail_ops:
                results[m] = {"status": "ERROR", "message": "worker unavailable"}
                continue
            if command == "DNSW_FORWARDERS":
                results[m] = {"status": "SUCCESS", "forwarders": [
                    {"zone": ".", "class": "IN", "upstreams": ["9.9.9.9"]}]}
            elif command == "DNSW_APPLY":
                results[m] = {"status": "SUCCESS", "version": data["version"],
                              "digest": data["digest"],
                              "record_count": len(data["records"])}
            elif command == "DNSW_STATE":
                recs = self.member_records.get(m, [])
                results[m] = {"status": "SUCCESS", "version": None,
                              "digest": None, "records": recs,
                              "record_count": len(recs), "running": True}
            elif command == "DNSW_STANDDOWN":
                if m in self.standdown_fails:
                    results[m] = {"status": "ERROR", "message": "unreachable"}
                    continue
                self.stood_down.append(m)
                results[m] = {"status": "SUCCESS", "changed": True}
            elif command == "DNSW_DIAGNOSTICS":
                results[m] = {"status": "SUCCESS", "healthy": True,
                              "recommendations": [], "service": {"ok": True}}
            elif command == "DNSW_STATS":
                results[m] = {"status": "SUCCESS",
                              "global": {"total_queries": 10, "cache_hits": 5},
                              "query_types": {"A": 10}}
            else:
                results[m] = {"status": "SUCCESS"}
        ok = [member for member, result in results.items()
              if result.get("status") == "SUCCESS"]
        failed = [member for member in targets if member not in ok]
        status = "SUCCESS" if not failed else ("PARTIAL" if ok else "ERROR")
        return {"status": status, "results": results,
                "ok": ok, "failed": failed}

    async def call(self, member_id, command, data, timeout=20.0):
        out = await self.fanout(command, data, member_ids=[member_id])
        return out["results"][member_id]


def _spoke(tmp_path, members=None):
    spoke = DNSSpoke("dns-1", {
        # Keep the real UnboundManager off /etc/unbound; every mgr call is then
        # replaced by FakeMgr below anyway.
        "unbound_conf": str(tmp_path / "conf.d" / "lm-netbox.conf"),
        "cluster_members": members or [],
        "cluster_config": str(tmp_path / "cluster.json"),
        "desired_state": str(tmp_path / "desired.json"),
    })
    spoke.mgr = FakeMgr()
    spoke._transport = FakeTransport(
        [{"id": m, "host": ""} if isinstance(m, str) else m
         for m in (members or [])])
    spoke.cluster.transport = spoke._transport
    return spoke


def _run(coro):
    return asyncio.run(coro)


# ── Single-host: unchanged ──────────────────────────────────────────────────

def test_single_host_writes_still_go_to_the_local_unbound(tmp_path):
    spoke = _spoke(tmp_path)
    assert spoke.cluster.enabled is False
    assert spoke.cluster_listener_required() is False
    assert _run(spoke.handle_command("DNS_SYNC", {"records": [
        {"name": "a.example.com", "type": "A", "value": "10.0.1.1"}]})) == {
        "status": "SUCCESS", "records_written": 1}
    assert _run(spoke.handle_command("DNS_ADD", {
        "name": "b.example.com", "value": "10.0.1.2"}))["status"] == "SUCCESS"
    assert _run(spoke.handle_command("DNS_LIST", {}))["records"][0]["name"] \
        == "local.example.com"
    assert [c[0] for c in spoke.mgr.calls] == [
        "sync", "add_record", "list_records"]
    assert spoke._transport.sent == [], "no cluster traffic on a single host"


def test_single_host_status_and_diagnostics_are_local(tmp_path):
    spoke = _spoke(tmp_path)
    assert _run(spoke.handle_command("DNS_STATUS", {}))["running"] is True
    assert _run(spoke.handle_command("DNS_DIAGNOSTICS", {}))["healthy"] is True
    status = _run(spoke.get_status())
    assert status["unbound"] == "running" and status["status"] == "HEALTHY"
    assert "cluster" not in status


def test_cluster_status_on_a_single_host_says_disabled(tmp_path):
    out = _run(_spoke(tmp_path).handle_command("DNS_CLUSTER_STATUS", {}))
    assert out["enabled"] is False and out["member_count"] == 0


# ── Clustered ───────────────────────────────────────────────────────────────

def test_clustered_writes_fan_out_and_bypass_the_local_manager(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    assert spoke.cluster.enabled is True
    assert spoke.cluster_listener_required() is True
    out = _run(spoke.handle_command("DNS_SYNC", {"records": [
        {"name": "a.example.com", "type": "A", "value": "10.0.1.1"}]}))
    assert out["status"] == "SUCCESS"
    assert sorted(out["members_applied"]) == ["dns-a", "dns-b"]
    assert spoke.mgr.calls == [], "the coordinator must not write its own Unbound"
    assert spoke._transport.sent[0][0] == "DNSW_APPLY"


def test_clustered_list_returns_the_authoritative_desired_set(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    _run(spoke.handle_command("DNS_SYNC", {"records": [
        {"name": "a.example.com", "type": "A", "value": "10.0.1.1"}]}))
    out = _run(spoke.handle_command("DNS_LIST", {}))
    assert out["cluster"] is True and out["version"] == 1
    assert [r["name"] for r in out["records"]] == ["a.example.com"]


def test_clustered_invalid_record_is_rejected_before_any_fanout(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    out = _run(spoke.handle_command("DNS_ADD", {
        "name": 'evil"host.example.com', "value": "10.0.1.1"}))
    assert out["status"] == "ERROR" and "not a valid DNS name" in out["message"]
    assert spoke._transport.sent == []


def test_clustered_diagnostics_carry_the_cluster_and_member_evidence(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    out = _run(spoke.handle_command("DNS_DIAGNOSTICS", {}))
    assert out["cluster"]["member_count"] == 2
    assert set(out["members"]) == {"dns-a", "dns-b"}
    assert out["diagnostics_source"] in ("dns-a", "dns-b")
    # Never converged here (workers report no applied digest) → not healthy.
    assert out["healthy"] is False


def test_clustered_stats_are_summed_across_members(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    out = _run(spoke.handle_command("DNS_STATS", {}))
    assert out["global"]["total_queries"] == 20
    assert out["query_types"] == {"A": 20}


def test_clustered_telemetry_is_degraded_until_converged(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    status = _run(spoke.get_status())
    assert status["unbound"] == "cluster"
    assert status["status"] == "DEGRADED"
    assert status["cluster"]["members"] == 2


# ── Configuration ───────────────────────────────────────────────────────────

class FakePlane:
    def __init__(self, secret=None):
        self.secret = secret
        self.agent_secret = secret or ""
        self.ensured = 0
        self._agent_server_task = None

    def set_agent_secret(self, secret):
        self.secret = secret
        self.agent_secret = secret
        return True

    async def ensure_cluster_listener(self):
        self.ensured += 1
        return True


def test_cluster_config_persists_members_and_sets_the_psk_write_only(tmp_path):
    spoke = _spoke(tmp_path)
    plane = FakePlane()
    spoke.control_plane = plane
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "shared-psk"}))
    assert out["status"] == "SUCCESS" and out["cluster_enabled"] is True
    assert "worker_secret" not in json.dumps(out), "the PSK must never be echoed"
    assert plane.secret == "shared-psk" and plane.ensured == 1
    saved = json.loads((tmp_path / "cluster.json").read_text())
    assert [m["id"] for m in saved["members"]] == ["dns-a", "dns-b"]


def test_cluster_config_rejects_a_bad_body(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane(secret="already-set")
    assert _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {}))["status"] == "ERROR"
    assert _run(spoke.handle_command(
        "DNS_CLUSTER_CONFIG", {"members": "dns-a"}))["status"] == "ERROR"
    assert _run(spoke.handle_command(
        "DNS_CLUSTER_CONFIG", {"members": [{"host": "10.0.1.1"}]}))["status"] == "ERROR"


def test_reconcile_command_requires_a_cluster(tmp_path):
    assert _run(_spoke(tmp_path).handle_command(
        "DNS_CLUSTER_RECONCILE", {}))["status"] == "ERROR"
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    # Nothing committed yet: reconcile must SKIP rather than push an empty set.
    assert _run(spoke.handle_command(
        "DNS_CLUSTER_RECONCILE", {}))["status"] == "SKIPPED"
    _run(spoke.handle_command("DNS_SYNC", {"records": [
        {"name": "a.example.com", "type": "A", "value": "10.0.1.1"}]}))
    assert _run(spoke.handle_command(
        "DNS_CLUSTER_RECONCILE", {}))["status"] in ("SUCCESS", "PARTIAL", "ERROR")


# ── Item 13: clustered forwarders come from the workers ────────────────────

def test_clustered_forwarders_are_aggregated_per_member(tmp_path):
    """REGRESSION (review #13): DNS_FORWARDERS used to fall through to the
    coordinator's own unbound-control, which may not exist on that box."""
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    out = _run(spoke.handle_command("DNS_FORWARDERS", {}))
    assert out["status"] == "SUCCESS" and out["cluster"] is True
    assert {f["member_id"] for f in out["forwarders"]} == {"dns-a", "dns-b"}
    assert all(f["upstreams"] == ["9.9.9.9"] for f in out["forwarders"])
    assert out["member_errors"] == {}
    assert spoke.mgr.calls == [], "the coordinator's own Unbound is not consulted"


def test_clustered_forwarders_surface_a_failing_member(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    spoke._transport.fail_ops.add(("dns-b", "DNSW_FORWARDERS"))
    out = _run(spoke.handle_command("DNS_FORWARDERS", {}))
    assert [f["member_id"] for f in out["forwarders"]] == ["dns-a"]
    assert "dns-b" in out["member_errors"]


def test_single_host_forwarders_still_use_the_local_manager(tmp_path):
    spoke = _spoke(tmp_path)
    out = _run(spoke.handle_command("DNS_FORWARDERS", {}))
    assert out["forwarders"][0]["zone"] == "."
    assert ("list_forwarders",) in spoke.mgr.calls


def test_clustered_forwarder_add_reaches_every_member(tmp_path):
    spoke = _spoke(tmp_path, members=("dns-a", "dns-b"))

    out = _run(spoke.handle_command("DNS_FORWARDER_ADD", {
        "zone": ".", "upstreams": ["1.1.1.1"],
    }))

    assert out["status"] == "SUCCESS"
    assert spoke._transport.sent[-1] == (
        "DNSW_FORWARDER_ADD",
        {"zone": ".", "upstreams": ["1.1.1.1"]},
        ("dns-a", "dns-b"),
    )


def test_clustered_forwarder_add_rolls_back_partial_write(tmp_path):
    spoke = _spoke(tmp_path, members=("dns-a", "dns-b"))
    spoke._transport.fail_ops.add(("dns-b", "DNSW_FORWARDER_ADD"))

    out = _run(spoke.handle_command("DNS_FORWARDER_ADD", {
        "zone": ".", "upstreams": ["1.1.1.1"],
    }))

    assert out["status"] == "ERROR"
    assert spoke._transport.sent[-1] == (
        "DNSW_FORWARDER_REMOVE",
        {"zone": "."},
        ("dns-a", "dns-b"),
    )


# ── Item 8: fail-closed surfaces as an actionable error ────────────────────

def test_a_broken_desired_state_blocks_cluster_writes(tmp_path):
    import json as _json
    (tmp_path / "desired.json").write_text(_json.dumps(
        {"version": 4, "digest": "bogus", "records": []}))
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    out = _run(spoke.handle_command("DNS_SYNC", {"records": [
        {"name": "a.example.com", "type": "A", "value": "10.0.1.1"}]}))
    assert out["status"] == "ERROR" and out["state_unavailable"] is True
    assert spoke._transport.sent == []
    status = _run(spoke.handle_command("DNS_CLUSTER_STATUS", {}))
    assert status["status"] == "ERROR" and status["state_unavailable"] is True


# ── Item 11: the reconcile loop is cancellable ─────────────────────────────

def test_stop_background_loops_cancels_the_reconcile_task(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])

    async def _cycle():
        spoke.start_background_loops()
        task = spoke._reconcile_task
        assert task is not None and not task.done()
        returned = spoke.stop_background_loops()
        assert returned is task
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert task.cancelled() or task.done()
        assert spoke._reconcile_task is None
        # Idempotent: a second stop with nothing running is a no-op.
        assert spoke.stop_background_loops() is None

    asyncio.run(_cycle())


# ── Review #2: the worker secret is never generated ────────────────────────

def test_enabling_a_cluster_without_a_secret_is_refused(tmp_path):
    """REGRESSION: a minted secret nobody can read could never be handed to the
    resolvers, so they could never authenticate."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}]}))
    assert out["status"] == "ERROR" and out["secret_required"] is True
    assert not (tmp_path / "cluster.json").exists()
    assert spoke.cluster.enabled is False, "the topology must be rolled back"


def test_a_resubmit_without_a_secret_keeps_the_stored_one(tmp_path):
    spoke = _spoke(tmp_path)
    plane = FakePlane()
    spoke.control_plane = plane
    _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    again = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}]}))
    assert again["status"] == "SUCCESS" and plane.secret == "psk"


# ── Review #10: enabling seeds from the live records ───────────────────────

def test_enabling_adopts_the_coordinators_existing_records(tmp_path):
    """REGRESSION: with no committed state the first reconcile would have fanned
    an EMPTY set out over resolvers that were already answering."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    spoke.mgr.records = [
        {"name": "live.example.com", "type": "A", "value": "10.0.5.5", "ttl": 300},
        # The auto-generated PTR companion must NOT be adopted as its own record.
        {"name": "10.0.5.5", "type": "PTR", "value": "live.example.com", "ttl": 300},
    ]
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    assert out["status"] == "SUCCESS"
    assert out["seed"]["seeded"] is True and out["seed"]["source"] == "coordinator"
    assert spoke.desired.version == 1
    assert [r["name"] for r in spoke.desired.records] == ["live.example.com"]


def test_enabling_adopts_a_members_records_when_the_coordinator_has_none(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    spoke.mgr.records = []
    spoke._transport.member_records["dns-b"] = [
        {"name": "member.example.com", "type": "A", "value": "10.0.6.6", "ttl": 300}]
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    assert out["seed"]["seeded"] is True and out["seed"]["source"] == "dns-b"
    assert [r["name"] for r in spoke.desired.records] == ["member.example.com"]


def test_reconcile_never_pushes_an_uncommitted_empty_set(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    assert spoke.desired.version == 0
    out = _run(spoke.handle_command("DNS_CLUSTER_RECONCILE", {}))
    assert out["status"] == "SKIPPED"
    assert not [c for c in spoke._transport.sent if c[0] == "DNSW_APPLY"]


def test_seeding_is_idempotent(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    spoke.mgr.records = [
        {"name": "a.example.com", "type": "A", "value": "10.0.1.1", "ttl": 300}]
    _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    version = spoke.desired.version
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}]}))
    assert out["seed"] == {} or out["seed"].get("seeded") is False
    assert spoke.desired.version == version


# ── Review #12: topology restore on failure ────────────────────────────────

def test_a_failed_topology_save_restores_the_previous_members(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    spoke.control_plane = FakePlane(secret="already-set")
    before = [m["id"] for m in spoke._transport.members]
    spoke._cluster_config_path = str(tmp_path / "missing" / "\0bad" / "c.json")
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-x", "host": "10.0.9.1"},
                    {"id": "dns-y", "host": "10.0.9.2"}]}))
    assert out["status"] == "ERROR"
    assert [m["id"] for m in spoke._transport.members] == before


# ── Review #13: removed resolvers are stood down or reported ───────────────

def test_removing_a_member_stands_it_down(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    spoke.control_plane = FakePlane(secret="already-set")
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {"members": []}))
    assert out["status"] == "SUCCESS"
    assert sorted(out["removed_stood_down"]) == ["dns-a", "dns-b"]
    assert sorted(spoke._transport.stood_down) == ["dns-a", "dns-b"]


def test_an_unreachable_removed_member_is_reported_as_partial(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    spoke.control_plane = FakePlane(secret="already-set")
    spoke._transport.standdown_fails.add("dns-a")
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {"members": []}))
    assert out["status"] == "PARTIAL"
    assert out["removed_unreachable"] == ["dns-a"]
    assert "still hold their cluster marker" in out["message"]


# ── Round 3, #3: the seed never picks a winner between divergent sets ──────

def _members_reporting(spoke, mapping):
    spoke._transport.member_records.update(mapping)


def test_identical_member_sets_seed_safely(tmp_path):
    """Explicitly safe shape: every populated source agrees."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    spoke.mgr.records = []
    same = [{"name": "a.example.com", "type": "A", "value": "10.0.1.1", "ttl": 300}]
    _members_reporting(spoke, {"dns-a": [dict(r) for r in same],
                               "dns-b": [dict(r) for r in same]})
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    assert out["status"] == "SUCCESS"
    assert out["seed"]["seeded"] is True
    assert sorted(out["seed"]["sources_in_agreement"]) == ["dns-a", "dns-b"]
    assert [r["name"] for r in spoke.desired.records] == ["a.example.com"]


def test_one_populated_one_empty_seeds_safely(tmp_path):
    """Explicitly safe shape: the ordinary first-enablement case."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    spoke.mgr.records = []
    _members_reporting(spoke, {
        "dns-a": [{"name": "only.example.com", "type": "A",
                   "value": "10.0.1.7", "ttl": 300}],
        "dns-b": []})
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    assert out["status"] == "SUCCESS" and out["seed"]["seeded"] is True
    assert out["seed"]["source"] == "dns-a"
    assert [r["name"] for r in spoke.desired.records] == ["only.example.com"]


def test_divergent_member_sets_abort_instead_of_erasing(tmp_path):
    """REGRESSION (round 3, #3): picking the LARGEST set silently erased every
    record unique to the smaller one."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    spoke.mgr.records = []
    _members_reporting(spoke, {
        "dns-a": [{"name": "a.example.com", "type": "A", "value": "10.0.1.1",
                   "ttl": 300},
                  {"name": "extra.example.com", "type": "A", "value": "10.0.1.2",
                   "ttl": 300}],
        "dns-b": [{"name": "unique-to-b.example.com", "type": "A",
                   "value": "10.0.1.3", "ttl": 300}]})
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    assert out["status"] == "ERROR" and out["divergent"] is True
    assert set(out["seed"]["sources"]) == {"dns-a", "dns-b"}
    assert out["seed"]["sources"]["dns-a"]["record_count"] == 2
    assert out["seed"]["sources"]["dns-b"]["record_count"] == 1
    assert "erase records unique" in out["message"]
    # Nothing was adopted and nothing was pushed.
    assert spoke.desired.version == 0
    assert not [c for c in spoke._transport.sent if c[0] == "DNSW_APPLY"]
    # And the module is left single-host, not half-enabled: the persisted
    # topology is rolled back to the previous (empty) member list.
    assert spoke.cluster.enabled is False
    assert json.loads((tmp_path / "cluster.json").read_text())["members"] == []


def test_coordinator_records_that_differ_from_a_member_also_abort(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    spoke.mgr.records = [{"name": "coord.example.com", "type": "A",
                          "value": "10.0.1.1", "ttl": 300}]
    _members_reporting(spoke, {
        "dns-a": [{"name": "member.example.com", "type": "A",
                   "value": "10.0.1.9", "ttl": 300}]})
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    assert out["status"] == "ERROR" and out["divergent"] is True
    assert "coordinator" in out["seed"]["sources"]
    assert spoke.desired.version == 0


def test_a_coordinator_set_matching_the_members_is_adopted(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    shared = [{"name": "same.example.com", "type": "A", "value": "10.0.1.4",
               "ttl": 300}]
    spoke.mgr.records = [dict(r) for r in shared]
    _members_reporting(spoke, {"dns-a": [dict(r) for r in shared]})
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    assert out["status"] == "SUCCESS"
    assert out["seed"]["source"] == "coordinator"
    assert [r["name"] for r in spoke.desired.records] == ["same.example.com"]


# ── Round 3, #2: the listener must be READY before we report success ───────

class _ListenerPlane(FakePlane):
    def __init__(self, result):
        super().__init__()
        self.result = result

    async def ensure_cluster_listener(self, timeout=20.0):
        self.ensured += 1
        return self.result


def test_a_listener_that_fails_to_start_is_reported_as_an_error(tmp_path):
    """REGRESSION: returning SUCCESS before an asynchronous bind/TLS failure
    told the operator the cluster was configured when no worker could ever
    connect."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = _ListenerPlane(
        {"ok": False, "serving": False, "endpoint": "",
         "error": "no TLS certificate for the dns cluster listener"})
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    assert out["status"] == "ERROR"
    assert "did not start" in out["message"]
    assert "no TLS certificate" in out["listener"]["error"]
    assert spoke.cluster.enabled is False
    assert json.loads((tmp_path / "cluster.json").read_text())["members"] == []


def test_a_ready_listener_reports_its_endpoint(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = _ListenerPlane(
        {"ok": True, "serving": True, "endpoint": "wss://0.0.0.0:8769",
         "error": ""})
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    assert out["status"] == "SUCCESS"
    assert out["listener"]["serving"] is True
    assert out["listener"]["endpoint"] == "wss://0.0.0.0:8769"


def test_an_older_core_returning_a_bool_is_tolerated(tmp_path):
    """Backward compatibility: the spoke and core deploy independently."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = _ListenerPlane(True)
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "psk"}))
    assert out["status"] == "SUCCESS"


# ── Round 3, #6: topology edits share the apply lock ──────────────────────

def test_topology_change_and_apply_do_not_interleave(tmp_path):
    """REGRESSION: a topology edit landing between an apply's validate and its
    commit made the fan-out target a member list that no longer existed."""
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    spoke.control_plane = FakePlane(secret="already-set")
    _run(spoke.handle_command("DNS_SYNC", {"records": [
        {"name": "a.example.com", "type": "A", "value": "10.0.1.1"}]}))
    spoke._transport.sent.clear()

    async def _race():
        return await asyncio.gather(
            spoke.handle_command("DNS_SYNC", {"records": [
                {"name": "b.example.com", "type": "A", "value": "10.0.1.2"}]}),
            spoke.handle_command("DNS_CLUSTER_CONFIG", {
                "members": [{"id": "dns-a", "host": "10.0.1.1"},
                            {"id": "dns-b", "host": "10.0.1.2"}]}))

    sync_out, topo_out = asyncio.run(_race())
    assert sync_out["status"] == "SUCCESS"
    assert topo_out["status"] == "SUCCESS"
    # The sync's fan-out reached BOTH members as one uninterrupted unit.
    applies = [c for c in spoke._transport.sent if c[0] == "DNSW_APPLY"]
    assert applies and all(set(c[2]) == {"dns-a", "dns-b"} for c in applies)


# ── Round 4, #4: a rolled-back topology restores the previous PSK ──────────

class _SecretPlane(FakePlane):
    def __init__(self, result, secret=None):
        super().__init__(secret=secret)
        self.result = result
        self.restored = []

    async def ensure_cluster_listener(self, timeout=20.0):
        self.ensured += 1
        return self.result

    def snapshot_agent_secret(self):
        return str(self.agent_secret or "")

    def restore_agent_secret(self, previous):
        self.restored.append(previous)
        self.secret = previous or None
        self.agent_secret = previous
        return True


def test_a_listener_failure_restores_the_previous_worker_secret(tmp_path):
    """REGRESSION (round 4, #4): the new PSK was written before the listener
    could fail, so a rejected change left every already-provisioned resolver
    unable to authenticate against a coordinator whose config was reverted."""
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    plane = _SecretPlane({"ok": False, "serving": False, "endpoint": "",
                          "error": "could not bind 0.0.0.0:8769"},
                         secret="original-psk")
    spoke.control_plane = plane
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "brand-new-psk"}))
    assert out["status"] == "ERROR"
    assert plane.agent_secret == "original-psk", \
        "already-provisioned workers must keep authenticating"
    assert plane.restored == ["original-psk"]


def test_a_divergent_seed_restores_the_previous_worker_secret(tmp_path):
    """The seed abort is a rollback too — the credential rolls back with it."""
    spoke = _spoke(tmp_path)
    plane = _SecretPlane({"ok": True, "serving": True,
                          "endpoint": "wss://0.0.0.0:8769", "error": ""},
                         secret="original-psk")
    spoke.control_plane = plane
    spoke.mgr.records = []
    spoke._transport.member_records.update({
        "dns-a": [{"name": "a.example.com", "type": "A", "value": "10.0.1.1",
                   "ttl": 300}],
        "dns-b": [{"name": "b.example.com", "type": "A", "value": "10.0.1.2",
                   "ttl": 300}]})
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "brand-new-psk"}))
    assert out["status"] == "ERROR" and out["divergent"] is True
    assert plane.agent_secret == "original-psk"
    assert plane.restored == ["original-psk"]


def test_a_successful_change_keeps_the_new_worker_secret(tmp_path):
    spoke = _spoke(tmp_path)
    plane = _SecretPlane({"ok": True, "serving": True,
                          "endpoint": "wss://0.0.0.0:8769", "error": ""},
                         secret="original-psk")
    spoke.control_plane = plane
    spoke.mgr.records = []
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-a", "host": "10.0.1.1"},
                    {"id": "dns-b", "host": "10.0.1.2"}],
        "worker_secret": "brand-new-psk"}))
    assert out["status"] == "SUCCESS"
    assert plane.agent_secret == "brand-new-psk"
    assert plane.restored == []


def test_a_failed_topology_save_restores_the_previous_worker_secret(tmp_path):
    spoke = _spoke(tmp_path, ["dns-a", "dns-b"])
    plane = _SecretPlane({"ok": True, "serving": True, "endpoint": "x",
                          "error": ""}, secret="original-psk")
    spoke.control_plane = plane
    spoke._cluster_config_path = str(tmp_path / "missing" / "\0bad" / "c.json")
    out = _run(spoke.handle_command("DNS_CLUSTER_CONFIG", {
        "members": [{"id": "dns-x", "host": "10.0.9.1"},
                    {"id": "dns-y", "host": "10.0.9.2"}],
        "worker_secret": "brand-new-psk"}))
    assert out["status"] == "ERROR"
    # The save fails BEFORE the secret is staged, so nothing to restore — and
    # the PSK in force is still the original.
    assert plane.agent_secret == "original-psk"
