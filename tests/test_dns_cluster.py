"""DNS resolver-cluster tests: validation, versioning, convergence, reconcile.

The properties that matter, in the order the code depends on them:

* **Directive injection is rejected, not escaped.** Unbound's config is
  quote-delimited and line-oriented, so a record value containing a quote or a
  newline could append arbitrary ``server:`` directives to a resolver's config.
* **The digest is canonical.** Two record sets expressing the same intent must
  digest identically regardless of input order/case/formatting, or convergence
  checking is meaningless.
* **A partial commit is reported as PARTIAL.** Including the subtle case where a
  worker answers ``SUCCESS`` but with the WRONG digest — it did not reach the
  desired state, so it is a failure.
* **Reconcile repairs drift and reconnects** without re-pushing to a member that
  is already converged.
"""

import asyncio

import pytest

from dns_cluster import (
    DnsClusterCoordinator, DnsDesiredState, DnsRecordError, DnsStateUnavailable,
    records_digest, load_cluster_config, save_cluster_config, validate_record,
    validate_records,
)


# ── Validation / injection ──────────────────────────────────────────────────

def test_valid_record_is_canonicalized():
    assert validate_record({"name": "Host.Example.COM.", "type": "a",
                            "value": "10.0.1.5", "ttl": "300"}) == {
        "name": "host.example.com", "type": "A", "value": "10.0.1.5", "ttl": 300}


@pytest.mark.parametrize("value", [
    '10.0.1.5"\n    forward-zone:\n        name: "."',   # break out of local-data
    '10.0.1.5"',
    "10.0.1.5\nlocal-data: \"evil.example.com. 300 IN A 1.2.3.4\"",
])
def test_injection_in_a_record_value_is_rejected(value):
    with pytest.raises(DnsRecordError):
        validate_record({"name": "host.example.com", "type": "A", "value": value})


@pytest.mark.parametrize("name", [
    'host.example.com" 300 IN A 6.6.6.6"',
    "host.example.com\n    local-zone: \".\" refuse",
    "host example com",
    'a"b.example.com',
    "host;example.com",
])
def test_injection_in_a_record_name_is_rejected(name):
    with pytest.raises(DnsRecordError, match="not a valid DNS name"):
        validate_record({"name": name, "type": "A", "value": "10.0.1.5"})


def test_cname_target_is_validated_too():
    with pytest.raises(DnsRecordError, match="not a valid DNS name"):
        validate_record({"name": "alias.example.com", "type": "CNAME",
                         "value": 'target.example.com" 1 IN A 1.2.3.4'})


@pytest.mark.parametrize("record,match", [
    ({"name": "", "type": "A", "value": "10.0.1.5"}, "name is required"),
    ({"name": "h.example.com", "type": "A", "value": ""}, "no value"),
    ({"name": "h.example.com", "type": "SRV", "value": "x"}, "unsupported type"),
    ({"name": "h.example.com", "type": "A", "value": "not-an-ip"}, "not an IP"),
    ({"name": "h.example.com", "type": "A", "value": "fd00::1"}, "is IPv6"),
    ({"name": "h.example.com", "type": "AAAA", "value": "10.0.1.5"}, "is IPv4"),
    ({"name": "h.example.com", "type": "A", "value": "10.0.1.5", "ttl": "x"}, "non-numeric"),
    ({"name": "h.example.com", "type": "A", "value": "10.0.1.5", "ttl": 0}, "outside"),
    ({"name": "h.example.com", "type": "A", "value": "10.0.1.5", "ttl": 10 ** 9}, "outside"),
])
def test_bad_records_are_rejected_with_an_actionable_message(record, match):
    with pytest.raises(DnsRecordError, match=match):
        validate_record(record)


def test_one_bad_record_rejects_the_whole_set():
    good = {"name": "a.example.com", "type": "A", "value": "10.0.1.5"}
    with pytest.raises(DnsRecordError):
        validate_records([good, {"name": "b.example.com", "type": "A", "value": "x"}])


def test_duplicate_records_collapse():
    rec = {"name": "a.example.com", "type": "A", "value": "10.0.1.5", "ttl": 300}
    assert len(validate_records([rec, dict(rec)])) == 1


# ── Digest ──────────────────────────────────────────────────────────────────

def _recs(*pairs):
    return [{"name": n, "type": "A", "value": v, "ttl": 300} for n, v in pairs]


def test_digest_is_order_independent():
    a = _recs(("a.example.com", "10.0.1.1"), ("b.example.com", "10.0.1.2"))
    assert (records_digest(validate_records(a))
            == records_digest(validate_records(list(reversed(a)))))


def test_digest_changes_with_content():
    a = validate_records(_recs(("a.example.com", "10.0.1.1")))
    b = validate_records(_recs(("a.example.com", "10.0.1.2")))
    assert records_digest(a) != records_digest(b)


# ── Desired state ───────────────────────────────────────────────────────────

def test_version_bumps_only_on_a_real_change(tmp_path):
    state = DnsDesiredState(str(tmp_path / "desired.json"))
    v1, changed = state.set_records(_recs(("a.example.com", "10.0.1.1")))
    assert (v1, changed) == (1, True)
    v2, changed = state.set_records(_recs(("a.example.com", "10.0.1.1")))
    assert (v2, changed) == (1, False), "an identical re-sync must not re-version"
    v3, changed = state.set_records(_recs(("a.example.com", "10.0.1.2")))
    assert (v3, changed) == (2, True)


def test_desired_state_survives_a_coordinator_restart(tmp_path):
    path = str(tmp_path / "desired.json")
    first = DnsDesiredState(path)
    first.set_records(_recs(("a.example.com", "10.0.1.1")))
    reloaded = DnsDesiredState(path)
    assert reloaded.version == first.version
    assert reloaded.digest == first.digest
    assert reloaded.records == first.records


def test_a_tampered_state_file_is_ignored(tmp_path):
    import json
    path = tmp_path / "desired.json"
    path.write_text(json.dumps({
        "version": 9, "digest": "not-the-real-digest",
        "records": _recs(("evil.example.com", "6.6.6.6"))}))
    state = DnsDesiredState(str(path))
    assert state.version == 0 and state.records == []


def test_add_update_delete_mutations():
    state = DnsDesiredState("")
    state.add({"name": "a.example.com", "type": "A", "value": "10.0.1.1"})
    state.add({"name": "b.example.com", "type": "A", "value": "10.0.1.2"})
    assert len(state.records) == 2
    state.update({"name": "a.example.com", "type": "A", "value": "10.0.1.9"})
    assert [r for r in state.records if r["name"] == "a.example.com"][0]["value"] == "10.0.1.9"
    state.delete("b.example.com")
    assert [r["name"] for r in state.records] == ["a.example.com"]
    state.delete("a.example.com", "AAAA")
    assert len(state.records) == 1, "type-scoped delete must not remove the A record"


def test_cluster_config_round_trip(tmp_path):
    path = str(tmp_path / "cluster.json")
    assert load_cluster_config(path) == {"members": []}
    save_cluster_config(path, [{"id": "dns-a", "host": "10.0.1.1", "role": ""}])
    assert load_cluster_config(path)["members"][0]["id"] == "dns-a"


# ── Coordinator ─────────────────────────────────────────────────────────────

class FakeTransport:
    """ClusterCoordinator surface with scripted per-member replies."""

    def __init__(self, members, replies=None, connected=None):
        self._members = list(members)
        self.replies = replies or {}
        self.connected = set(members if connected is None else connected)
        self.calls = []

    enabled = property(lambda self: len(self._members) >= 2)

    def member_ids(self):
        return list(self._members)

    def member_links(self):
        return [{"id": m, "host": "", "role": "", "connected": m in self.connected,
                 "pending_approval": False, "last_seen": 1.0,
                 "seconds_since_seen": 1.0, "version": "1.0"}
                for m in self._members]

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        targets = list(member_ids) if member_ids is not None else self.member_ids()
        self.calls.append((command, data, tuple(targets)))
        results = {}
        for m in targets:
            if m not in self.connected:
                results[m] = {"status": "ERROR", "message": "not connected"}
                continue
            results[m] = self.replies.get((m, command), {"status": "SUCCESS"})
            if command == "DNSW_APPLY" and results[m].get("status") == "SUCCESS" \
                    and "digest" not in results[m]:
                # A scripted reply's own fields win; the defaults only fill the
                # gaps (a worker confirms the reload before answering SUCCESS).
                results[m] = {"version": data["version"],
                              "digest": data["digest"], "reloaded": True,
                              "record_count": len(data["records"]),
                              **results[m]}
        ok = [m for m, r in results.items() if r.get("status") == "SUCCESS"]
        failed = [m for m in targets if m not in ok]
        return {"status": "SUCCESS" if not failed else ("PARTIAL" if ok else "ERROR"),
                "results": results, "ok": ok, "failed": failed}

    async def call(self, member_id, command, data, timeout=20.0):
        out = await self.fanout(command, data, member_ids=[member_id])
        return out["results"][member_id]


def _coord(transport):
    return DnsClusterCoordinator(transport, DnsDesiredState(""))


def test_commit_to_both_resolvers_is_success():
    asyncio.run(_test_commit_to_both_resolvers_is_success())


async def _test_commit_to_both_resolvers_is_success():
    t = FakeTransport(["dns-a", "dns-b"])
    coord = _coord(t)
    out = await coord.apply_records(_recs(("a.example.com", "10.0.1.1")))
    assert out["status"] == "SUCCESS"
    assert sorted(out["members_applied"]) == ["dns-a", "dns-b"]
    assert coord.cluster_report()["converged"] is True


def test_commit_with_one_resolver_down_is_partial_not_success():
    asyncio.run(_test_commit_with_one_resolver_down_is_partial_not_success())


async def _test_commit_with_one_resolver_down_is_partial_not_success():
    t = FakeTransport(["dns-a", "dns-b"], connected=["dns-a"])
    coord = _coord(t)
    out = await coord.apply_records(_recs(("a.example.com", "10.0.1.1")))
    assert out["status"] == "PARTIAL"
    assert out["members_applied"] == ["dns-a"] and out["members_failed"] == ["dns-b"]
    assert "not applied on: dns-b" in out["message"]
    report = coord.cluster_report()
    assert report["converged"] is False and report["state"] == "partial"


def test_commit_with_both_resolvers_down_is_error():
    asyncio.run(_test_commit_with_both_resolvers_down_is_error())


async def _test_commit_with_both_resolvers_down_is_error():
    t = FakeTransport(["dns-a", "dns-b"], connected=[])
    out = await _coord(t).apply_records(_recs(("a.example.com", "10.0.1.1")))
    assert out["status"] == "ERROR" and out["members_applied"] == []


def test_a_worker_that_confirms_the_wrong_digest_counts_as_failed():
    asyncio.run(_test_a_worker_that_confirms_the_wrong_digest_counts_as_failed())


async def _test_a_worker_that_confirms_the_wrong_digest_counts_as_failed():
    """A SUCCESS carrying a different digest means the worker did NOT reach the
    desired state — laundering that into a green cluster is the exact bug this
    guards."""
    t = FakeTransport(["dns-a", "dns-b"], replies={
        ("dns-b", "DNSW_APPLY"): {"status": "SUCCESS", "version": 1,
                                  "digest": "some-other-digest"}})
    coord = _coord(t)
    out = await coord.apply_records(_recs(("a.example.com", "10.0.1.1")))
    assert out["status"] == "PARTIAL"
    assert out["members_failed"] == ["dns-b"]
    assert "desired is" in out["member_errors"]["dns-b"]


def test_invalid_records_never_reach_a_resolver():
    asyncio.run(_test_invalid_records_never_reach_a_resolver())


async def _test_invalid_records_never_reach_a_resolver():
    t = FakeTransport(["dns-a", "dns-b"])
    coord = _coord(t)
    with pytest.raises(DnsRecordError):
        await coord.apply_records([{"name": 'x"y.example.com', "type": "A",
                                    "value": "10.0.1.1"}])
    assert t.calls == []


def test_mutations_go_to_every_member():
    asyncio.run(_test_mutations_go_to_every_member())


async def _test_mutations_go_to_every_member():
    t = FakeTransport(["dns-a", "dns-b"])
    coord = _coord(t)
    await coord.mutate("add", {"name": "a.example.com", "type": "A",
                               "value": "10.0.1.1"})
    out = await coord.mutate("delete", {"name": "a.example.com"})
    assert out["status"] == "SUCCESS" and out["records_written"] == 0
    assert [c[0] for c in t.calls] == ["DNSW_APPLY", "DNSW_APPLY"]


def test_report_flags_drift_unreachable_and_stopped_unbound():
    asyncio.run(_test_report_flags_drift_unreachable_and_stopped_unbound())


async def _test_report_flags_drift_unreachable_and_stopped_unbound():
    t = FakeTransport(["dns-a", "dns-b", "dns-c"], connected=["dns-a", "dns-b"])
    coord = _coord(t)
    coord.desired.set_records(_recs(("a.example.com", "10.0.1.1")))
    coord.reported = {
        "dns-a": {"digest": coord.desired.digest,
                  "recorded_digest": coord.desired.digest,
                  "version": coord.desired.version, "running": False},
        "dns-b": {"digest": "stale", "recorded_digest": "stale",
                  "version": 0, "running": True},
    }
    report = coord.cluster_report()
    by_id = {m["id"]: m for m in report["members"]}
    assert by_id["dns-a"]["convergence"] == "converged"
    assert by_id["dns-b"]["convergence"] == "drifted"
    assert by_id["dns-c"]["convergence"] == "unreachable"
    assert report["state"] == "partial"
    text = " ".join(report["recommendations"])
    assert "dns-c" in text and "not connected" in text
    assert "dns-b" in text and "reconcile" in text
    assert "Unbound is not running on 'dns-a'" in text


def test_reconcile_repushes_only_to_the_drifted_member():
    asyncio.run(_test_reconcile_repushes_only_to_the_drifted_member())


async def _test_reconcile_repushes_only_to_the_drifted_member():
    t = FakeTransport(["dns-a", "dns-b"])
    coord = _coord(t)
    await coord.apply_records(_recs(("a.example.com", "10.0.1.1")))
    t.calls.clear()
    # dns-b came back from a reboot with nothing applied.
    t.replies[("dns-b", "DNSW_STATE")] = {"status": "SUCCESS", "version": None,
                                          "digest": None,
                                          "recorded_digest": None,
                                          "record_count": 0}
    t.replies[("dns-a", "DNSW_STATE")] = {"status": "SUCCESS", "version": 1,
                                          "digest": coord.desired.digest,
                                          "recorded_digest": coord.desired.digest,
                                          "record_count": 1}
    out = await coord.reconcile()
    assert out["status"] == "SUCCESS" and out["reconciled"] == ["dns-b"]
    applies = [c for c in t.calls if c[0] == "DNSW_APPLY"]
    assert len(applies) == 1 and applies[0][2] == ("dns-b",)
    assert coord.cluster_report()["converged"] is True


def test_reconcile_is_a_noop_when_everything_is_converged():
    asyncio.run(_test_reconcile_is_a_noop_when_everything_is_converged())


async def _test_reconcile_is_a_noop_when_everything_is_converged():
    t = FakeTransport(["dns-a", "dns-b"])
    coord = _coord(t)
    await coord.apply_records(_recs(("a.example.com", "10.0.1.1")))
    for m in ("dns-a", "dns-b"):
        t.replies[(m, "DNSW_STATE")] = {"status": "SUCCESS", "version": 1,
                                        "digest": coord.desired.digest,
                                        "recorded_digest": coord.desired.digest,
                                        "record_count": 1}
    t.calls.clear()
    out = await coord.reconcile()
    assert out["reconciled"] == []
    assert [c[0] for c in t.calls] == ["DNSW_STATE"]


def test_reconcile_that_cannot_repair_reports_error_not_success():
    asyncio.run(_test_reconcile_that_cannot_repair_reports_error_not_success())


async def _test_reconcile_that_cannot_repair_reports_error_not_success():
    t = FakeTransport(["dns-a", "dns-b"], connected=["dns-a"])
    coord = _coord(t)
    coord.desired.set_records(_recs(("a.example.com", "10.0.1.1")))
    t.replies[("dns-a", "DNSW_STATE")] = {"status": "SUCCESS", "version": 0,
                                          "digest": "stale",
                                          "recorded_digest": "stale",
                                          "record_count": 0}
    t.replies[("dns-a", "DNSW_APPLY")] = {"status": "ERROR", "message": "disk full"}
    out = await coord.reconcile()
    assert out["status"] == "ERROR" and out["failed"] == ["dns-a"]


def test_a_single_member_is_not_a_cluster():
    asyncio.run(_test_a_single_member_is_not_a_cluster())


async def _test_a_single_member_is_not_a_cluster():
    coord = DnsClusterCoordinator(FakeTransport(["dns-a"]), DnsDesiredState(""))
    assert coord.enabled is False
    assert (await coord.reconcile())["status"] == "SKIPPED"


# ── Item 8: desired-state persistence fails CLOSED ─────────────────────────

def test_a_corrupt_desired_state_blocks_mutation_and_reconcile(tmp_path):
    """REGRESSION (review #8): starting clean on a corrupt file silently
    republished an EMPTY record set to both resolvers."""
    import json as _json
    path = tmp_path / "desired.json"
    path.write_text(_json.dumps({
        "version": 9, "digest": "not-the-real-digest",
        "records": _recs(("a.example.com", "10.0.1.1"))}))
    state = DnsDesiredState(str(path))
    assert state.broken and "corrupt" in state.broken
    with pytest.raises(DnsStateUnavailable):
        state.set_records(_recs(("b.example.com", "10.0.1.2")))
    with pytest.raises(DnsStateUnavailable):
        state.add({"name": "c.example.com", "type": "A", "value": "10.0.1.3"})
    with pytest.raises(DnsStateUnavailable):
        state.delete("a.example.com")


def test_an_unreadable_desired_state_blocks_mutation(tmp_path):
    path = tmp_path / "desired.json"
    path.write_text("{not json")
    state = DnsDesiredState(str(path))
    assert state.broken and "could not be read" in state.broken
    with pytest.raises(DnsStateUnavailable):
        state.set_records([])


def test_a_broken_state_refuses_to_commit_or_reconcile(tmp_path):
    import json as _json
    path = tmp_path / "desired.json"
    path.write_text(_json.dumps({"version": 3, "digest": "bogus", "records": []}))
    t = FakeTransport(["dns-a", "dns-b"])
    coord = DnsClusterCoordinator(t, DnsDesiredState(str(path)))
    assert coord.state_error
    with pytest.raises(DnsStateUnavailable):
        asyncio.run(coord.apply_records(_recs(("a.example.com", "10.0.1.1"))))
    assert t.calls == [], "no resolver may be touched while the state is broken"
    out = asyncio.run(coord.reconcile())
    assert out["status"] == "ERROR" and "corrupt" in out["message"]
    assert t.calls == []


def test_no_worker_apply_when_persistence_fails(tmp_path):
    """REGRESSION (review #8): the fan-out must not run if the coordinator could
    not durably record the version it is about to push."""
    unwritable = tmp_path / "nope" / "\0bad" / "desired.json"
    t = FakeTransport(["dns-a", "dns-b"])
    coord = DnsClusterCoordinator(t, DnsDesiredState(str(unwritable)))
    with pytest.raises(DnsStateUnavailable):
        asyncio.run(coord.apply_records(_recs(("a.example.com", "10.0.1.1"))))
    assert t.calls == []
    assert coord.desired.version == 0, "the version must not advance"


def test_persist_before_promote_keeps_state_consistent(tmp_path):
    state = DnsDesiredState(str(tmp_path / "desired.json"))
    state.set_records(_recs(("a.example.com", "10.0.1.1")))
    assert state.version == 1
    state.state_path = str(tmp_path / "missing" / "\0bad" / "x.json")
    with pytest.raises(DnsStateUnavailable):
        state.set_records(_recs(("b.example.com", "10.0.1.2")))
    assert state.version == 1
    assert [r["name"] for r in state.records] == ["a.example.com"]


# ── Item 10: mutations are serialized ──────────────────────────────────────

def test_concurrent_mutations_are_serialized(tmp_path):
    """REGRESSION (review #10): interleaved fan-outs left the two resolvers on
    different versions with the coordinator believing both landed."""
    t = FakeTransport(["dns-a", "dns-b"])
    coord = DnsClusterCoordinator(t, DnsDesiredState(str(tmp_path / "d.json")))

    async def _both():
        return await asyncio.gather(
            coord.mutate("add", {"name": "a.example.com", "type": "A",
                                 "value": "10.0.1.1"}),
            coord.mutate("add", {"name": "b.example.com", "type": "A",
                                 "value": "10.0.1.2"}))

    first, second = asyncio.run(_both())
    assert {first["version"], second["version"]} == {1, 2}
    applies = [c for c in t.calls if c[0] == "DNSW_APPLY"]
    assert len(applies) == 2
    # Each commit fanned out to BOTH members before the next one started.
    assert all(set(c[2]) == {"dns-a", "dns-b"} for c in applies)
    assert coord.desired.version == 2
    assert len(coord.desired.records) == 2


# ── Round 4, #2: convergence needs disk digest AND confirmed runtime apply ──

def _converged_state(coord):
    return {"digest": coord.desired.digest,
            "recorded_digest": coord.desired.digest,
            "version": coord.desired.version, "running": True}


def test_a_member_is_converged_only_on_all_three_facts(tmp_path):
    t = FakeTransport(["dns-a", "dns-b"])
    coord = DnsClusterCoordinator(t, DnsDesiredState(str(tmp_path / "d.json")))
    coord.desired.set_records(_recs(("a.example.com", "10.0.1.1")))
    coord.reported["dns-a"] = _converged_state(coord)
    assert coord.member_converged("dns-a") is True
    assert coord.member_convergence("dns-a") == "converged"


def test_a_failed_reload_is_not_converged_even_though_the_disk_matches(tmp_path):
    """REGRESSION (round 4, #2): the conf write landed, the reload did not, so
    the resolver is still ANSWERING the previous set — but the disk digest
    already equalled the desired one."""
    t = FakeTransport(["dns-a", "dns-b"])
    coord = DnsClusterCoordinator(t, DnsDesiredState(str(tmp_path / "d.json")))
    coord.desired.set_records(_recs(("a.example.com", "10.0.1.1")))
    coord.reported["dns-a"] = {
        "digest": coord.desired.digest,        # file on disk is right...
        "recorded_digest": None,               # ...but no confirmed reload
        "version": None, "running": True,
    }
    assert coord.member_converged("dns-a") is False
    assert coord.member_convergence("dns-a") == "pending-reload"
    report = coord.cluster_report()
    assert report["converged"] is False
    by_id = {m["id"]: m for m in report["members"]}
    assert by_id["dns-a"]["convergence"] == "pending-reload"
    assert any("never confirmed an Unbound reload" in r
               for r in report["recommendations"])


def test_a_stale_applied_version_is_not_converged(tmp_path):
    """Catches a worker that re-applied an older set whose digest happens to
    match a stale desired value."""
    t = FakeTransport(["dns-a", "dns-b"])
    coord = DnsClusterCoordinator(t, DnsDesiredState(str(tmp_path / "d.json")))
    coord.desired.set_records(_recs(("a.example.com", "10.0.1.1")))
    coord.desired.set_records(_recs(("a.example.com", "10.0.1.2")))
    coord.reported["dns-a"] = {"digest": coord.desired.digest,
                               "recorded_digest": coord.desired.digest,
                               "version": 1, "running": True}
    assert coord.desired.version == 2
    assert coord.member_converged("dns-a") is False


def test_reconcile_retries_a_pending_reload_member(tmp_path):
    """REGRESSION: the member must be RE-PUSHED (DNSW_APPLY) until the reload is
    confirmed, not written off as converged from disk alone."""
    t = FakeTransport(["dns-a", "dns-b"])
    coord = DnsClusterCoordinator(t, DnsDesiredState(str(tmp_path / "d.json")))
    asyncio.run(coord.apply_records(_recs(("a.example.com", "10.0.1.1"))))
    t.calls.clear()
    # dns-b wrote the file but never confirmed the reload.
    t.replies[("dns-b", "DNSW_STATE")] = {
        "status": "SUCCESS", "version": None, "digest": coord.desired.digest,
        "recorded_digest": None, "record_count": 1}
    t.replies[("dns-a", "DNSW_STATE")] = {
        "status": "SUCCESS", "version": coord.desired.version,
        "digest": coord.desired.digest,
        "recorded_digest": coord.desired.digest, "record_count": 1}
    out = asyncio.run(coord.reconcile())
    applies = [c for c in t.calls if c[0] == "DNSW_APPLY"]
    assert len(applies) == 1 and applies[0][2] == ("dns-b",)
    assert out["reconciled"] == ["dns-b"]


def test_a_commit_reply_that_did_not_reload_counts_as_failed(tmp_path):
    """A worker that answers with reloaded=False has NOT applied the set."""
    t = FakeTransport(["dns-a", "dns-b"], replies={
        ("dns-b", "DNSW_APPLY"): {"status": "SUCCESS", "version": 1,
                                  "reloaded": False}})
    coord = DnsClusterCoordinator(t, DnsDesiredState(str(tmp_path / "d.json")))
    out = asyncio.run(coord.apply_records(_recs(("a.example.com", "10.0.1.1"))))
    assert out["status"] == "PARTIAL"
    assert out["members_failed"] == ["dns-b"]
    assert coord.member_converged("dns-b") is False


def test_a_stopped_unbound_with_a_matching_disk_is_still_reported(tmp_path):
    t = FakeTransport(["dns-a", "dns-b"])
    coord = DnsClusterCoordinator(t, DnsDesiredState(str(tmp_path / "d.json")))
    coord.desired.set_records(_recs(("a.example.com", "10.0.1.1")))
    state = _converged_state(coord)
    state["running"] = False
    coord.reported["dns-a"] = state
    coord.reported["dns-b"] = _converged_state(coord)
    report = coord.cluster_report()
    assert report["converged"] is True   # records ARE applied...
    assert any("Unbound is not running on 'dns-a'" in r
               for r in report["recommendations"])   # ...but the daemon is down
