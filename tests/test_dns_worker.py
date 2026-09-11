"""``DnsWorkerOps`` — the resolver-side operation table.

The worker is deliberately not a generic agent: only these five ops exist, and
the apply op re-validates + re-digests everything the coordinator sends before it
touches disk. A payload whose digest doesn't match its own records is rejected —
otherwise the cluster's convergence check would be comparing the coordinator's
claim against itself.
"""

import json

import pytest

from dns_cluster import DNS_WORKER_OPS, records_digest, validate_records
from dns_worker import DnsWorkerOps


class FakeMgr:
    def __init__(self):
        self.synced = None
        self.fail = False
        self.reload_fails = False
        self.running = True
        self.conf_records = []          # what Unbound is actually serving
        self.forwarders = {"status": "SUCCESS", "forwarders": [
            {"zone": ".", "class": "IN", "upstreams": ["9.9.9.9"]}]}

    def list_records(self):
        """Mirrors UnboundManager.list_records: A/AAAA come back with their
        auto-generated PTR companion, which derive_managed_records drops."""
        out = []
        for r in self.conf_records:
            out.append(dict(r))
            if r["type"] in ("A", "AAAA"):
                out.append({"name": r["value"], "type": "PTR",
                            "value": r["name"], "ttl": r["ttl"]})
        return out

    def sync(self, records):
        self.synced = list(records)
        if self.fail:
            return {"status": "ERROR", "message": "conf write failed"}
        self.conf_records = list(records)
        if self.reload_fails:
            # Mirrors UnboundManager.sync after the reload-propagation fix: the
            # file changed but the running resolver did not.
            return {"status": "ERROR", "records_written": len(records),
                    "reloaded": False, "error": "unbound-control reload failed",
                    "message": "records written but unbound-control reload failed"}
        return {"status": "SUCCESS", "records_written": len(records),
                "reloaded": True}

    def list_forwarders(self):
        return self.forwarders

    def status(self):
        return {"running": self.running, "record_count": len(self.synced or []),
                "conf_path": "/tmp-unused/lm.conf"}

    def diagnostics(self):
        return {"status": "SUCCESS", "healthy": True, "recommendations": []}

    def get_stats(self, search=None, source_prefixes=None):
        return {"status": "SUCCESS", "global": {"total_queries": 3},
                "query_types": {"A": 3}}


def _ops(tmp_path):
    return DnsWorkerOps(FakeMgr(), state_path=str(tmp_path / "applied.json"))


def _payload(records, digest=None, version=4):
    clean = validate_records(records)
    return {"version": version, "digest": digest or records_digest(clean),
            "records": clean}


RECORDS = [{"name": "a.example.com", "type": "A", "value": "10.0.1.1", "ttl": 300}]


def test_the_op_table_matches_the_coordinator_allowlist(tmp_path):
    assert set(_ops(tmp_path).op_table()) == set(DNS_WORKER_OPS)


def test_apply_writes_the_record_set_and_records_the_version(tmp_path):
    ops = _ops(tmp_path)
    payload = _payload(RECORDS)
    out = ops.apply(payload)
    assert out["status"] == "SUCCESS"
    assert out["version"] == 4 and out["digest"] == payload["digest"]
    assert ops.mgr.synced == payload["records"]
    saved = json.loads((tmp_path / "applied.json").read_text())
    assert saved["version"] == 4 and saved["digest"] == payload["digest"]


def test_applied_state_survives_a_worker_restart(tmp_path):
    payload = _payload(RECORDS)
    ops = _ops(tmp_path)
    ops.apply(payload)
    reborn = DnsWorkerOps(ops.mgr, state_path=str(tmp_path / "applied.json"))
    state = reborn.state({})
    assert state["version"] == 4
    assert state["recorded_digest"] == payload["digest"]


def test_a_digest_that_does_not_match_its_records_is_rejected(tmp_path):
    ops = _ops(tmp_path)
    out = ops.apply(_payload(RECORDS, digest="0" * 64))
    assert out["status"] == "ERROR" and "digest mismatch" in out["message"]
    assert ops.mgr.synced is None, "nothing may be written on a mismatch"


def test_an_injected_record_is_rejected_at_the_worker_too(tmp_path):
    """Defense in depth: the coordinator validates, and so does the worker."""
    ops = _ops(tmp_path)
    out = ops.apply({"version": 1, "digest": "",
                     "records": [{"name": 'x"y.example.com', "type": "A",
                                  "value": "10.0.1.1"}]})
    assert out["status"] == "ERROR" and "invalid record set" in out["message"]
    assert ops.mgr.synced is None


def test_a_failed_unbound_sync_is_not_recorded_as_applied(tmp_path):
    ops = _ops(tmp_path)
    ops.mgr.fail = True
    out = ops.apply(_payload(RECORDS))
    assert out["status"] == "ERROR"
    assert ops.state({})["version"] is None
    assert not (tmp_path / "applied.json").exists()


def test_state_reports_a_stopped_unbound(tmp_path):
    ops = _ops(tmp_path)
    ops.apply(_payload(RECORDS))
    ops.mgr.running = False
    assert ops.state({})["running"] is False


def test_status_diagnostics_and_stats_pass_through(tmp_path):
    ops = _ops(tmp_path)
    assert ops.status({})["status"] == "SUCCESS"
    assert ops.diagnostics({})["healthy"] is True
    assert ops.stats({})["global"]["total_queries"] == 3


def test_a_failed_reload_is_reported_and_not_recorded_as_applied(tmp_path):
    """REGRESSION (review #9): a conf write Unbound never reloaded has NOT taken
    effect. Recording the version would make the coordinator believe this
    resolver is serving a set it is not."""
    ops = _ops(tmp_path)
    ops.mgr.reload_fails = True
    out = ops.apply(_payload(RECORDS))
    assert out["status"] == "ERROR"
    assert out["reloaded"] is False
    assert "reload" in out["message"]
    assert ops.state({})["version"] is None
    assert not (tmp_path / "applied.json").exists()


def test_a_confirmed_reload_records_the_version(tmp_path):
    ops = _ops(tmp_path)
    out = ops.apply(_payload(RECORDS))
    assert out["status"] == "SUCCESS" and out["reloaded"] is True
    assert ops.state({})["version"] == 4


def test_forwarders_op_is_exposed_and_delegates(tmp_path):
    """REGRESSION (review #13): forwarders are per-resolver, so the coordinator
    asks each worker instead of reading its own (possibly absent) Unbound."""
    ops = _ops(tmp_path)
    assert "DNSW_FORWARDERS" in ops.op_table()
    out = ops.forwarders({})
    assert out["forwarders"][0]["upstreams"] == ["9.9.9.9"]


# ── Review #11: DNSW_STATE hashes the LIVE conf, not the stored marker ─────

def test_state_digest_comes_from_the_conf_not_the_marker(tmp_path):
    """REGRESSION: a digest read back from the worker's own applied-state file
    reports 'converged' for a resolver that is actually serving something else
    (out-of-band edit, half-landed write, marker that outlived the conf)."""
    ops = _ops(tmp_path)
    payload = _payload(RECORDS)
    ops.apply(payload)
    assert ops.state({})["digest"] == payload["digest"]

    # Someone edits the resolver out of band. The MARKER still says v4/old
    # digest, but the live digest must change.
    ops.mgr.conf_records = [{"name": "evil.example.com", "type": "A",
                             "value": "6.6.6.6", "ttl": 300}]
    state = ops.state({})
    assert state["recorded_digest"] == payload["digest"]
    assert state["digest"] != payload["digest"], \
        "the digest must track what Unbound is actually serving"
    assert state["version"] == 4, "the marker is still reported, separately"


def test_state_digest_ignores_auto_generated_ptr_companions(tmp_path):
    """UnboundManager writes a PTR for every A/AAAA, so a raw hash of the parsed
    conf could never equal the coordinator's digest."""
    ops = _ops(tmp_path)
    payload = _payload(RECORDS)
    ops.apply(payload)
    parsed = ops.mgr.list_records()
    assert len(parsed) == 2, "the fake mirrors the auto-PTR behaviour"
    assert ops.state({})["digest"] == payload["digest"]
    assert ops.state({})["record_count"] == 1


def test_state_reports_the_derived_records_for_seeding(tmp_path):
    ops = _ops(tmp_path)
    ops.apply(_payload(RECORDS))
    records = ops.state({})["records"]
    assert [r["name"] for r in records] == ["a.example.com"]


def test_an_explicit_ptr_record_is_kept(tmp_path):
    ops = _ops(tmp_path)
    ops.mgr.conf_records = [
        {"name": "5.1.0.10.in-addr.arpa", "type": "PTR",
         "value": "host.example.com", "ttl": 300}]
    records = ops.state({})["records"]
    assert [r["type"] for r in records] == ["PTR"]


def test_standdown_clears_the_marker_but_keeps_the_records(tmp_path):
    """REGRESSION (review #13): a removed resolver must stop claiming
    membership, but deleting its records would blackhole every client still
    pointed at it."""
    ops = _ops(tmp_path)
    ops.apply(_payload(RECORDS))
    assert (tmp_path / "applied.json").exists()
    out = ops.standdown({})
    assert out["status"] == "SUCCESS"
    assert not (tmp_path / "applied.json").exists()
    assert ops.state({})["version"] is None
    assert ops.mgr.conf_records, "records are left in place"
