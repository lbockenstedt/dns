"""Event-loop offload tests for ``DNSSpoke.handle_command`` / ``get_status``.

The DNS role runs on the lm-svcs agent's ONE shared event loop alongside the
dhcp + base role sub-spokes. ``UnboundManager`` does sync ``subprocess.run``
(``unbound-control reload/status/stats_noreset/list_forwards``, 5-10s timeouts)
+ sync conf writes. Calling those directly from ``async def handle_command``
blocks the whole loop → the hub's 5s ``request_response`` fires for every
in-flight request across all three sub-spokes at once (the "lm-svcs-dhcp/dns/
svcs time out in the same second" incident). The fix wraps every mgr call in
``await asyncio.to_thread(...)`` so the sync work runs in a worker thread and
the loop keeps servicing the other roles + the hub WS link.

These tests lock that in: a fake mgr records the thread id it ran on, and each
command asserts the result contract is unchanged AND the mgr call ran in a
DIFFERENT thread than the event loop (i.e. it was offloaded, not called sync).
"""

import asyncio
import threading

import pytest

from dns_spoke import DNSSpoke


class FakeMgr:
    """Records every call + the thread it ran in. Methods mirror UnboundManager
    signatures + return shapes so the spoke's response wrapping is exercised."""

    def __init__(self):
        self.calls = []
        self.thread_ids = []

    def _tid(self):
        tid = threading.get_ident()
        self.thread_ids.append(tid)
        return tid

    def sync(self, records):
        self.calls.append(("sync", len(records)))
        self._tid()
        return {"status": "SUCCESS", "records_written": len(records)}

    def list_records(self):
        self.calls.append(("list_records",))
        self._tid()
        return [{"name": "host.example.com", "type": "A", "value": "10.0.1.5", "ttl": 300}]

    def add_record(self, name, rtype, value, ttl):
        self.calls.append(("add_record", name, rtype, value, ttl))
        self._tid()
        return {"status": "SUCCESS"}

    def update_record(self, name, rtype, value, ttl):
        self.calls.append(("update_record", name, rtype, value, ttl))
        self._tid()
        return {"status": "SUCCESS"}

    def delete_record(self, name, rtype=None):
        self.calls.append(("delete_record", name, rtype))
        self._tid()
        return {"status": "SUCCESS"}

    def status(self):
        self.calls.append(("status",))
        self._tid()
        return {"running": True, "record_count": 3, "conf_path": "/etc/unbound/conf.d/lm-netbox.conf"}

    def get_stats(self):
        self.calls.append(("get_stats",))
        self._tid()
        return {"status": "SUCCESS", "global": {"total_queries": 10}}

    def list_forwarders(self):
        self.calls.append(("list_forwarders",))
        self._tid()
        return {"status": "SUCCESS", "forwarders": []}


@pytest.fixture
def spoke(tmp_path):
    s = DNSSpoke("test-dns", {"unbound_conf": str(tmp_path / "unbound.conf")})
    s.mgr = FakeMgr()
    return s


@pytest.fixture
def loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield loop
    finally:
        loop.close()
        # Leave a usable loop for any later TestClient-based tests (Py3.9).
        asyncio.set_event_loop(asyncio.new_event_loop())


def _run(loop, coro):
    return loop.run_until_complete(coro)


def _assert_offloaded(spoke, loop):
    """The mgr call ran in a worker thread, NOT the event-loop thread."""
    assert spoke.mgr.thread_ids, "mgr method was never called"
    loop_thread = threading.get_ident()
    for tid in spoke.mgr.thread_ids:
        assert tid != loop_thread, "mgr call ran on the event-loop thread (not offloaded)"


def test_get_version_does_not_touch_mgr(spoke, loop):
    """GET_VERSION is a cheap file read; it must NOT go through the (sync-I/O)
    mgr nor need offloading — verifies the offload is scoped to mgr calls only."""
    resp = _run(loop, spoke.handle_command("GET_VERSION", {}))
    assert resp["status"] == "SUCCESS"
    assert "version" in resp
    assert spoke.mgr.calls == []


def test_dns_sync_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DNS_SYNC", {"records": [
        {"name": "a", "type": "A", "value": "10.0.1.5"}]}))
    assert resp == {"status": "SUCCESS", "records_written": 1}
    _assert_offloaded(spoke, loop)


def test_dns_list_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DNS_LIST", {}))
    assert resp["status"] == "SUCCESS"
    assert resp["records"][0]["name"] == "host.example.com"
    _assert_offloaded(spoke, loop)


def test_dns_add_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DNS_ADD",
              {"name": "a", "type": "A", "value": "10.0.1.5", "ttl": 300}))
    assert resp["status"] == "SUCCESS"
    _assert_offloaded(spoke, loop)


def test_dns_add_missing_fields_short_circuits_before_mgr(spoke, loop):
    """Validation runs on the loop (cheap) and must NOT offload a doomed mgr call."""
    resp = _run(loop, spoke.handle_command("DNS_ADD", {"name": "a"}))
    assert resp["status"] == "ERROR"
    assert spoke.mgr.calls == []


def test_dns_update_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DNS_UPDATE",
              {"name": "a", "value": "10.0.1.6"}))
    assert resp["status"] == "SUCCESS"
    _assert_offloaded(spoke, loop)


def test_dns_delete_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DNS_DELETE", {"name": "a"}))
    assert resp["status"] == "SUCCESS"
    _assert_offloaded(spoke, loop)


def test_dns_status_offloaded_and_spread(spoke, loop):
    """DNS_STATUS spreads the mgr.status() dict into the response — verify the
    offloaded result is merged correctly (not the call itself)."""
    resp = _run(loop, spoke.handle_command("DNS_STATUS", {}))
    assert resp["status"] == "SUCCESS"
    assert resp["running"] is True
    assert resp["record_count"] == 3
    _assert_offloaded(spoke, loop)


def test_dns_stats_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DNS_STATS", {}))
    assert resp["status"] == "SUCCESS"
    _assert_offloaded(spoke, loop)


def test_dns_forwarders_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DNS_FORWARDERS", {}))
    assert resp["status"] == "SUCCESS"
    _assert_offloaded(spoke, loop)


def test_unknown_command_no_mgr(spoke, loop):
    resp = _run(loop, spoke.handle_command("DNS_NOPE", {}))
    assert resp["status"] == "ERROR"
    assert "Unknown command" in resp["error"]
    assert spoke.mgr.calls == []


def test_get_status_offloaded(spoke, loop):
    """get_status is polled by the hub for telemetry — the sync unbound-control
    status subprocess must be offloaded too, or a slow poll stalls the loop."""
    s = _run(loop, spoke.get_status())
    assert s["spoke_id"] == "test-dns"
    assert s["module"] == "dns"
    assert s["unbound"] == "running"
    assert s["status"] == "HEALTHY"
    assert s["record_count"] == 3
    _assert_offloaded(spoke, loop)