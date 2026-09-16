"""The cluster coordinator must say WHY a forwarder add failed.

_cluster_add_forwarder collapsed every member's result into

    forwarder was not added to all resolvers (<uuid>, <uuid>)

and dropped the per-member payloads into a `members` dict the UI never
renders. In production that hid a completely actionable message ("forwarder
zone . already exists") behind two opaque UUIDs, and recovering it meant
reading each resolver's own log by hand over the admin API.
"""
import asyncio

from test_dns_spoke_cluster import FakeTransport, _spoke, _run

MEMBERS = ["res-a", "res-b"]


def _fail_add(spoke, message, members=MEMBERS):
    transport = spoke._transport
    for member in members:
        transport.fail_ops.add((member, "DNSW_FORWARDER_ADD"))
    original = transport.fanout

    async def fanout(command, data, timeout=20.0, member_ids=None):
        out = await original(command, data, timeout=timeout, member_ids=member_ids)
        if command == "DNSW_FORWARDER_ADD":
            for member in out["failed"]:
                out["results"][member] = {"status": "ERROR", "message": message}
        return out

    transport.fanout = fanout


def test_the_members_own_reason_reaches_the_error_message(tmp_path):
    spoke = _spoke(tmp_path, MEMBERS)
    _fail_add(spoke, "forwarder zone . already exists")
    out = _run(spoke.handle_command(
        "DNS_FORWARDER_ADD", {"zone": ".", "upstreams": ["1.1.1.1"]}))
    assert out["status"] == "ERROR"
    assert "forwarder zone . already exists" in out["message"]
    # the resolver ids are still named, so an operator knows WHICH failed
    for member in MEMBERS:
        assert member in out["message"]


def test_identical_reasons_are_reported_once(tmp_path):
    spoke = _spoke(tmp_path, MEMBERS)
    _fail_add(spoke, "no more than 8 forwarder addresses are allowed")
    out = _run(spoke.handle_command(
        "DNS_FORWARDER_ADD", {"zone": ".", "upstreams": ["1.1.1.1"]}))
    assert out["message"].count("no more than 8 forwarder addresses") == 1


def test_differing_reasons_are_both_reported(tmp_path):
    spoke = _spoke(tmp_path, MEMBERS)
    transport = spoke._transport
    for member in MEMBERS:
        transport.fail_ops.add((member, "DNSW_FORWARDER_ADD"))
    original = transport.fanout
    reasons = {"res-a": "already exists", "res-b": "unbound-control reload failed"}

    async def fanout(command, data, timeout=20.0, member_ids=None):
        out = await original(command, data, timeout=timeout, member_ids=member_ids)
        if command == "DNSW_FORWARDER_ADD":
            for member in out["failed"]:
                out["results"][member] = {"status": "ERROR",
                                          "message": reasons[member]}
        return out

    transport.fanout = fanout
    out = _run(spoke.handle_command(
        "DNS_FORWARDER_ADD", {"zone": ".", "upstreams": ["1.1.1.1"]}))
    assert "already exists" in out["message"]
    assert "unbound-control reload failed" in out["message"]


def test_a_member_with_no_message_does_not_add_empty_noise(tmp_path):
    spoke = _spoke(tmp_path, MEMBERS)
    transport = spoke._transport
    for member in MEMBERS:
        transport.fail_ops.add((member, "DNSW_FORWARDER_ADD"))
    original = transport.fanout

    async def fanout(command, data, timeout=20.0, member_ids=None):
        out = await original(command, data, timeout=timeout, member_ids=member_ids)
        if command == "DNSW_FORWARDER_ADD":
            for member in out["failed"]:
                out["results"][member] = {"status": "ERROR"}
        return out

    transport.fanout = fanout
    out = _run(spoke.handle_command(
        "DNS_FORWARDER_ADD", {"zone": ".", "upstreams": ["1.1.1.1"]}))
    assert out["status"] == "ERROR"
    assert out["message"].rstrip().endswith(")")
    assert ": " not in out["message"].split(")")[-1]


def test_a_successful_add_is_unaffected(tmp_path):
    spoke = _spoke(tmp_path, MEMBERS)
    out = _run(spoke.handle_command(
        "DNS_FORWARDER_ADD", {"zone": ".", "upstreams": ["1.1.1.1"]}))
    assert out["status"] == "SUCCESS"
    assert "message" not in out or "not added" not in str(out.get("message"))
