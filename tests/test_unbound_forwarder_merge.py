"""Adding an upstream to a forwarding zone LM already manages must MERGE,
not fail, and the zone must be written as ONE forward-zone block.

Seen in production. The WebUI's "Add Forwarder" zone field defaults to "."
(saveDnsForwarder: `value?.trim() || '.'`), so "add an upstream server" is
almost always an add against the already-present root zone. add_forwarder
refused that with "forwarder zone . already exists", both cluster members
returned the same, and the coordinator collapsed it to

    forwarder was not added to all resolvers (<uuid>, <uuid>)

— which names no cause at all. Recovering the real reason meant reading each
resolver's log by hand.

The live lm-forwarders.conf on the resolvers had also accumulated FOUR
separate `forward-zone: name: "."` stanzas (1.1.1.1, 8.8.8.8, 9.9.9.9 and
1.1.1.1 again), because the writer emitted one block per list entry.
"""
import pytest

from unbound_manager import UnboundManager


def _mgr(tmp_path, monkeypatch, live=None):
    mgr = UnboundManager(str(tmp_path / "conf.d" / "lm-netbox.conf"))
    monkeypatch.setattr(mgr, "_reload", lambda: {"ok": True, "error": ""})
    monkeypatch.setattr(
        mgr, "list_forwarders",
        lambda: {"status": "SUCCESS", "forwarders": live or []})
    return mgr


def _blocks(mgr):
    with open(mgr.forwarders_path, encoding="utf-8") as fh:
        return fh.read()


# ── merging into an existing managed zone ───────────────────────────────────

def test_adding_an_upstream_to_the_root_zone_merges(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    assert mgr.add_forwarder(".", ["1.1.1.1"])["status"] == "SUCCESS"
    out = mgr.add_forwarder(".", ["8.8.8.8"])
    assert out["status"] == "SUCCESS"          # used to be ERROR "already exists"
    assert out["changed"] is True
    assert out["upstreams"] == ["1.1.1.1", "8.8.8.8"]


def test_the_merged_zone_is_written_as_a_single_block(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", ["1.1.1.1"])
    mgr.add_forwarder(".", ["8.8.8.8"])
    mgr.add_forwarder(".", ["9.9.9.9"])
    text = _blocks(mgr)
    assert text.count("forward-zone:") == 1
    assert text.count('name: "."') == 1
    for address in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        assert f"forward-addr: {address}" in text


def test_readding_the_same_upstream_is_idempotent(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", ["1.1.1.1"])
    out = mgr.add_forwarder(".", ["1.1.1.1"])
    assert out["status"] == "SUCCESS"
    assert out["changed"] is False
    assert _blocks(mgr).count("forward-addr: 1.1.1.1") == 1


def test_a_partly_new_set_adds_only_the_missing_addresses(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", ["1.1.1.1", "8.8.8.8"])
    out = mgr.add_forwarder(".", ["8.8.8.8", "9.9.9.9"])
    assert out["upstreams"] == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    assert _blocks(mgr).count("forward-addr: 8.8.8.8") == 1


def test_a_named_zone_merges_the_same_way(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder("lab.example.com", ["10.0.0.1"])
    out = mgr.add_forwarder("lab.example.com", ["10.0.0.2"])
    assert out["status"] == "SUCCESS"
    assert out["upstreams"] == ["10.0.0.1", "10.0.0.2"]
    assert _blocks(mgr).count("forward-zone:") == 1


def test_distinct_zones_stay_separate_blocks(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", ["1.1.1.1"])
    mgr.add_forwarder("lab.example.com", ["10.0.0.1"])
    text = _blocks(mgr)
    assert text.count("forward-zone:") == 2
    assert 'name: "."' in text and 'name: "lab.example.com."' in text


def test_merging_past_the_eight_address_cap_is_refused(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", [f"10.0.0.{n}" for n in range(1, 9)])
    out = mgr.add_forwarder(".", ["10.0.0.9"])
    assert out["status"] == "ERROR"
    assert "8-address" in out["message"]
    assert out["changed"] is False
    assert _blocks(mgr).count("forward-addr: 10.0.0.9") == 0


# ── healing a file that already drifted ─────────────────────────────────────

def test_a_file_with_duplicate_zone_blocks_is_coalesced_on_write(tmp_path, monkeypatch):
    """The exact production file: four "." stanzas, 1.1.1.1 listed twice."""
    mgr = _mgr(tmp_path, monkeypatch)
    with open(mgr.forwarders_path, "w", encoding="utf-8") as fh:
        fh.write("# Managed by Lab Manager — do not edit manually\n")
        for address in ("1.1.1.1", "8.8.8.8", "9.9.9.9", "1.1.1.1"):
            fh.write(f'forward-zone:\n    name: "."\n    forward-addr: {address}\n')
    out = mgr.add_forwarder(".", ["208.67.222.222"])
    assert out["status"] == "SUCCESS"
    text = _blocks(mgr)
    assert text.count("forward-zone:") == 1
    assert text.count("forward-addr: 1.1.1.1") == 1
    assert out["upstreams"] == ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]


# ── guard rails preserved ───────────────────────────────────────────────────

def test_a_zone_unbound_serves_from_foreign_config_is_still_refused(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch,
               live=[{"zone": "corp.example.com.", "upstreams": ["10.9.9.9"]}])
    out = mgr.add_forwarder("corp.example.com", ["10.0.0.1"])
    assert out["status"] == "ERROR"
    assert "does not manage" in out["message"]
    assert out["changed"] is False


def test_an_unparseable_live_zone_does_not_raise(tmp_path, monkeypatch):
    """_normalize_forward_zone raises on junk; the duplicate scan used to call
    it unguarded on whatever unbound-control printed."""
    mgr = _mgr(tmp_path, monkeypatch,
               live=[{"zone": "not a zone!", "upstreams": ["10.9.9.9"]}])
    out = mgr.add_forwarder("lab.example.com", ["10.0.0.1"])
    assert out["status"] == "SUCCESS"


def test_invalid_upstream_is_still_rejected(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    out = mgr.add_forwarder(".", ["not-an-ip"])
    assert out["status"] == "ERROR"
    assert out["changed"] is False


def test_invalid_zone_is_still_rejected(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    out = mgr.add_forwarder("bad_zone!", ["1.1.1.1"])
    assert out["status"] == "ERROR"
    assert out["changed"] is False


def test_a_failed_reload_still_reports_error_and_restores(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", ["1.1.1.1"])
    before = _blocks(mgr)
    monkeypatch.setattr(mgr, "_reload",
                        lambda: {"ok": False, "error": "connection refused"})
    out = mgr.add_forwarder(".", ["8.8.8.8"])
    assert out["status"] == "ERROR"
    assert out["changed"] is False
    assert "connection refused" in out["message"]
    assert _blocks(mgr) == before


def test_remove_still_drops_the_zone(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", ["1.1.1.1"])
    mgr.add_forwarder("lab.example.com", ["10.0.0.1"])
    assert mgr.remove_forwarder("lab.example.com")["changed"] is True
    text = _blocks(mgr)
    assert 'name: "lab.example.com."' not in text
    assert 'name: "."' in text


def test_remove_nonexistent_zone_is_noop(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", ["1.1.1.1"])
    out = mgr.remove_forwarder("nonexistent.example.com")
    assert out["status"] == "SUCCESS"
    assert out["changed"] is False


def test_update_forwarder_replaces_upstreams_in_place(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", ["1.1.1.1", "8.8.8.8"])
    out = mgr.update_forwarder(".", ["9.9.9.9"])
    assert out["status"] == "SUCCESS"
    assert out["changed"] is True
    assert out["upstreams"] == ["9.9.9.9"]
    text = _blocks(mgr)
    assert "forward-addr: 9.9.9.9" in text
    assert "forward-addr: 1.1.1.1" not in text
    assert "forward-addr: 8.8.8.8" not in text


def test_update_forwarder_with_identical_upstreams_reports_unchanged(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", ["1.1.1.1"])
    out = mgr.update_forwarder(".", ["1.1.1.1"])
    assert out["status"] == "SUCCESS"
    assert out["changed"] is False


def test_update_forwarder_nonexistent_zone_errors(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    out = mgr.update_forwarder("ghost.example.com", ["1.1.1.1"])
    assert out["status"] == "ERROR"
    assert "not found" in out["message"]
    assert out["changed"] is False


def test_update_forwarder_rename_zone_success(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder("old.example.com", ["10.0.0.1"])
    out = mgr.update_forwarder(zone="new.example.com", upstreams=["10.0.0.2"], old_zone="old.example.com")
    assert out["status"] == "SUCCESS"
    assert out["changed"] is True
    assert out["zone"] == "new.example.com."
    text = _blocks(mgr)
    assert 'name: "new.example.com."' in text
    assert 'name: "old.example.com."' not in text


def test_update_forwarder_rename_to_existing_zone_fails(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder("first.example.com", ["10.0.0.1"])
    mgr.add_forwarder("second.example.com", ["10.0.0.2"])
    out = mgr.update_forwarder(zone="second.example.com", upstreams=["10.0.0.3"], old_zone="first.example.com")
    assert out["status"] == "ERROR"
    assert "already exists" in out["message"]
    assert out["changed"] is False


def test_update_forwarder_exceeding_eight_addresses_fails(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.add_forwarder(".", ["1.1.1.1"])
    out = mgr.update_forwarder(".", [f"10.0.0.{i}" for i in range(1, 10)])
    assert out["status"] == "ERROR"
    assert out["changed"] is False

