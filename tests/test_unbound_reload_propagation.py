"""``UnboundManager.sync`` must report a failed reload.

REGRESSION (review #9): ``_reload`` swallowed the failure with a WARNING and
``sync`` still returned SUCCESS, so a conf write that Unbound never picked up
looked identical to one it did. Every caller — the single-host spoke and the
clustered worker's applied-version bookkeeping — depends on the distinction.
"""

from unbound_manager import UnboundManager

RECORDS = [{"name": "a.example.com", "type": "A", "value": "10.0.1.5", "ttl": 300}]


def _mgr(tmp_path):
    return UnboundManager(str(tmp_path / "conf.d" / "lm-netbox.conf"))


def test_sync_reports_success_with_reloaded_true(monkeypatch, tmp_path):
    mgr = _mgr(tmp_path)
    monkeypatch.setattr(mgr, "_reload", lambda: {"ok": True, "error": ""})
    out = mgr.sync(RECORDS)
    assert out["status"] == "SUCCESS"
    assert out["reloaded"] is True
    assert out["records_written"] == 2      # A + auto PTR


def test_sync_reports_error_when_the_reload_fails(monkeypatch, tmp_path):
    mgr = _mgr(tmp_path)
    monkeypatch.setattr(mgr, "_reload",
                        lambda: {"ok": False, "error": "connection refused"})
    out = mgr.sync(RECORDS)
    assert out["status"] == "ERROR"
    assert out["reloaded"] is False
    assert "connection refused" in out["message"]
    # The write still happened — the message says so, rather than pretending
    # nothing changed.
    assert out["records_written"] == 2
    assert (tmp_path / "conf.d" / "lm-netbox.conf").exists()


def test_reload_returns_a_structured_result(monkeypatch, tmp_path):
    mgr = _mgr(tmp_path)

    def boom(*_a, **_kw):
        raise OSError("unbound-control: command not found")

    monkeypatch.setattr("unbound_manager.subprocess.run", boom)
    result = mgr._reload()
    assert result["ok"] is False
    assert "command not found" in result["error"]
