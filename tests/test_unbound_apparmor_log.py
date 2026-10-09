"""AppArmor denies the unbound daemon /var/log/unbound by default, so the query
log never appears and "Queries by Destination" stays empty. The manager now
reports whether the override was applied, was already active, or failed so
callers can avoid mistaking a broken host for a healthy no-op."""

import subprocess
from unittest.mock import patch, MagicMock

import unbound_manager as um_mod
from unbound_manager import UnboundManager


def _mgr(tmp_path):
    return UnboundManager(conf_path=str(tmp_path / "lm-netbox.conf"))


def test_override_written_once_and_profile_reloaded(tmp_path, monkeypatch):
    local = tmp_path / "local"
    local.mkdir()
    profile = tmp_path / "usr.sbin.unbound"
    profile.write_text("# profile\n")
    query_log = tmp_path / "lm-queries.log"
    real_join, real_isdir, real_exists = (um_mod.os.path.join, um_mod.os.path.isdir,
                                          um_mod.os.path.exists)
    remap = {"/etc/apparmor.d/local": str(local),
             "/etc/apparmor.d/usr.sbin.unbound": str(profile)}
    monkeypatch.setattr(um_mod, "QUERY_LOG", str(query_log))
    monkeypatch.setattr(um_mod.os.path, "isdir", lambda p: real_isdir(remap.get(p, p)))
    monkeypatch.setattr(um_mod.os.path, "exists", lambda p: real_exists(remap.get(p, p)))
    monkeypatch.setattr(um_mod.os.path, "join",
                        lambda a, *b: real_join(remap.get(a, a), *b))
    mgr = _mgr(tmp_path)
    run = MagicMock()
    with patch.object(um_mod.subprocess, "run", run):
        first = mgr._ensure_apparmor_log_access()
        assert first == {"status": "applied", "changed": True, "restarted": True,
                         "ok": True, "reason": "override-applied"}
        query_log.write_text("")
        second = mgr._ensure_apparmor_log_access()
        assert second == {"status": "noop", "changed": False, "restarted": False,
                          "ok": True, "reason": "rule-already-active"}
    assert f"{query_log.parent}/** rw," in (local / "usr.sbin.unbound").read_text()
    cmds = [c.args[0][0] for c in run.call_args_list]
    assert cmds == ["apparmor_parser", "systemctl"]


def test_failed_apply_is_retried_on_a_later_call(tmp_path, monkeypatch):
    local = tmp_path / "local"
    local.mkdir()
    profile = tmp_path / "usr.sbin.unbound"
    profile.write_text("# profile\n")
    query_log = tmp_path / "lm-queries.log"
    real_join, real_isdir, real_exists = (um_mod.os.path.join, um_mod.os.path.isdir,
                                          um_mod.os.path.exists)
    remap = {"/etc/apparmor.d/local": str(local),
             "/etc/apparmor.d/usr.sbin.unbound": str(profile)}
    monkeypatch.setattr(um_mod, "QUERY_LOG", str(query_log))
    monkeypatch.setattr(um_mod.os.path, "isdir", lambda p: real_isdir(remap.get(p, p)))
    monkeypatch.setattr(um_mod.os.path, "exists", lambda p: real_exists(remap.get(p, p)))
    monkeypatch.setattr(um_mod.os.path, "join",
                        lambda a, *b: real_join(remap.get(a, a), *b))
    mgr = _mgr(tmp_path)
    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd[0])
        if calls == ["apparmor_parser", "systemctl"]:
            raise subprocess.CalledProcessError(returncode=1, cmd=cmd, stderr="busy")
        return MagicMock(returncode=0)

    with patch.object(um_mod.subprocess, "run", side_effect=fake_run):
        first = mgr._ensure_apparmor_log_access()
        second = mgr._ensure_apparmor_log_access()

    assert first["status"] == "failed"
    assert first["ok"] is False
    assert first["changed"] is True
    assert second["status"] == "applied"
    assert second["ok"] is True
    assert calls == ["apparmor_parser", "systemctl", "apparmor_parser", "systemctl"]


def test_noop_without_apparmor(tmp_path):
    assert _mgr(tmp_path)._ensure_apparmor_log_access() == {
        "status": "noop", "changed": False, "restarted": False,
        "ok": True, "reason": "apparmor-unavailable"}
