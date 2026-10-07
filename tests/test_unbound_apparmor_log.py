"""AppArmor denies the unbound daemon /var/log/unbound by default, so the query
log never appears and "Queries by Destination" stays empty. The manager adds a
local override, reloads the profile and restarts unbound — once."""

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
    real_join, real_isdir, real_exists = (um_mod.os.path.join, um_mod.os.path.isdir,
                                          um_mod.os.path.exists)
    remap = {"/etc/apparmor.d/local": str(local),
             "/etc/apparmor.d/usr.sbin.unbound": str(profile)}
    monkeypatch.setattr(um_mod.os.path, "isdir", lambda p: real_isdir(remap.get(p, p)))
    monkeypatch.setattr(um_mod.os.path, "exists", lambda p: real_exists(remap.get(p, p)))
    monkeypatch.setattr(um_mod.os.path, "join",
                        lambda a, *b: real_join(remap.get(a, a), *b))
    mgr = _mgr(tmp_path)
    run = MagicMock()
    with patch.object(um_mod.subprocess, "run", run):
        assert mgr._ensure_apparmor_log_access() is True
        assert mgr._ensure_apparmor_log_access() is False
    assert "/var/log/unbound/** rw," in (local / "usr.sbin.unbound").read_text()
    cmds = [c.args[0][0] for c in run.call_args_list]
    assert cmds == ["apparmor_parser", "systemctl"]


def test_noop_without_apparmor(tmp_path):
    assert _mgr(tmp_path)._ensure_apparmor_log_access() is False
