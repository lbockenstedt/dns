"""``UnboundManager._ensure_conf_included`` — make sure Unbound actually PARSES
the directory we write managed config into.

The outage this pins: every managed file (records, forwarders, query logging)
is written to ``/etc/unbound/conf.d/``, but Debian/Ubuntu's packaged
``unbound.conf`` includes ``/etc/unbound/unbound.conf.d/*.conf`` — a different
directory (note the ``unbound.`` prefix). With nothing bridging the two, the
resolver silently ignores every file we write: ``sync()`` returns SUCCESS and
``unbound-control reload`` succeeds, because both honestly describe writing and
reloading a config Unbound never reads. Observed in production on a Kea/Unbound
pair: 13 records synced, ``members_failed: []``, and not one lab name
resolvable, while public recursion worked perfectly.

Because the failure mode is "everything reports healthy", these tests assert on
the FILESYSTEM outcome — is our directory reachable from the main conf — rather
than on any return value the buggy version would also have produced.
"""
import os

import pytest

from unbound_manager import BRIDGE_CONF_NAME, UnboundManager


def _layout(tmp_path, main_conf_text, distro_dir="unbound.conf.d",
            lm_dir="conf.d"):
    """Build an /etc/unbound-shaped tree and return (manager, paths)."""
    etc = tmp_path / "unbound"
    etc.mkdir()
    (etc / distro_dir).mkdir()
    (etc / lm_dir).mkdir()
    main = etc / "unbound.conf"
    main.write_text(main_conf_text)
    return etc, main


@pytest.fixture
def mgr(monkeypatch):
    """Construct an UnboundManager against a temp tree.

    ``__init__`` calls ``_ensure_conf_included``; MAIN_CONF is a module
    constant, so it is patched per-test to point into the temp tree.
    """
    def _build(etc, lm_dir="conf.d"):
        import unbound_manager
        monkeypatch.setattr(unbound_manager, "MAIN_CONF",
                            str(etc / "unbound.conf"))
        return UnboundManager(conf_path=str(etc / lm_dir / "lm-netbox.conf"))
    return _build


# --- the production layout: the bug, and the repair --------------------------

DEBIAN_MAIN = (
    'server:\n'
    '    directory: "/etc/unbound"\n'
    '# The following line includes additional configuration files\n'
    'include-toplevel: "%s/unbound.conf.d/*.conf"\n'
)


def test_debian_layout_gets_a_bridge_written(tmp_path, mgr):
    """The exact production shape: our dir is NOT the included one."""
    etc, _ = _layout(tmp_path, DEBIAN_MAIN % tmp_path.joinpath("unbound"))
    mgr(etc)
    bridge = etc / "unbound.conf.d" / BRIDGE_CONF_NAME
    assert bridge.exists(), "no bridge written — managed config stays unparsed"
    assert str(etc / "conf.d") in bridge.read_text()


def test_the_bridge_uses_include_toplevel(tmp_path, mgr):
    """Our files declare their own top-level clauses (``server:``,
    ``forward-zone:``), so a plain ``include:`` would be a parse error."""
    etc, _ = _layout(tmp_path, DEBIAN_MAIN % tmp_path.joinpath("unbound"))
    mgr(etc)
    text = (etc / "unbound.conf.d" / BRIDGE_CONF_NAME).read_text()
    assert "include-toplevel:" in text


def test_the_packaged_main_conf_is_never_modified(tmp_path, mgr):
    """An apt upgrade would revert an edit to the distro's own file, so the
    repair must live in a drop-in instead."""
    etc, main = _layout(tmp_path, DEBIAN_MAIN % tmp_path.joinpath("unbound"))
    before = main.read_text()
    mgr(etc)
    assert main.read_text() == before


def test_repair_is_idempotent(tmp_path, mgr):
    etc, _ = _layout(tmp_path, DEBIAN_MAIN % tmp_path.joinpath("unbound"))
    mgr(etc)
    bridge = etc / "unbound.conf.d" / BRIDGE_CONF_NAME
    first = bridge.read_text()
    mgr(etc)
    assert bridge.read_text() == first


# --- layouts that must be left alone ----------------------------------------

def test_no_bridge_when_our_dir_is_already_included(tmp_path, mgr):
    etc, _ = _layout(
        tmp_path,
        'include-toplevel: "%s/conf.d/*.conf"\n' % tmp_path.joinpath("unbound"))
    mgr(etc)
    assert not (etc / "unbound.conf.d" / BRIDGE_CONF_NAME).exists()


def test_plain_include_directive_also_counts_as_covered(tmp_path, mgr):
    """Some layouts use ``include:`` rather than ``include-toplevel:``."""
    etc, _ = _layout(
        tmp_path,
        'include: "%s/conf.d/*.conf"\n' % tmp_path.joinpath("unbound"))
    mgr(etc)
    assert not (etc / "unbound.conf.d" / BRIDGE_CONF_NAME).exists()


def test_an_existing_operator_bridge_is_respected(tmp_path, mgr):
    """Someone already bridged the dirs by hand under a different filename —
    don't add a second, redundant include."""
    etc, _ = _layout(tmp_path, DEBIAN_MAIN % tmp_path.joinpath("unbound"))
    (etc / "unbound.conf.d" / "zz-operator.conf").write_text(
        'include-toplevel: "%s/conf.d/*.conf"\n' % (etc,))
    mgr(etc)
    assert not (etc / "unbound.conf.d" / BRIDGE_CONF_NAME).exists()


# --- degrade safely, never raise --------------------------------------------

def test_missing_main_conf_does_not_raise(tmp_path, monkeypatch):
    import unbound_manager
    monkeypatch.setattr(unbound_manager, "MAIN_CONF",
                        str(tmp_path / "does-not-exist.conf"))
    lm_dir = tmp_path / "conf.d"
    lm_dir.mkdir()
    UnboundManager(conf_path=str(lm_dir / "lm-netbox.conf"))


def test_main_conf_including_no_directory_does_not_raise(tmp_path, mgr):
    etc, _ = _layout(tmp_path, 'server:\n    verbosity: 1\n')
    m = mgr(etc)
    assert m is not None
    assert not (etc / "unbound.conf.d" / BRIDGE_CONF_NAME).exists()


def test_reports_what_it_did(tmp_path, mgr):
    etc, _ = _layout(tmp_path, DEBIAN_MAIN % tmp_path.joinpath("unbound"))
    m = mgr(etc)
    assert m._ensure_conf_included()["action"] == "already-bridged"
