"""Per-destination-name query stats: log-tail parsing, offset/rotation
handling, the MAX_TRACKED_NAMES cap, and get_stats()'s query_names field.

``unbound-control stats_noreset`` has no per-name counters, so this feature
tails Unbound's own query log (enabled via a managed conf.d snippet). These
tests never touch a real unbound-control binary or unbound.conf — they drive
UnboundManager against a plain temp file standing in for the query log.
"""

import os
from unittest.mock import patch, MagicMock

import pytest

import unbound_manager as um_mod
from unbound_manager import UnboundManager


QUERY_LINES = [
    "[1700000000] unbound[1:0] info: 172.17.1.5 www.dwx.com. A IN query: 172.17.1.5 www.dwx.com. A IN\n",
    "query: 172.17.1.5 www.dwx.com. A IN\n",
    "query: 172.17.1.6 api.dwx.com. AAAA IN\n",
    "query: 172.17.1.5 www.dwx.com. A IN\n",
    "not a query line, should be ignored\n",
]


@pytest.fixture
def mgr(tmp_path):
    m = UnboundManager(conf_path=str(tmp_path / "lm-netbox.conf"))
    return m


def _patch_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(um_mod, "LOGGING_CONF", str(tmp_path / "lm-logging.conf"))
    monkeypatch.setattr(um_mod, "QUERY_LOG", str(tmp_path / "lm-queries.log"))


def test_tail_query_log_counts_names_and_types(tmp_path, monkeypatch, mgr):
    _patch_paths(tmp_path, monkeypatch)
    with open(um_mod.QUERY_LOG, "w") as f:
        f.writelines(QUERY_LINES)

    mgr._tail_query_log()

    rows = {(r["name"], r["type"]): r["count"] for r in mgr.get_query_names()}
    assert rows[("www.dwx.com", "A")] == 3  # matched by the syslog-style line + 2 bare "query: ..." lines
    assert rows[("api.dwx.com", "AAAA")] == 1


def test_tail_query_log_incremental_offset(tmp_path, monkeypatch, mgr):
    """A second tail only parses newly-appended lines, not the whole file."""
    _patch_paths(tmp_path, monkeypatch)
    with open(um_mod.QUERY_LOG, "w") as f:
        f.write("query: 1.1.1.1 one.dwx.com. A IN\n")
    mgr._tail_query_log()
    assert mgr.get_query_names()[0]["count"] == 1

    with open(um_mod.QUERY_LOG, "a") as f:
        f.write("query: 1.1.1.1 one.dwx.com. A IN\n")
    mgr._tail_query_log()
    rows = {r["name"]: r["count"] for r in mgr.get_query_names()}
    assert rows["one.dwx.com"] == 2


def test_tail_query_log_handles_rotation(tmp_path, monkeypatch, mgr):
    """If the log file is replaced (new inode, smaller size), restart from 0
    rather than skipping the rotated-in content or crashing."""
    _patch_paths(tmp_path, monkeypatch)
    with open(um_mod.QUERY_LOG, "w") as f:
        f.write("query: 1.1.1.1 old.dwx.com. A IN\n" * 5)
    mgr._tail_query_log()
    assert mgr._query_log_offset > 0

    os.remove(um_mod.QUERY_LOG)
    with open(um_mod.QUERY_LOG, "w") as f:
        f.write("query: 2.2.2.2 new.dwx.com. A IN\n")
    mgr._tail_query_log()

    names = {r["name"] for r in mgr.get_query_names()}
    assert "new.dwx.com" in names


def test_max_tracked_names_cap_stops_new_names(tmp_path, monkeypatch, mgr):
    _patch_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(um_mod, "MAX_TRACKED_NAMES", 2)
    with open(um_mod.QUERY_LOG, "w") as f:
        f.write("query: 1.1.1.1 a.dwx.com. A IN\n")
        f.write("query: 1.1.1.1 b.dwx.com. A IN\n")
        f.write("query: 1.1.1.1 c.dwx.com. A IN\n")  # over the cap of 2
    mgr._tail_query_log()

    names = {r["name"] for r in mgr.get_query_names()}
    assert names == {"a.dwx.com", "b.dwx.com"}
    assert "c.dwx.com" not in names

    # existing tracked names keep incrementing past the cap
    with open(um_mod.QUERY_LOG, "a") as f:
        f.write("query: 1.1.1.1 a.dwx.com. A IN\n")
    mgr._tail_query_log()
    rows = {r["name"]: r["count"] for r in mgr.get_query_names()}
    assert rows["a.dwx.com"] == 2


def test_get_query_names_search_filters_by_substring(tmp_path, monkeypatch, mgr):
    _patch_paths(tmp_path, monkeypatch)
    with open(um_mod.QUERY_LOG, "w") as f:
        f.write("query: 1.1.1.1 www.dwx.com. A IN\n")
        f.write("query: 1.1.1.1 mail.example.com. A IN\n")

    results = mgr.get_query_names(search="dwx")
    assert [r["name"] for r in results] == ["www.dwx.com"]


def test_get_query_names_sorted_by_count_desc(tmp_path, monkeypatch, mgr):
    _patch_paths(tmp_path, monkeypatch)
    with open(um_mod.QUERY_LOG, "w") as f:
        f.write("query: 1.1.1.1 low.dwx.com. A IN\n")
        for _ in range(3):
            f.write("query: 1.1.1.1 high.dwx.com. A IN\n")

    results = mgr.get_query_names()
    assert results[0]["name"] == "high.dwx.com"
    assert results[0]["count"] == 3


def test_get_query_names_limit_truncates_results(tmp_path, monkeypatch, mgr):
    _patch_paths(tmp_path, monkeypatch)
    with open(um_mod.QUERY_LOG, "w") as f:
        for i in range(5):
            f.write(f"query: 1.1.1.1 host{i}.dwx.com. A IN\n")

    assert len(mgr.get_query_names(limit=2)) == 2
    assert len(mgr.get_query_names(limit=None)) == 5


def test_ensure_query_logging_writes_conf_once(tmp_path, monkeypatch, mgr):
    _patch_paths(tmp_path, monkeypatch)
    assert not os.path.exists(um_mod.LOGGING_CONF)

    first = mgr._ensure_query_logging()
    assert first is False  # newly written -> caller should reload
    assert os.path.exists(um_mod.LOGGING_CONF)
    content = open(um_mod.LOGGING_CONF).read()
    assert "log-queries: yes" in content
    assert um_mod.QUERY_LOG in content

    second = mgr._ensure_query_logging()
    assert second is True  # already matches -> no rewrite needed


@patch("unbound_manager.subprocess.run")
def test_get_stats_includes_query_names_and_reloads_on_first_enable(mock_run, tmp_path, monkeypatch, mgr):
    _patch_paths(tmp_path, monkeypatch)
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="total.num.queries=10\ntotal.num.cachehits=5\ntotal.num.cachemiss=5\n"
               "total.num.recursivereplies=5\ntotal.recursion.time.avg=0.01\n"
               "total.num.prefetch=0\ntime.up=100\nnum.query.type.A=10\n",
        stderr="",
    )
    with open(um_mod.QUERY_LOG, "w") as f:
        f.write("query: 1.1.1.1 www.dwx.com. A IN\n")

    result = mgr.get_stats()

    assert result["status"] == "SUCCESS"
    assert result["query_types"] == {"A": 10}
    assert result["query_names"] == [{"name": "www.dwx.com", "type": "A", "count": 1}]
    assert result["query_names_tracked"] == 1
    # first call must have triggered the "reload" unbound-control invocation
    # (query logging conf was freshly written) in addition to stats_noreset.
    calls = [c.args[0] for c in mock_run.call_args_list]
    assert ["unbound-control", "reload"] in calls
    assert ["unbound-control", "stats_noreset"] in calls


@patch("unbound_manager.subprocess.run")
def test_get_stats_search_filters_query_names(mock_run, tmp_path, monkeypatch, mgr):
    _patch_paths(tmp_path, monkeypatch)
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="total.num.queries=2\n",
        stderr="",
    )
    with open(um_mod.QUERY_LOG, "w") as f:
        f.write("query: 1.1.1.1 www.dwx.com. A IN\n")
        f.write("query: 1.1.1.1 mail.example.com. A IN\n")

    result = mgr.get_stats(search="mail")
    assert [q["name"] for q in result["query_names"]] == ["mail.example.com"]
