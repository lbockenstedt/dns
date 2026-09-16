"""Clustered DNS statistics must combine EVERY resolver, correctly.

The Statistics page is fed by ``DNSSpoke._cluster_stats``, which fans
``DNSW_STATS`` out to every member and folds the replies into one set of
headline numbers. Two things were wrong with that fold:

1. ``recursion_time_avg`` -- produced by every member (see
   ``unbound_manager.get_stats``) -- was never carried into the combined
   ``global`` block at all. The WebUI renders it as the "Recursive Replies"
   sub-label, so a clustered deployment always read **"avg 0s"** no matter what
   either resolver measured.

2. A member that failed to answer was skipped silently. The headline totals are
   a SUM, so one missing resolver quietly halves them with nothing on screen to
   say so.

``recursion_time_avg`` is an AVERAGE, so the fix is not to sum it and not to
take a plain mean of the members' averages -- a resolver that served 10,000
recursions must not be outvoted by one that served 3. It is weighted by each
member's own ``num_recursive``.

These tests use the real ``DNSSpoke``/coordinator with a fake transport, so
they exercise the actual fold rather than asserting on source text.
"""

import asyncio

from dns_spoke import DNSSpoke

from test_dns_spoke_cluster import FakeMgr, FakeTransport


def _run(coro):
    return asyncio.run(coro)


class StatsTransport(FakeTransport):
    """FakeTransport whose DNSW_STATS reply is per-member and scriptable."""

    def __init__(self, members, stats_by_member):
        super().__init__(members)
        self.stats_by_member = stats_by_member

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        if command != "DNSW_STATS":
            return await super().fanout(command, data, timeout=timeout,
                                        member_ids=member_ids)
        targets = list(member_ids) if member_ids is not None else self.member_ids()
        results = {m: self.stats_by_member[m] for m in targets}
        ok = [m for m, r in results.items()
              if isinstance(r, dict) and r.get("status") == "SUCCESS"]
        failed = [m for m in targets if m not in ok]
        return {"status": "SUCCESS" if not failed else ("PARTIAL" if ok else "ERROR"),
                "results": results, "ok": ok, "failed": failed}


def _spoke(tmp_path, stats_by_member):
    members = list(stats_by_member)
    spoke = DNSSpoke("dns-1", {
        "unbound_conf": str(tmp_path / "conf.d" / "lm-netbox.conf"),
        "cluster_members": members,
        "cluster_config": str(tmp_path / "cluster.json"),
        "desired_state": str(tmp_path / "desired.json"),
    })
    spoke.mgr = FakeMgr()
    spoke._transport = StatsTransport([{"id": m, "host": ""} for m in members],
                                      stats_by_member)
    spoke.cluster.transport = spoke._transport
    return spoke


def _ok(**g):
    return {"status": "SUCCESS", "global": g, "query_types": {}, "query_names": []}


def _two_nodes(tmp_path, a, b):
    return _spoke(tmp_path, {"svcs1": a, "svcs2": b})


# --- the reported symptom -------------------------------------------------

def test_the_recursion_average_is_no_longer_always_zero(tmp_path):
    spoke = _two_nodes(
        tmp_path,
        _ok(total_queries=100, num_recursive=10, recursion_time_avg=0.2),
        _ok(total_queries=100, num_recursive=10, recursion_time_avg=0.4),
    )
    out = _run(spoke.handle_command("DNS_STATS", {}))
    assert out["global"]["recursion_time_avg"] != 0.0, (
        "clustered Statistics reported 'avg 0s' because this key was dropped"
    )


def test_two_equally_busy_resolvers_average_to_the_midpoint(tmp_path):
    spoke = _two_nodes(
        tmp_path,
        _ok(num_recursive=10, recursion_time_avg=0.2),
        _ok(num_recursive=10, recursion_time_avg=0.4),
    )
    out = _run(spoke.handle_command("DNS_STATS", {}))
    assert out["global"]["recursion_time_avg"] == 0.3


def test_the_average_is_weighted_by_how_much_each_resolver_actually_served(tmp_path):
    # A near-idle node must not drag the cluster average halfway to its own.
    # Naive mean would be 5.05; weighted is (10000*0.1 + 1*10.0)/10001.
    spoke = _two_nodes(
        tmp_path,
        _ok(num_recursive=10000, recursion_time_avg=0.1),
        _ok(num_recursive=1, recursion_time_avg=10.0),
    )
    out = _run(spoke.handle_command("DNS_STATS", {}))
    got = out["global"]["recursion_time_avg"]
    assert got == round((10000 * 0.1 + 1 * 10.0) / 10001, 4)
    assert abs(got - 5.05) > 1.0, "a plain mean would have been badly wrong here"


def test_a_cluster_with_no_recursions_reports_zero_not_a_crash(tmp_path):
    spoke = _two_nodes(tmp_path,
                       _ok(total_queries=5, num_recursive=0),
                       _ok(total_queries=5, num_recursive=0))
    out = _run(spoke.handle_command("DNS_STATS", {}))
    assert out["global"]["recursion_time_avg"] == 0.0


def test_a_garbage_average_from_one_resolver_does_not_break_the_fold(tmp_path):
    spoke = _two_nodes(
        tmp_path,
        _ok(num_recursive=10, recursion_time_avg="not-a-number"),
        _ok(num_recursive=10, recursion_time_avg=0.4),
    )
    out = _run(spoke.handle_command("DNS_STATS", {}))
    # svcs1 contributes its recursion COUNT but no time; the result must still
    # be a number and must not silently become svcs2's own average.
    assert out["global"]["recursion_time_avg"] == round(0.4 * 10 / 20, 4)


# --- the counters are still summed across BOTH nodes ---------------------

def test_the_headline_counters_sum_both_resolvers(tmp_path):
    spoke = _two_nodes(
        tmp_path,
        _ok(total_queries=100, cache_hits=60, cache_misses=40, num_recursive=40),
        _ok(total_queries=300, cache_hits=240, cache_misses=60, num_recursive=60),
    )
    g = _run(spoke.handle_command("DNS_STATS", {}))["global"]
    assert g["total_queries"] == 400
    assert g["cache_hits"] == 300
    assert g["cache_misses"] == 100
    assert g["num_recursive"] == 100


def test_the_cache_hit_ratio_is_computed_on_the_combined_totals(tmp_path):
    # Not an average of the two members' ratios (which would be 67.5%).
    spoke = _two_nodes(
        tmp_path,
        _ok(total_queries=100, cache_hits=60),
        _ok(total_queries=300, cache_hits=240),
    )
    g = _run(spoke.handle_command("DNS_STATS", {}))["global"]
    assert g["cache_hit_ratio"] == 75.0


# --- a resolver that did not answer must be visible ----------------------

def test_a_resolver_that_did_not_answer_is_reported(tmp_path):
    spoke = _two_nodes(
        tmp_path,
        _ok(total_queries=100, num_recursive=10, recursion_time_avg=0.2),
        {"status": "ERROR", "message": "worker unavailable"},
    )
    out = _run(spoke.handle_command("DNS_STATS", {}))
    assert out["member_errors"] == {"svcs2": "worker unavailable"}
    assert out["members_reporting"] == 1
    assert out["member_count"] == 2


def test_a_healthy_cluster_reports_no_errors(tmp_path):
    spoke = _two_nodes(tmp_path, _ok(total_queries=1), _ok(total_queries=1))
    out = _run(spoke.handle_command("DNS_STATS", {}))
    assert out["member_errors"] == {}
    assert out["members_reporting"] == 2 == out["member_count"]


def test_a_missing_resolver_does_not_corrupt_the_totals(tmp_path):
    # It is excluded, not counted as zeroes that skew the average.
    spoke = _two_nodes(
        tmp_path,
        _ok(total_queries=100, num_recursive=10, recursion_time_avg=0.5),
        {"status": "ERROR", "message": "down"},
    )
    g = _run(spoke.handle_command("DNS_STATS", {}))["global"]
    assert g["total_queries"] == 100
    assert g["recursion_time_avg"] == 0.5


def test_a_malformed_reply_is_treated_as_a_non_reporting_member(tmp_path):
    spoke = _spoke(tmp_path, {"svcs1": _ok(total_queries=7), "svcs2": None})
    out = _run(spoke.handle_command("DNS_STATS", {}))
    assert "svcs2" in out["member_errors"]
    assert out["global"]["total_queries"] == 7
