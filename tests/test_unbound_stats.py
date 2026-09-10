from types import SimpleNamespace

from unbound_manager import UnboundManager


def test_query_types_accept_total_prefixed_counters(monkeypatch, tmp_path):
    output = "\n".join([
        "total.num.queries=9",
        "total.num.query.type.A=6",
        "total.num.query.type.AAAA=3",
    ])
    monkeypatch.setattr(
        "unbound_manager.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=output, stderr=""))

    result = UnboundManager(str(tmp_path / "records.conf")).get_stats()

    assert result["query_types"] == {"A": 6, "AAAA": 3}


def test_query_types_fall_back_to_summed_thread_counters(
        monkeypatch, tmp_path):
    output = "\n".join([
        "total.num.queries=9",
        "thread0.num.query.type.A=4",
        "thread1.num.query.type.A=2",
        "thread1.num.query.type.AAAA=3",
    ])
    monkeypatch.setattr(
        "unbound_manager.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=output, stderr=""))

    result = UnboundManager(str(tmp_path / "records.conf")).get_stats()

    assert result["query_types"] == {"A": 6, "AAAA": 3}
