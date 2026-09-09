from unbound_manager import UnboundManager


def _result(ok=True, output="", error=""):
    return {"ok": ok, "exit_code": 0 if ok else 1,
            "output": output, "error": error}


def test_diagnostics_distinguishes_loopback_from_lan_listener(monkeypatch, tmp_path):
    mgr = UnboundManager(str(tmp_path / "records.conf"))

    def run(cmd, timeout=5):
        if cmd[0] == "ss":
            return _result(output=(
                "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* "
                'users:(("systemd-resolve",pid=1,fd=1))'))
        return _result(output="active")

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_local_ipv4s", lambda: ["10.0.0.5"])
    monkeypatch.setattr(mgr, "_dns_probe", lambda server: {
        "server": server, "responded": server == "127.0.0.1",
        "rcode": 0, "answers": 1, "latency_ms": 1,
        "error": "" if server == "127.0.0.1" else "timed out",
    })

    result = mgr.diagnostics()
    assert result["healthy"] is False
    assert result["sockets"]["has_port_53_listener"] is True
    assert result["sockets"]["has_lan_listener"] is False
    assert any("loopback" in item for item in result["recommendations"])
