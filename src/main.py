# Dependency self-heal — MUST run before the third-party imports below. A skewed
# auto-update / partial install can leave the venv missing a declared dep, which
# would hard-crash at import and crash-loop the unit under Restart=always.
# dep_guard is stdlib-only; it find_spec-checks requirements.txt and pip-installs
# any missing. Best-effort — an unavailable dep_guard is skipped, never fatal.
import os as _os
try:
    try:
        from core.src.dep_guard import ensure_requirements as _ensure_requirements
    except ImportError:
        from dep_guard import ensure_requirements as _ensure_requirements
    _ensure_requirements(_os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "requirements.txt"))
except Exception:
    pass

import asyncio
import logging
import argparse
import os

try:
    from core.src.messaging.agent_hosting import AgentHostingControlPlane
except ImportError:
    from messaging.agent_hosting import AgentHostingControlPlane

from src.dns_spoke import DNSSpoke

try:
    from logging_setup import configure_logging
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    except ImportError:
        import logging as _logging
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
configure_logging()
logger = logging.getLogger("DNSControlPlane")


class DNSControlPlane(AgentHostingControlPlane):
    """Standalone DNS spoke.

    Subclasses ``AgentHostingControlPlane`` so a clustered deployment can host
    its resolver workers on a DNS-specific ``/ws/agent`` port (8769 — distinct
    from pxmx 8766 / cs 8767 / hub-self 8768 so the roles coexist on one box).
    The listener is opt-in and only comes up once the DNS module declares 2+
    cluster members, so a single-host install binds nothing and behaves exactly
    as it did before.
    """

    MODULE_TYPE = "dns"
    AGENT_PORT_ENV = "LM_DNS_AGENT_PORT"
    AGENT_LOOPBACK_ENV = "LM_DNS_AGENT_LOOPBACK"
    AGENT_LISTENER_ENV = "LM_DNS_AGENT_LISTENER"
    AGENT_CONFIG_PATH = "/etc/lm-dns/agent.json"
    AGENT_LISTENER_OPT_IN = True
    # Workers authenticate by sending the shared PSK in their first frame, so
    # this listener never serves plaintext on a public interface: with no cert
    # it leaves the port closed and says why.
    AGENT_LISTENER_REQUIRE_TLS = True
    # Role-specific TLS env so a box hosting BOTH cluster roles gives each
    # listener its own certificate (the shared LM_TLS_CERT stays the fallback).
    AGENT_TLS_CERT_ENV = "LM_DNS_TLS_CERT"
    AGENT_TLS_KEY_ENV = "LM_DNS_TLS_KEY"
    AGENT_LOOPBACK_PORT = 8769
    AGENT_WSS_PORT = 8769
    AGENT_FALLBACK_PORT = 8769

    def get_service_name(self) -> str:
        return "lm-dns"

    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        self.module_type = "dns"
        # Separate from ``self.config`` — that dict is the /ws/agent listener's
        # own on-disk config (agent_secret) and is re-persisted verbatim, so
        # module settings must not be mixed into it.
        self.module_config = {
            # Persisted Unbound: records are written to a conf.d file (survives
            # reload/restart), matching the agent-role (lm/dns) implementation.
            "unbound_conf": os.getenv("UNBOUND_CONF", "/etc/unbound/conf.d/lm-netbox.conf"),
        }

    def _agent_listener_enabled(self) -> bool:
        """Serve ``/ws/agent`` only for a real resolver cluster (or an explicit
        ``LM_DNS_AGENT_LISTENER=1`` override)."""
        if os.environ.get(self.AGENT_LISTENER_ENV, "").strip() in ("1", "true", "True"):
            return True
        return self._cluster_listener_required()

    async def run(self):
        logger.info(f"Starting DNS spoke → {self.hub_url}")
        dns_spoke = DNSSpoke(self.spoke_id, self.module_config)
        # Wire the back-reference BEFORE registration: the module's cluster
        # transport resolves ``control_plane`` to reach connected workers, and
        # ``_cluster_listener_required`` is consulted the moment the module is
        # registered. Registering first left a window where the module looked
        # like a cluster but had no plane to talk to.
        dns_spoke.control_plane = self
        self.register_module("dns", dns_spoke)
        if self._agent_listener_enabled():
            self._ensure_agent_secret()
            self._start_agent_server_task()
        dns_spoke.start_background_loops()
        await super().run()


if __name__ == "__main__":
    # Everything defaults from the unit's EnvironmentFile ($INSTALL_DIR/dns/.env).
    # The secret is deliberately NOT passed on the command line — argv is world
    # readable via `ps`, and the unit never passed it, so `--secret required=True`
    # crash-looped every fresh install before the first hub connection. An empty
    # SPOKE_SECRET is the legitimate zero-touch case (the spoke connects
    # unauthenticated and waits for admin approval), so it must not be fatal.
    parser = argparse.ArgumentParser()
    parser.add_argument("--id",         default=os.getenv("SPOKE_ID", ""))
    parser.add_argument("--secret",     default=os.getenv("SPOKE_SECRET", ""))
    parser.add_argument("--hub-secret", nargs='?',
                        default=os.getenv("HUB_SECRET", ""), const="")
    parser.add_argument("--hub",        default=os.getenv("HUB_URL") or "auto")  # was required; default to auto-discovery (won't argparse-crash standalone)
    args = parser.parse_args()
    if not args.id:
        parser.error("--id is required (or SPOKE_ID in the environment)")

    cp = DNSControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
