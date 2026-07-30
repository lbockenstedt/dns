# dns — Unbound DNS spoke (LM module)

<!-- INSTALLERS:START -->
## Installation

This repo holds the Unbound DNS spoke **source only** — it ships no installer of its own.
Install it one of two ways.

### As an agent role (preferred)

Load the `dns` role onto a generic LM agent from the hub WebUI, or pre-load it at install time:

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \
  | sudo bash -s -- --hub lm-hub.lrbtechnologies.com --roles dns
```

### Standalone, via the lm repo

```bash
sudo bash /opt/lm/dns/install_dns.sh --hub lm-hub.lrbtechnologies.com
```

| Flag | Purpose |
| :--- | :--- |
| `--hub URL` | Hub WebSocket URL. |
| `--id` | Pin the spoke id. |
| `--secret` | Pre-shared spoke secret. |
| `--infra-only` | Host-level infrastructure only — no spoke runtime. |

> A second copy of this source also lives at `lm/dns/`. The two drift deliberately; don't delete either.
<!-- INSTALLERS:END -->
