# dns — Unbound DNS Spoke (Lab Manager Module)

The `dns` spoke manages DNS records, upstream forwarding zones, resolver clustering, and live query analytics across one or more **Unbound** resolver workers within the Lab Manager (LM) hub-and-spoke infrastructure.

---

## Overview & Architecture

The DNS module architecture separates management coordination from high-performance resolver execution:

```
┌─────────────────────────────────────────────────────────────┐
│                       Lab Manager Hub                       │
│                   (Control Plane & WebUI)                   │
└──────────────────────────────┬──────────────────────────────┘
                               │ WebSocket (TLS :443)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 DNS Coordinator (DNSSpoke)                  │
│       Role: dns  |  Desired State: /var/lib/lm-dns/desired.json│
└───────────────┬─────────────────────────────┬───────────────┘
                │ Verified TLS (:8769)        │ Verified TLS (:8769)
                ▼                             ▼
┌──────────────────────────────┐ ┌──────────────────────────────┐
│   Resolver Worker A (dns-a)   │ │   Resolver Worker B (dns-b)   │
│   Unit: lm-dns-worker        │ │   Unit: lm-dns-worker        │
│   Unbound Resolver & conf.d  │ │   Unbound Resolver & conf.d  │
└──────────────────────────────┘ └──────────────────────────────┘
```

- **Management Spoke (`DNSSpoke`):** Runs as an agent role or standalone service acting as the cluster coordinator. Connects to the Lab Manager Hub over WebSocket port 443 with push-ack-retry mailbox semantics.
- **Worker Resolver Tier (`DnsWorkerOps` / `lm-dns-worker`):** Deployed on one or more dedicated resolver nodes running Unbound. Resolvers communicate with the coordinator over a strictly verified TLS WebSocket listener on port **8769** with HMAC-signed framing and pinned CA certificates (`LM_CLUSTER_CA_CERT`). Workers execute bounded, import-fixed operations (`DNS_WORKER_OPS`).
- **Desired-State Authority:** The coordinator persists the single source of truth at `/var/lib/lm-dns/desired.json` with monotonic versioning and SHA-256 content digesting. All mutations write to disk before fan-out.
- **Fail-Closed Semantics:** Any corrupt, missing, or unreadable desired-state file blocks mutations and reconcile passes with actionable alerts, preventing inadvertent overwrites or record wipeout.
- **30-Second Convergence Reconcile Loop:** A background loop polls every worker via `DNSW_STATE`, compares on-disk and applied digests against the coordinator's desired state, and automatically reconciles drifted or rebooted resolvers.

---

## Core Features

- **DNS Record Management:**
  - Manages `A`, `AAAA`, `CNAME`, and `PTR` records.
  - Adding an `A` or `AAAA` record automatically generates the corresponding reverse `PTR` record.
  - Strict input validation (`_NAME_RE`) prevents line breaks, quotation marks, or semicolons from escaping Unbound's `local-data:` directives, mitigating configuration injection vulnerabilities.
- **Upstream Forwarders:**
  - Per-zone upstream resolution forwarding (e.g. `.` for root, `lab.example.com`).
  - Supports up to 8 upstream IP addresses (IPv4 and IPv6) per forwarding zone.
  - Supports atomic forwarder creation (`DNS_FORWARDER_ADD`), in-place updates and zone renaming (`DNS_FORWARDER_UPDATE`), and forwarder deletion (`DNS_FORWARDER_REMOVE`).
  - Clustered writes fan out across all resolver members; partial failures trigger automatic rollback to ensure multi-resolver consistency.
- **Live Query Analytics & Statistics:**
  - Extended Unbound telemetry retrieved via `stats_noreset` (total queries, cache hit/miss ratio, recursion latency, uptime, and query type distribution).
  - Incremental query log tailing surfaces per-destination query metrics with client IP tracking.
  - Tenant-scoped CIDR filtering ensures multi-tenant data isolation.
- **Diagnostics & Probing:**
  - Evaluates systemd service status, `unbound-checkconf` syntax validation, and port 53 socket listeners.
  - Performs live loopback (`127.0.0.1`) and LAN interface DNS resolution probes to verify operational readiness.
- **Resolver Clustering:**
  - Multi-node redundancy topology.
  - Reconciles state across all nodes and reports per-member drift, applied versions, and Unbound availability.
- **NetBox IPAM Auto-Sync:**
  - Built-in integration with NetBox IPAM.
  - Synchronizes IP assignments and `dns_name` attributes automatically via background loop (default 300s) and manual trigger (`DNS_SYNC`).

---

## Spoke Command Reference Table

Commands received and handled by `DNSSpoke` over the hub-to-spoke control channel:

| Command | Description | Handler / Action |
| :--- | :--- | :--- |
| `GET_VERSION` | Returns module name and active version string. | Returns module version. |
| `UPDATE_CONFIG` | Rebuilds `UnboundManager` and cluster paths from pushed config. | Updates runtime configuration. |
| `DNS_STATUS` | Reports Unbound status and total active record count. | Aggregated status across cluster or local node. |
| `DNS_DIAGNOSTICS` | Collects service health, configuration syntax, and query probes. | Returns comprehensive diagnostics payload. |
| `DNS_LIST` | Returns all managed records parsed from the configuration. | Regex-parses `local-data:` directives. |
| `DNS_ADD` | Adds a single DNS record with automatic PTR companion. | Validates, persists desired state, fans out / rewrites conf. |
| `DNS_UPDATE` | Replaces an existing DNS record matching name and type. | Validates, updates desired state, applies change. |
| `DNS_DELETE` | Removes a record by name and optional type. | Validates, updates desired state, applies change. |
| `DNS_SYNC` | Performs bulk record synchronization (e.g. from NetBox). | Deduplicates against existing records and applies. |
| `DNS_STATS` | Fetches performance stats and live destination query logs. | Queries `stats_noreset` and tails query log. |
| `DNS_FORWARDERS` | Lists configured upstream forwarding zones. | Aggregates forwarders across all cluster members. |
| `DNS_FORWARDER_ADD` | Adds a persistent forwarding zone across all resolvers. | Persists forwarder in `lm-forwarders.conf` and reloads. |
| `DNS_FORWARDER_UPDATE` | Updates upstream IP addresses for an existing forwarder zone. | Replaces upstreams in-place and reloads across workers. |
| `DNS_FORWARDER_REMOVE` | Removes a persistent forwarder zone from all resolvers. | Drops forwarder block and reloads across workers. |
| `DNS_CLUSTER_STATUS` | Reports cluster member convergence, digests, and drift. | Queries worker states and generates cluster summary. |
| `DNS_CLUSTER_CONFIG` | Configures member topology and worker PSK credentials. | Persists cluster members and starts TLS listener. |
| `DNS_CLUSTER_RECONCILE` | Triggers an immediate cluster state reconciliation pass. | Re-synchronizes drifted resolvers with desired state. |

---

## Worker Operations Reference Table

Operations exposed by `DnsWorkerOps` on resolver nodes (`lm-dns-worker`) over verified TLS (port 8769):

| Worker Operation | Description | Target Subsystem |
| :--- | :--- | :--- |
| `DNSW_APPLY` | Writes the desired record set to conf and reloads daemon. | Unbound conf.d rewrite + `unbound-control reload`. |
| `DNSW_STATE` | Reports applied version, record count, and on-disk digest. | Local state tracking and conf parser. |
| `DNSW_STATUS` | Checks whether Unbound daemon is running and counts records. | Local process monitoring. |
| `DNSW_DIAGNOSTICS` | Executes syntax validation, port checks, and query probes. | `unbound-checkconf`, socket inspect, DNS probe. |
| `DNSW_STATS` | Collects counters and query destination breakdown. | `unbound-control stats_noreset` and log tailer. |
| `DNSW_FORWARDERS` | Returns current forwarding zones active in Unbound. | `unbound-control list_forwards`. |
| `DNSW_FORWARDER_ADD` | Adds or merges upstream forwarders for a zone. | `/etc/unbound/conf.d/lm-forwarders.conf`. |
| `DNSW_FORWARDER_UPDATE` | Updates upstream resolvers in-place for a zone. | `/etc/unbound/conf.d/lm-forwarders.conf`. |
| `DNSW_FORWARDER_REMOVE` | Drops a forwarding zone from the managed configuration. | `/etc/unbound/conf.d/lm-forwarders.conf`. |
| `DNSW_STANDDOWN` | Disassociates worker from cluster, retaining active records. | Clears local cluster marker file. |

---

<!-- INSTALLERS:START -->
## Installation & Deployment

The `dns` module can be deployed as an agent-hosted role, as a standalone management service, or as dedicated resolver workers.

### 1. Hosted Role via Agent (Preferred for Coordinator)

Install the `dns` role onto a generic Lab Manager agent:

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \
  | sudo bash -s -- --hub lm-hub.lrbtechnologies.com --roles dns
```

### 2. Standalone Management Unit

Deploy the standalone management spoke unit directly from the LM repository:

```bash
sudo bash /opt/lm/dns/install_dns.sh --hub lm-hub.lrbtechnologies.com
```

### 3. Resolver Worker Installation

Deploy an Unbound resolver worker host to join a coordinator cluster:

```bash
sudo bash install_dns.sh \
  --member-id dns-a \
  --coordinator coordinator.internal.net \
  --worker-secret <shared-psk> \
  --ca-cert /etc/lm-dns/tls/coordinator.crt
```

| Flag | Purpose |
| :--- | :--- |
| `--hub URL` | Hub WebSocket URL (management spoke). |
| `--id` | Explicitly sets spoke ID. |
| `--secret` | Pre-shared key for hub authentication. |
| `--roles dns` | Enables the DNS management coordinator role. |
| `--roles dns-server` | Installs Unbound and enables resolver worker role. |
| `--member-id ID` | Unique resolver worker identifier for cluster participation. |
| `--coordinator HOST` | Hostname or IP of the DNS coordinator node. |
| `--worker-secret PSK` | Shared authentication secret between worker and coordinator. |
| `--ca-cert PATH` | Path to pinned coordinator TLS certificate (required for workers). |
| `--stand-down` | Deconfigures worker from cluster and disables `lm-dns-worker`. |
| `--infra-only` | Sets up host dependencies and Unbound without spoke runtime. |

> A second copy of this source also lives at `lm/dns/`. The two drift deliberately; do not delete either.
<!-- INSTALLERS:END -->

---

## Branches & Fleet Conventions

This repository strictly follows the workspace-wide `dev` → `qa` → `main` branching model:
- Contributors push directly to `dev`.
- Promotion into `qa` and `main` is handled exclusively through automated Pull Requests.
- `VERSION` is branch-owned and incremented by automation — never edit `VERSION` manually.
