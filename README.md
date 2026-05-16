# YugabyteDB CIS Benchmark Checker :: Runbook

A Python security audit tool based on **CIS YugabyteDB 2.x Benchmark v1.0.0**.
Supports single-node and multi-node clusters, SSH-based remote OS checks, evidence collection, and HTML/JSON reports.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [All Options](#all-options)
4. [Usage Examples](#usage-examples)
   - [Single Node — DB checks only](#1-single-node--db-checks-only)
   - [Single Node — Full with OS checks](#2-single-node--full-with-os-checks)
   - [Single Node — From a jump host](#3-single-node--from-a-jump-host)
   - [Multi-Node — All cluster nodes via SSH](#4-multi-node--all-cluster-nodes-via-ssh)
   - [Multi-Node — SSH as a jump user](#5-multi-node--ssh-as-a-non-yugabyte-jump-user)
   - [Include YCQL checks](#6-include-ycql-checks)
   - [Include Level 2 checks](#7-include-level-2-checks)
   - [With evidence collection](#8-with-evidence-collection)
   - [JSON output](#9-json-output)
5. [CIS Section Alignment](#cis-section-alignment)
6. [Check Reference](#check-reference)
7. [OS Hardening Checks](#os-hardening-checks)
8. [SSH Setup for Multi-Node](#ssh-setup-for-multi-node)
9. [Report Guide](#report-guide)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.8+ | |
| psycopg2-binary | any | `pip install psycopg2-binary` |
| Network access | — | Port 5433 (YSQL) to the seed node |
| SSH client | — | Required for `--all-nodes` or when `--seed` is remote; `ssh` must be in `PATH` |
| Linux OS on nodes | — | OS hardening checks require Linux (`/proc`, `/sys`) |

```bash
pip install psycopg2-binary
```

---

## Quick Start

```bash
# Minimal — DB checks only, Level 1, report saved to yb_cis_report.html
python3 yugabytedb_cis_checker.py \
    --seed 127.0.0.1 \
    --user yugabyte \
    --password secret
```

Open `yb_cis_report.html` in a browser. Checks are grouped by CIS doc section. Use the **Filter** buttons (Fail / Warn / Pass / Manual) and **Expand All** to review findings.

---

## All Options

```
Database connection:
  --seed HOST           Seed node host/IP — YSQL connection and cluster discovery entry point
                        (default: 127.0.0.1)
  --port PORT           YSQL port (default: 5433)
  --user USER           Database user (default: yugabyte)
  --password PASSWORD   Database password
  --dbname DBNAME       Database name (default: yugabyte)
  --sslmode SSLMODE     prefer | require | disable (default: prefer)

File paths for conf / TLS checks:
  --tserver-conf PATH   Path to yb-tserver server.conf (enables GFlag-based checks).
                        When --ssh-key is set, the file is read from the remote seed
                        host via SSH — pass the path as it exists on that host.
  --master-conf  PATH   Path to yb-master server.conf (enables master GFlag checks).
                        Same remote-read behaviour as --tserver-conf when --ssh-key is set.
  --ssl-key-file PATH   TLS private key file        (enables key-file permission check)

Multi-node SSH:
  --all-nodes           Discover all cluster nodes via yb_servers() and SSH into each
  --ssh-user USER       SSH login user (default: yugabyte)
  --ssh-key  PATH       SSH private key file
  --ssh-port PORT       SSH port (default: 22)

API scope:
  --check-ycql          Include YCQL authentication check (CIS 5.1)

Evidence & output:
  --evidence            Capture raw command / query output in the report
  --output / -o FILE    Output file (default: yb_cis_report.html)
  --format html|json    Output format (default: html)
  --level 1|2           CIS level filter: 1 = Level-1 only (default), 2 = include Level-2 checks
```

> **Note on `--seed`:** The seed host is the entry point for both the YSQL connection and cluster node discovery (`SELECT * FROM yb_servers()`). The seed itself is included in discovery results and will have OS checks run against it. When `--ssh-key` is provided, all OS checks — including the seed — are performed via SSH (jump-host safe).

---

## Usage Examples

### 1. Single Node — DB checks only

Connects to the database and runs all DB-level CIS checks. No OS checks require additional parameters (they appear as MANUAL in the report if paths are not provided).

```bash
python3 yugabytedb_cis_checker.py \
    --seed     127.0.0.1 \
    --port     5433 \
    --user     yugabyte \
    --password secret \
    --output   report.html
```

---

### 2. Single Node — Full with OS checks

Provides all path arguments so every automated check can run. Suitable when the script runs directly on the YugabyteDB node.

```bash
python3 yugabytedb_cis_checker.py \
    --seed     127.0.0.1 \
    --port     5433 \
    --user     yugabyte \
    --password secret \
    --tserver-conf   /home/yugabyte/tserver/conf/server.conf \
    --master-conf    /home/yugabyte/master/conf/server.conf \
    --ssl-key-file   /home/yugabyte/certs/node.key \
    --output   report.html
```

---

### 3. Single Node — From a jump host

When the script runs on a jump/bastion host and the seed is remote, provide SSH credentials. The tool will use SSH for all OS checks against the seed node.

```bash
python3 yugabytedb_cis_checker.py \
    --seed     10.0.1.10 \
    --port     5433 \
    --user     yugabyte \
    --password secret \
    --ssh-user yugabyte \
    --ssh-key  ~/.ssh/yb_audit_rsa \
    --tserver-conf   /home/yugabyte/tserver/conf/server.conf \
    --master-conf    /home/yugabyte/master/conf/server.conf \
    --ssl-key-file   /home/yugabyte/certs/node.key \
    --output   report.html
```

> **Jump-host behaviour:** When `--ssh-key` is set, every OS check (including on the seed) is performed via SSH regardless of whether the host resolves to `localhost`. Additionally, `--tserver-conf` and `--master-conf` are read from the remote seed host via SSH — pass the path as it exists on that host (e.g. `/home/yugabyte/tserver/conf/server.conf`). This avoids incorrect results when the script runs on a machine that is not a cluster node.

---

### 4. Multi-Node — All cluster nodes via SSH

Discovers every node in the cluster using `SELECT * FROM yb_servers()`, then SSHes into each to run OS checks. DB checks run once against `--seed`.

```bash
python3 yugabytedb_cis_checker.py \
    --seed     10.0.1.10 \
    --port     5433 \
    --user     yugabyte \
    --password secret \
    --all-nodes \
    --ssh-user yugabyte \
    --ssh-key  ~/.ssh/yb_cluster_rsa \
    --tserver-conf   /home/yugabyte/tserver/conf/server.conf \
    --master-conf    /home/yugabyte/master/conf/server.conf \
    --ssl-key-file   /home/yugabyte/certs/node.key \
    --evidence \
    --output   cluster_report.html
```

The report shows:
- **Node badges** on every OS check card (e.g., `10.0.1.10`, `10.0.1.11`)
- **Node filter pills** to isolate a single node's results; cluster-wide DB checks always remain visible
- Per-section counts such as "11 checks · 3 nodes"

**What runs where:**

| CIS Section | Checks | Target |
|-------------|--------|--------|
| Section 1 Installation and Patches | CIS 1.2–1.8 | SSH → each node |
| Section 2 Directory and File Permissions | — (manual: umask) | Human review |
| Section 3 Logging Monitoring and Auditing | CIS 3.1.x, 3.2 | DB connection → seed |
| Section 4 User Access and Authorization | CIS 4.2–4.5 | DB connection → seed |
| Section 5 Access Control / Password Policies | CIS 5.1 (YCQL, opt-in), 5.5 (bind address) | tserver conf |
| Section 6 Connection and Login | CIS 6.1 (local auth), 6.2 (TCP trust) | DB + conf files |
| Section 7 YugabyteDB Settings | CIS 7.2, 7.7, 7.8, 7.9 | DB + conf files |
| Section 8 Special Configuration | Manual stubs | Human review |
| OS Hardening | Ulimits, systemctl | SSH → each node |

---

### 5. Multi-Node — SSH as a non-yugabyte jump user

If your SSH user is `ubuntu` or `ec2-user`, the tool wraps OS commands in `sudo -u yugabyte`. See [SSH Setup](#ssh-setup-for-multi-node) for the sudoers rule required.

```bash
python3 yugabytedb_cis_checker.py \
    --seed     10.0.1.10 \
    --port     5433 \
    --user     yugabyte \
    --password secret \
    --all-nodes \
    --ssh-user ubuntu \
    --ssh-key  ~/.ssh/aws_ec2_rsa \
    --tserver-conf /home/yugabyte/tserver/conf/server.conf \
    --output   cluster_report.html
```

---

### 6. Include YCQL checks

CIS 5.1 (`use_cassandra_authentication`) is opt-in because not all clusters use the YCQL API.

```bash
python3 yugabytedb_cis_checker.py \
    --seed         127.0.0.1 \
    --user         yugabyte \
    --password     secret \
    --tserver-conf /home/yugabyte/tserver/conf/server.conf \
    --check-ycql \
    --output report.html
```

---

### 7. Include Level 2 checks

Level 1 checks run by default. Pass `--level 2` to also include defence-in-depth controls.

```bash
python3 yugabytedb_cis_checker.py \
    --seed     127.0.0.1 \
    --user     yugabyte \
    --password secret \
    --level    2 \
    --output   report_l2.html
```

| Level | Description |
|-------|-------------|
| 1 (default) | Foundational controls — should pass on every deployment |
| 2 | Defence-in-depth controls — tighter settings, may not suit all environments |

---

### 8. With evidence collection

Captures the raw command or query output inside each check card for audit documentation.

```bash
python3 yugabytedb_cis_checker.py \
    --seed     10.0.1.10 \
    --user     yugabyte \
    --password secret \
    --all-nodes \
    --ssh-user yugabyte \
    --ssh-key  ~/.ssh/yb_audit_rsa \
    --evidence \
    --output   report_with_evidence.html
```

Each check card shows an **Evidence** toggle that expands to the raw output (ulimits from `/proc`, GUC values from `pg_settings`, SSH command stdout, etc.).

---

### 9. JSON output

Feed results into a SIEM, Jira, or custom tooling.

```bash
python3 yugabytedb_cis_checker.py \
    --seed     10.0.1.10 \
    --user     yugabyte \
    --password secret \
    --all-nodes \
    --ssh-user yugabyte \
    --ssh-key  ~/.ssh/yb_rsa \
    --evidence \
    --format   json \
    --output   cluster_report.json
```

JSON schema:

```json
{
  "generated":  "2025-05-16T10:30:00",
  "host":       "10.0.1.10",
  "port":       5433,
  "benchmark":  "CIS YugabyteDB 2.x Benchmark v1.0.0",
  "mode":       "3-node",
  "nodes":      ["10.0.1.10", "10.0.1.11", "10.0.1.12"],
  "summary":    { "PASS": 32, "FAIL": 5, "WARN": 8, "MANUAL": 27, "N/A": 2 },
  "checks": [
    {
      "id":          "cis1.8",
      "cis_ref":     "CIS 1.8",
      "title":       "Clocks NTP-synchronized",
      "level":       1,
      "section":     "Installation",
      "status":      "PASS",
      "detail":      "[10.0.1.10] NTP synchronized.",
      "value":       "",
      "node":        "10.0.1.10",
      "evidence":    "yes",
      "remediation": ""
    }
  ]
}
```

---

## CIS Section Alignment

The report is organized to mirror the **CIS YugabyteDB 2.x Benchmark v1.0.0** document structure. Each check card shows its CIS reference (e.g., `CIS 3.1.18`) as the primary identifier.

| CIS Section | Title | Automated | Manual |
|-------------|-------|-----------|--------|
| Section 1 | Installation and Patches | 1.2 (systemd), 1.4 (user/group), 1.5 (Python), 1.6 (YB version), 1.7 (non-root), 1.8 (NTP) | 1.1, 1.3 |
| Section 2 | Directory and File Permissions | — | 2.1 (umask) |
| Section 3 | Logging Monitoring and Auditing | 3.1.2–3.1.7, 3.1.12–3.1.24, 3.2 | 3.1.1, 3.1.8–3.1.11, 3.3 |
| Section 4 | User Access and Authorization | 4.2 (privileges), 4.3 (SECURITY DEFINER), 4.4 (DML grants), 4.5 (BYPASSRLS) | 4.1, 4.5 (RLS policies), 4.6 |
| Section 5 | Access Control / Password Policies | 5.1 (YCQL auth, opt-in), 5.5 (YCQL bind address) | 5.2–5.4 |
| Section 6 | Connection and Login | 6.1 (local auth), 6.2 (TCP trust) | — |
| Section 7 | YugabyteDB Settings | 7.2 (GUCs), 7.7 (node TLS), 7.8 (client TLS), 7.9 (pgcrypto) | 7.1, 7.3–7.6 |
| Section 8 | Special Configuration Considerations | — | 8.1–8.4 |

CIS sections marked **Manual** in the benchmark are included as reminder cards in the report so an auditor can document their manual verification. They are counted separately in the score banner and do not affect the automated pass rate.

---

## Check Reference

### CIS Section 1 — Installation and Patches

| CIS Ref | L | Title | Method |
|---------|---|-------|--------|
| CIS 1.4 | 1 | Dedicated `yugabyte` OS user/group exists | `getent passwd yugabyte` / `getent group yugabyte` |
| CIS 1.5 | 1 | Python 3.6+ installed | `python3 --version` |
| CIS 1.6 | 1 | YugabyteDB version is current | `SELECT version()` — warns on < 2.20, fails on EOL (< 2.14) |
| CIS 1.7 | 1 | YugabyteDB not running as root | `ps` output for `yb-tserver` |
| CIS 1.8 | 1 | Clocks NTP-synchronized | `timedatectl show` → `systemctl is-active chronyd` fallback |
| CIS 1.2 | 1 | `yb-tserver` systemd user service active | `systemctl --user is-active yb-tserver` as `yugabyte` |
| CIS 1.2 | 1 | `yb-master` systemd user service active | `systemctl --user is-active yb-master` as `yugabyte` |

Manual reminders: CIS 1.1 (packages), CIS 1.3 (cluster init).

### Section 2 — Directory and File Permissions

| Check | What is checked | CIS ref |
|-------|-----------------|---------|
| TLS key file permissions | `stat` on `--ssl-key-file`; expects `600` or `400` | CIS 7.8 |

Manual reminder: CIS 2.1 (OS umask — verify `umask 027` for the `yugabyte` user).

### Section 3 — Logging Monitoring and Auditing

| CIS Ref | L | GUC / Check | Pass Condition |
|---------|---|-------------|----------------|
| CIS 3.1.2 | 1 | `log_destination` | includes `stderr`, `csvlog`, or `jsonlog` |
| CIS 3.1.3 | 1 | `log_filename` | any non-empty pattern |
| CIS 3.1.4 | 1 | `log_file_mode` | `0600` or `0640` |
| CIS 3.1.5 | 1 | `log_truncate_on_rotation` | `on` |
| CIS 3.1.6 | 1 | `log_rotation_age` | > 0 (e.g., `1d`) |
| CIS 3.1.7 | 2 | `log_rotation_size` | > 0 (e.g., `100MB`) |
| CIS 3.1.12 | 1 | `log_min_messages` | `WARNING` or stricter |
| CIS 3.1.13 | 1 | `log_min_error_statement` | `ERROR` or stricter |
| CIS 3.1.14-16 | 1 | `debug_print_parse/rewritten/plan` | all `off` |
| CIS 3.1.17 | 1 | `debug_pretty_print` | `on` |
| CIS 3.1.18 | 1 | `log_connections` | `on` |
| CIS 3.1.19 | 1 | `log_disconnections` | `on` |
| CIS 3.1.20 | 1 | `log_error_verbosity` | `DEFAULT` or `VERBOSE` (not `TERSE`) |
| CIS 3.1.21 | 2 | `log_hostname` | `off` (avoid DNS overhead) |
| CIS 3.1.22 | 1 | `log_line_prefix` | includes `%t`, `%u`, `%d` |
| CIS 3.1.23 | 1 | `log_statement` | `ddl`, `mod`, or `all` |
| CIS 3.1.24 | 2 | `log_timezone` | `UTC` |
| CIS 3.2 | 1 | `pgaudit` loaded and `pgaudit.log` configured | `pgaudit` in `shared_preload_libraries` |

Manual reminders: CIS 3.1.1, 3.1.8–3.1.11 (syslog / syslog_ident), 3.3 (YCQL audit).

### Section 4 — User Access and Authorization

| CIS Ref | L | Title |
|---------|---|-------|
| CIS 4.2 | 1 | Superuser count ≤ 2 (WARN) / ≤ 5 (FAIL) |
| CIS 4.2 | 1 | Non-superusers without CREATEDB / CREATEROLE |
| CIS 4.2 | 1 | No grants of `pg_read/write_server_files`, `pg_execute_server_program` |
| CIS 4.3 | 2 | SECURITY DEFINER functions reviewed |
| CIS 4.4 | 1 | PUBLIC role cannot CREATE in public schema |
| CIS 4.4 | 2 | DELETE/TRUNCATE/UPDATE grants to app roles audited |
| CIS 4.5 | 2 | Non-superuser BYPASSRLS roles reviewed |

Manual reminders: CIS 4.1 (sudo), 4.5 (RLS policies), 4.6 (predefined roles).

### Section 5 — Access Control / Password Policies

| CIS Ref | L | Title | Notes |
|---------|---|-------|-------|
| CIS 5.1 | 1 | YCQL authentication enabled | Opt-in via `--check-ycql`; reads `--use_cassandra_authentication` from tserver conf |
| CIS 5.5 | 1 | YCQL bind address not unrestricted | Reads `--cql_proxy_bind_address` from tserver conf; FAIL if bound to `0.0.0.0` |

Manual reminders: CIS 5.2–5.4 (cassandra role password, dedicated role, unnecessary YCQL roles).

### Section 6 — Connection and Login

| CIS Ref | L | Title | Notes |
|---------|---|-------|-------|
| CIS 6.1 | 1 | `--ysql_enable_auth` flag enabled | Reads from tserver conf; FAIL if absent/false |
| CIS 6.1 | 1 | No `trust` auth for local UNIX socket connections | Reads `ysql_hba_conf_csv` from tserver conf; falls back to `pg_hba_file_rules` |
| CIS 6.2 | 1 | No `trust` auth for TCP/IP connections | Reads `ysql_hba_conf_csv` from tserver conf; falls back to `pg_hba_file_rules` |
| CIS 6.2 | 1 | No open `trust` HBA rules (all addresses) | Via `pg_hba_file_rules` |
| CIS 6.2 | 1 | No login roles with empty password | `pg_authid` |
| CIS 6.2 | 1 | `yugabyte` superuser has a password set | `pg_authid` |
| CIS 6.2 | 2 | Login roles have connection limits | `pg_roles.rolconnlimit` |

### Section 7 — YugabyteDB Settings

| CIS Ref | L | Title | Notes |
|---------|---|-------|-------|
| CIS 7.2 | 1 | `password_encryption = scram-sha-256` | `pg_settings` |
| CIS 7.2 | 2 | `statement_timeout` configured | Not `0` |
| CIS 7.2 | 2 | `idle_in_transaction_session_timeout` configured | Not `0` |
| CIS 7.2 | 1 | `track_activities = on` | |
| CIS 7.2 | 1 | `track_counts = on` | |
| CIS 7.2 | 2 | `listen_addresses` not `*` | |
| CIS 7.2 | 2 | `slow query logging` configured | `log_min_duration_statement` or `log_duration` |
| CIS 7.7 | 2 | Node-to-node encryption enabled | `--use_node_to_node_encryption=true` |
| CIS 7.8 | 1 | SSL enabled | `ssl = on` or `--use_client_to_server_encryption=true` |
| CIS 7.8 | 1 | `ssl_min_protocol_version` ≥ TLSv1.2 | |
| CIS 7.8 | 1 | `ssl_cert_file` and `ssl_key_file` configured | |
| CIS 7.2 | 1 | `--allow_non_tls_admin_requests=false` | Requires conf file |
| CIS 7.2 | 2 | `--webserver_interface` restricted | Requires conf file |
| CIS 7.2 | 2 | `--ysql_enable_pg_perm_extensions` not enabled | Requires conf file |
| CIS 7.2 | 2 | No dangerous extensions installed | `adminpack`, `file_fdw`, `dblink`, `postgres_fdw` |
| CIS 7.8 | 1 | `--ysql_enable_auth=true` | Requires conf file |
| CIS 7.9 | 2 | `pgcrypto` extension reviewed | `SELECT extname FROM pg_extension` — PASS if installed, WARN if absent |

Manual reminders: CIS 7.1, 7.3–7.6 (GFlag review).

---

## OS Hardening Checks

These checks run on each cluster node (locally or via SSH). They read from `/proc/<pid>/limits` and `systemctl --user` as the `yugabyte` OS user.

> **Note:** THP (Transparent Huge Pages), `vm.swappiness`, and core dump checks are not automated by this tool — verify them manually using the Remediation Quick Reference below.

| CIS Ref | L | Title | Source | Threshold |
|---------|---|-------|--------|-----------|
| CIS 1.7 | 1 | `nofile` ulimit ≥ 1,048,576 | `/proc/<pid>/limits` | soft & hard ≥ 1,048,576 |
| CIS 1.7 | 1 | `nproc` ulimit ≥ 12,000 | `/proc/<pid>/limits` | soft & hard ≥ 12,000 |
| CIS 1.2 | 1 | `yb-tserver` systemctl `--user` active | `systemctl --user is-active yb-tserver` | `active` |
| CIS 1.2 | 1 | `yb-master` systemctl `--user` active | `systemctl --user is-active yb-master` | `active` (N/A if not a master node) |

**How `systemctl --user` is invoked:**

```bash
# When SSH user IS yugabyte (--ssh-user yugabyte):
XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user is-active yb-tserver

# When SSH user is NOT yugabyte (e.g., ubuntu):
sudo -u yugabyte bash -c \
  'XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user is-active yb-tserver'
```

---

## SSH Setup for Multi-Node

### Key-based SSH access as `yugabyte`

```bash
# Generate a dedicated audit key pair (skip if you have one):
ssh-keygen -t ed25519 -f ~/.ssh/yb_audit -N ""

# Copy the public key to each cluster node:
ssh-copy-id -i ~/.ssh/yb_audit.pub yugabyte@10.0.1.10
ssh-copy-id -i ~/.ssh/yb_audit.pub yugabyte@10.0.1.11
ssh-copy-id -i ~/.ssh/yb_audit.pub yugabyte@10.0.1.12

# Test connectivity:
ssh -i ~/.ssh/yb_audit yugabyte@10.0.1.10 "echo OK"
```

Then run:

```bash
python3 yugabytedb_cis_checker.py \
    --seed 10.0.1.10 --user yugabyte --password secret \
    --all-nodes --ssh-user yugabyte --ssh-key ~/.ssh/yb_audit \
    --output cluster_report.html
```

### SSH via a jump/bastion user (`ubuntu`, `ec2-user`, etc.)

Allow the jump user to `sudo` as `yugabyte` without a password for the commands the tool needs:

```bash
# On each node:
echo "ubuntu ALL=(yugabyte) NOPASSWD: /bin/bash" \
    | sudo tee /etc/sudoers.d/audit-yugabyte
sudo chmod 440 /etc/sudoers.d/audit-yugabyte
```

Then:

```bash
python3 yugabytedb_cis_checker.py \
    --seed 10.0.1.10 --user yugabyte --password secret \
    --all-nodes --ssh-user ubuntu --ssh-key ~/.ssh/aws_key.pem \
    --output cluster_report.html
```

### Known-hosts / strict host checking

The tool passes `-o StrictHostKeyChecking=no` for automation convenience. For production audits, pre-populate `~/.ssh/known_hosts` and remove that flag from `ssh_run()` in the script.

---

## Report Guide

### Score banner

```
┌──────────┬──────┬──────┬─────────┬────────┐
│  Total   │ Pass │ Fail │ Warning │ Manual │
│   60     │  32  │  5   │   8     │  27    │
└──────────┴──────┴──────┴─────────┴────────┘
Compliance score (automated checks)   80% passed
```

**Score** = PASS ÷ (PASS + FAIL + WARN). Manual stubs and N/A checks are excluded from the score.

### CIS section grouping

Checks appear in CIS document order — Section 1 through Section 8. Each section header shows the check count and, in multi-node mode, the node count (e.g., "11 checks · 3 nodes").

### CIS reference badge

Each check card shows its CIS document reference as the primary identifier (e.g., `CIS 3.1.18`). The tool's internal check ID is shown as a small secondary label for cross-reference.

### Coverage summary table

Below the score banner, a grid shows per-CIS-section pass/fail/warn/manual counts at a glance.

### Node filter (multi-node only)

When `--all-nodes` is used, pill buttons appear:

```
Node:  [All Nodes]  [10.0.1.10]  [10.0.1.11]  [10.0.1.12]
```

Clicking a node pill shows only that node's OS checks. Cluster-wide DB checks (which apply to all nodes) remain visible regardless of the selected node. The status filter (Fail / Warn / Pass / Manual) and node filter work independently and can be combined.

### Manual check cards

All CIS sections that require human review appear in the report as **MANUAL** cards with audit instructions. They are counted separately and do not affect the automated pass rate. Use these as a checklist when completing your audit documentation.

### Evidence blocks

When `--evidence` is set, each card shows an **Evidence** toggle:

```
▶ Evidence
┌──────────────────────────────────────────────────┐
│ pg_settings[log_connections]                      │
│   setting : 'on'                                  │
│   unit    : None                                  │
│   source  : 'configuration file'                  │
│   context : 'superuser'                           │
└──────────────────────────────────────────────────┘
```

Clicking the toggle expands/collapses raw output without collapsing the check card.

---


## Troubleshooting

### `yb_servers()` returns no rows

- Requires the `yugabyte` superuser or a role with `pg_monitor` membership.
- Ensure the connecting role has sufficient privileges.
- The tool falls back to single-node mode automatically.

### OS checks or conf-based checks FAIL / MANUAL when running from a laptop

When the script runs on a laptop or jump host (not on the cluster node itself), two categories of checks are affected:

- **OS checks** (ulimits, systemctl) — fail because `/proc` is not local.
- **Conf-based checks** (CIS 6.1, 7.2, 7.7, etc.) — fail because `--tserver-conf` / `--master-conf` paths do not exist on the local machine.

Both are fixed by providing `--ssh-key`. OS checks SSH to each node; conf files are fetched from the remote seed host via `ssh cat <path>`:

```bash
python3 yugabytedb_cis_checker.py \
    --seed 10.0.1.10 --user yugabyte --password secret \
    --ssh-user yugabyte --ssh-key ~/.ssh/yb_audit \
    --tserver-conf /home/yugabyte/tserver/conf/server.conf \
    --master-conf  /home/yugabyte/master/conf/server.conf \
    --output report.html
```

The conf paths are interpreted as paths **on the remote host**, not the local machine.

### SSH checks return WARN / MANUAL for all OS hardening items

- Confirm `ssh -i <key> <user>@<host> "echo ok"` works from the auditing machine.
- Check that the SSH user can read `/proc/<pid>/limits` (readable by all users on Linux).
- For `systemctl --user`, ensure `loginctl enable-linger yugabyte` has been run on the node.

### `BatchMode=yes` causes connection refused

The tool uses `BatchMode=yes` to prevent interactive password prompts. Key-based SSH auth is required. Test with:

```bash
ssh -o BatchMode=yes -i <key> <user>@<host> "whoami"
```

### Section 8 shows MANUAL on the auditing machine (macOS)

`/proc` and `/sys` do not exist on macOS. OS hardening checks are Linux-only. Use `--all-nodes` + `--ssh-key` to run these checks remotely on Linux nodes even when the script runs on macOS.

### `psycopg2` import error

```bash
pip install psycopg2-binary
```

### Port 5433 connection refused

- Verify `--ysql_enable_auth=true` is set and YSQL is bound to the host you are connecting to.
- Check `--listen_addresses` in the tserver configuration.

### NTP check returns WARN instead of PASS

The tool checks `timedatectl show` first, then falls back to checking whether `chronyd` or `ntpd` is active. If neither command is available on the node, the check returns WARN. Verify manually with `timedatectl status` or `chronyc tracking`.
