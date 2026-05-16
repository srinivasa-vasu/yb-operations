#!/usr/bin/env python3
"""
YugabyteDB CIS Benchmark Checker — Multi-Node
Based on CIS YugabyteDB 2.x Benchmark v1.0.0

Usage:
    # Single-node (original behaviour):
    python3 yugabytedb_cis_checker.py \
        --seed 127.0.0.1 --port 5433 \
        --user yugabyte --password secret \
        --output report.html

    # All cluster nodes via yb_servers() + SSH:
    python3 yugabytedb_cis_checker.py \
        --seed 127.0.0.1 --port 5433 \
        --user yugabyte --password secret \
        --all-nodes --ssh-user yugabyte --ssh-key ~/.ssh/yb_rsa \
        --evidence --output report.html

    # YCQL checks included:
    python3 yugabytedb_cis_checker.py ... --check-ycql
"""

import argparse
import datetime
import json
import os
import pwd
import re
import shlex
import socket
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("ERROR: psycopg2 is required. Install with: pip install psycopg2-binary")
    sys.exit(1)

# ─── Status constants ───────────────────────────────────────────────────────────

PASS   = "PASS"
FAIL   = "FAIL"
WARN   = "WARN"
MANUAL = "MANUAL"
INFO   = "INFO"
NA     = "N/A"


# ─── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    check_id:    str
    title:       str
    level:       int          # CIS Level 1 or 2
    section:     str
    status:      str          # PASS / FAIL / WARN / MANUAL / N/A
    detail:      str          # What was found
    remediation: str          # How to fix if FAIL/WARN
    value:       str = ""     # Raw value observed
    node:        str = ""     # Hostname of the node (empty = cluster-wide)
    evidence:    str = ""     # Raw command/query output (populated with --evidence)
    cis_ref:     str = ""     # CIS doc section reference (e.g., "CIS 3.1.18")


@dataclass
class NodeInfo:
    host:      str
    port:      int            # YSQL port
    region:    str = ""
    zone:      str = ""
    node_type: str = "tserver"
    public_ip: str = ""


# ─── Helper utilities ────────────────────────────────────────────────────────────

def guc(cur, param: str) -> Optional[str]:
    """Fetch a single GUC setting from pg_settings."""
    try:
        cur.execute("SELECT setting FROM pg_settings WHERE name = %s", (param,))
        row = cur.fetchone()
        return row[0] if row else None   # row[0] works for both tuple and RealDictRow
    except Exception:
        return None


def _guc_ev(cur, param: str, args) -> Tuple[Optional[str], str]:
    """Fetch a GUC setting and build evidence text when --evidence is enabled."""
    try:
        if getattr(args, "evidence", False):
            cur.execute(
                "SELECT setting, unit, source, context FROM pg_settings WHERE name = %s",
                (param,)
            )
            row = cur.fetchone()
            if not row:
                return None, f"pg_settings[{param}]: not found"
            val = row[0]
            ev = (
                f"pg_settings[{param}]\n"
                f"  setting : {row[0]!r}\n"
                f"  unit    : {row[1]!r}\n"
                f"  source  : {row[2]!r}\n"
                f"  context : {row[3]!r}"
            )
            return val, ev
        else:
            return guc(cur, param), ""
    except Exception as e:
        return None, str(e) if getattr(args, "evidence", False) else ""


def _rows_ev(args, rows, label: str = "query result") -> str:
    """Format a list of rows as evidence text."""
    if not getattr(args, "evidence", False) or not rows:
        return ""
    lines = [f"{label}:"]
    for r in rows:
        lines.append(f"  {r}")
    return "\n".join(lines)


def query_col(cur, sql: str, params=None) -> list:
    """Return a flat list from the first column of a query."""
    try:
        cur.execute(sql, params or ())
        return [row[0] for row in cur.fetchall()]
    except Exception:
        return []


def query_one(cur, sql: str, params=None):
    """Return first cell of first row, or None."""
    try:
        cur.execute(sql, params or ())
        row = cur.fetchone()
        return row[0] if row else None
    except Exception:
        return None


def _gflag_from_text(text: str, flag: str) -> Optional[str]:
    """Parse a GFlag value from the text content of a conf file."""
    with_value = re.compile(
        rf'^--{re.escape(flag)}(?:\s*=\s*|\s+)([^#\s][^#]*?)(?:\s+#.*)?$'
    )
    bare_true  = re.compile(rf'^--{re.escape(flag)}\s*(?:#.*)?$')
    bare_false = re.compile(rf'^--no{re.escape(flag)}\s*(?:#.*)?$')
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if bare_false.match(line):
            return "false"
        if bare_true.match(line):
            return "true"
        m = with_value.match(line)
        if m:
            return m.group(1).strip()
    return None


def yb_gflag_from_conf(conf_path: str, flag: str, args=None) -> Optional[str]:
    """Read a YugabyteDB GFlag from a server.conf / master.conf file.

    Handles all gflags boolean and value forms:
      --flag=value          (standard)
      --flag = value        (spaces around =)
      --flag value          (space separator)
      --flag=value  # note  (inline comment)
      --flag                (bare boolean → returns "true")
      --noflag              (negated boolean → returns "false")

    When the file is not present locally and SSH credentials are configured
    (via args), it is fetched from the seed host via SSH so that the script
    can be run from a laptop / jump host.
    Returns the value string if found, None if the file is missing or the flag
    is absent.  Raises no exceptions.
    """
    if not conf_path:
        return None
    conf_path = os.path.expanduser(os.path.expandvars(conf_path.strip()))

    has_ssh = args is not None and bool(getattr(args, 'ssh_key', None))

    if has_ssh:
        # SSH mode: conf file lives on the remote seed host
        seed = getattr(args, 'host', None)
        if not seed:
            return None
        try:
            stdout, _, rc = ssh_run(seed, f"cat {shlex.quote(conf_path)} 2>/dev/null", args)
            if rc == 0 and stdout:
                return _gflag_from_text(stdout, flag)
        except Exception:
            pass
        return None

    # Local mode: conf file is on the machine running the script
    if not os.path.isfile(conf_path):
        return None
    try:
        with open(conf_path, encoding='utf-8', errors='replace') as f:
            return _gflag_from_text(f.read(), flag)
    except Exception:
        return None


# ─── SSH & multi-node helpers ────────────────────────────────────────────────────

def ssh_run(host: str, command: str, args) -> Tuple[str, str, int]:
    """Execute a shell command on a remote host via SSH."""
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
    ]
    if getattr(args, "ssh_key", None):
        ssh_cmd += ["-i", args.ssh_key]
    port = getattr(args, "ssh_port", 22)
    if port != 22:
        ssh_cmd += ["-p", str(port)]
    ssh_cmd.append(f"{args.ssh_user}@{host}")
    ssh_cmd.append(command)
    try:
        proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return "", "SSH connection timed out", -1
    except FileNotFoundError:
        return "", "ssh binary not found in PATH", -1
    except Exception as e:
        return "", str(e), -1


def ssh_as_yugabyte(host: str, command: str, args) -> Tuple[str, str, int]:
    """Run a command as the 'yugabyte' OS user on a remote host."""
    if args.ssh_user == "yugabyte":
        return ssh_run(host, command, args)
    wrapped = f"sudo -u yugabyte bash -c {shlex.quote(command)}"
    return ssh_run(host, wrapped, args)


def discover_nodes(conn) -> List[NodeInfo]:
    """Query yb_servers() to discover all cluster nodes."""
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT host, port, num_connections, node_type, cloud, region, zone, public_ip
            FROM yb_servers()
            ORDER BY host
        """)
        nodes = []
        for row in cur.fetchall():
            nodes.append(NodeInfo(
                host=row[0],
                port=int(row[1]) if row[1] else 5433,
                region=row[5] or "",
                zone=row[6] or "",
                node_type=row[3] or "tserver",
                public_ip=row[7] or "",
            ))
        return nodes
    except Exception as e:
        print(f"[!] yb_servers() failed: {e}")
        return []


def _run_cmd_local(command: str) -> Tuple[str, str, int]:
    """Run a shell command locally."""
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=30
        )
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except Exception as e:
        return "", str(e), -1


def run_cmd_on_node(host: str, command: str, args, is_local: bool) -> Tuple[str, str, int]:
    """Run a command locally or via SSH depending on is_local flag."""
    if is_local:
        return _run_cmd_local(command)
    return ssh_run(host, command, args)


def run_cmd_as_yugabyte_on_node(host: str, command: str, args, is_local: bool) -> Tuple[str, str, int]:
    """Run a command as yugabyte user locally or via SSH."""
    if is_local:
        # Try sudo -u yugabyte; fall back to running directly if already yugabyte
        try:
            current_user = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            current_user = ""
        if current_user == "yugabyte":
            return _run_cmd_local(command)
        wrapped = f"sudo -u yugabyte bash -c {shlex.quote(command)}"
        return _run_cmd_local(wrapped)
    return ssh_as_yugabyte(host, command, args)


# ─── Section 2: Authentication ───────────────────────────────────────────────────

def check_2_1(cur, args) -> CheckResult:
    """2.1 – YSQL authentication must be enabled (not trust for all)."""
    # Check pg_hba_file_rules for any 'trust' entries allowing all users
    try:
        cur.execute("""
            SELECT address, auth_method, options
            FROM pg_hba_file_rules
            WHERE auth_method = 'trust'
              AND (address = '0.0.0.0/0' OR address = '::/0' OR address IS NULL)
        """)
        rows = cur.fetchall()
    except Exception:
        rows = []

    if rows:
        detail = "Found 'trust' HBA rules allowing all connections without password: " + \
                 str([dict(r) for r in rows])
        return CheckResult(
            "2.1", "YSQL authentication enabled (no open trust rules)",
            1, "Authentication", FAIL, detail,
            "Replace 'trust' entries in ysql_hba_conf with 'scram-sha-256' or 'md5'.",
            cis_ref="CIS 6.2"
        )

    # Also check for any trust at all
    try:
        cur.execute("SELECT count(*) FROM pg_hba_file_rules WHERE auth_method = 'trust'")
        trust_count = cur.fetchone()[0]
    except Exception:
        trust_count = 0

    if trust_count > 0:
        return CheckResult(
            "2.1", "YSQL authentication enabled (no open trust rules)",
            1, "Authentication", WARN,
            f"{trust_count} 'trust' HBA rule(s) found. Verify these are intentional local-only entries.",
            "Review all 'trust' entries in ysql_hba_conf; prefer scram-sha-256.",
            str(trust_count), cis_ref="CIS 6.2"
        )

    return CheckResult(
        "2.1", "YSQL authentication enabled (no open trust rules)",
        1, "Authentication", PASS,
        "No open 'trust' HBA rules found allowing unauthenticated access.",
        "", cis_ref="CIS 6.2"
    )


def check_2_2(cur, args) -> CheckResult:
    """2.2 – Password encryption must be scram-sha-256 (not md5)."""
    val, ev = _guc_ev(cur, "password_encryption", args)
    if val is None:
        return CheckResult(
            "2.2", "Password encryption set to scram-sha-256",
            1, "Authentication", MANUAL,
            "Could not read password_encryption GUC.",
            "Set password_encryption = scram-sha-256 in ysql_pg_conf_csv flag.",
            evidence=ev, cis_ref="CIS 7.2"
        )
    status = PASS if val == "scram-sha-256" else FAIL
    detail = f"password_encryption = '{val}'"
    return CheckResult(
        "2.2", "Password encryption set to scram-sha-256",
        1, "Authentication", status, detail,
        "Add 'password_encryption=scram-sha-256' to --ysql_pg_conf_csv flag and reset all passwords.",
        val, evidence=ev, cis_ref="CIS 7.2"
    )


def check_2_3(cur, args) -> CheckResult:
    """2.3 – No roles should have an empty password."""
    try:
        cur.execute("""
            SELECT rolname
            FROM pg_authid
            WHERE rolcanlogin = true
              AND rolpassword IS NULL
              AND rolname NOT IN ('pg_signal_backend')
        """)
        rows = [r[0] for r in cur.fetchall()]
    except Exception:
        rows = []

    ev = _rows_ev(args, rows, "roles with empty password")
    if rows:
        return CheckResult(
            "2.3", "No login roles with empty password",
            1, "Authentication", FAIL,
            f"Roles with login and no password set: {rows}",
            "Set passwords for all login roles: ALTER ROLE <name> WITH PASSWORD '<pwd>';",
            str(rows), evidence=ev, cis_ref="CIS 7.2"
        )
    return CheckResult(
        "2.3", "No login roles with empty password",
        1, "Authentication", PASS,
        "All login-enabled roles have passwords set.",
        "", evidence=ev, cis_ref="CIS 7.2"
    )


def check_2_4(cur, args) -> CheckResult:
    """2.4 – Default 'yugabyte' superuser password should be changed."""
    try:
        cur.execute("""
            SELECT rolname,
                   rolpassword IS NULL AS no_password,
                   rolpassword LIKE 'md5%' AS md5_hash
            FROM pg_authid
            WHERE rolname = 'yugabyte'
        """)
        row = cur.fetchone()
    except Exception:
        row = None

    ev = _rows_ev(args, [row] if row else [], "pg_authid yugabyte row")
    if row is None:
        return CheckResult(
            "2.4", "Default 'yugabyte' superuser has a password set",
            1, "Authentication", MANUAL,
            "'yugabyte' role not found. Confirm superuser account name.",
            "Ensure the primary superuser has a strong, non-default password.", evidence=ev,
            cis_ref="CIS 7.2"
        )

    _, no_pwd, is_md5 = row
    if no_pwd:
        return CheckResult(
            "2.4", "Default 'yugabyte' superuser has a password set",
            1, "Authentication", FAIL,
            "'yugabyte' superuser has NO password set.",
            "Set a strong password: ALTER ROLE yugabyte WITH PASSWORD '<strong_pwd>';", evidence=ev,
            cis_ref="CIS 7.2"
        )
    if is_md5:
        return CheckResult(
            "2.4", "Default 'yugabyte' superuser has a password set",
            2, "Authentication", WARN,
            "'yugabyte' superuser password uses MD5 hashing (weaker).",
            "Re-set password with scram-sha-256 after setting password_encryption=scram-sha-256.", evidence=ev,
            cis_ref="CIS 7.2"
        )
    return CheckResult(
        "2.4", "Default 'yugabyte' superuser has a password set",
        1, "Authentication", PASS,
        "'yugabyte' superuser has a password set with scram-sha-256 hashing.",
        "", evidence=ev, cis_ref="CIS 7.2"
    )


def check_2_5(cur, args) -> CheckResult:
    """2.5 – Connection limit should be set per role (not unlimited)."""
    try:
        cur.execute("""
            SELECT rolname
            FROM pg_roles
            WHERE rolcanlogin = true
              AND rolconnlimit = -1
              AND rolname NOT LIKE 'pg_%'
              AND rolname NOT IN ('yugabyte', 'postgres')
        """)
        rows = [r[0] for r in cur.fetchall()]
    except Exception:
        rows = []

    ev = _rows_ev(args, rows, "roles with unlimited connections")
    if rows:
        return CheckResult(
            "2.5", "Login roles have connection limits set",
            2, "Authentication", WARN,
            f"Roles with unlimited connections (-1): {rows}",
            "Set connection limits: ALTER ROLE <name> CONNECTION LIMIT <n>;",
            str(rows), evidence=ev, cis_ref="CIS 7.2"
        )
    return CheckResult(
        "2.5", "Login roles have connection limits set",
        2, "Authentication", PASS,
        "All non-superuser login roles have explicit connection limits.",
        "", evidence=ev, cis_ref="CIS 7.2"
    )


# ─── Section 3: Privilege Management ────────────────────────────────────────────

def check_3_1(cur, args) -> CheckResult:
    """3.1 – Limit the number of superuser accounts."""
    try:
        cur.execute("""
            SELECT rolname FROM pg_roles
            WHERE rolsuper = true
            ORDER BY rolname
        """)
        supers = [r[0] for r in cur.fetchall()]
    except Exception:
        supers = []

    count = len(supers)
    ev = _rows_ev(args, supers, "superuser roles")
    if count > 5:
        status = FAIL
    elif count > 2:
        status = WARN
    else:
        status = PASS

    detail = f"{count} superuser role(s) found: {supers}"
    return CheckResult(
        "3.1", "Limit number of superuser accounts",
        1, "Privilege Management", status, detail,
        "Revoke superuser from accounts that don't need it: ALTER ROLE <name> NOSUPERUSER;",
        str(count), evidence=ev, cis_ref="CIS 4.2"
    )


def check_3_2(cur, args) -> CheckResult:
    """3.2 – No regular roles should have CREATEDB or CREATEROLE unnecessarily."""
    try:
        cur.execute("""
            SELECT rolname,
                   rolcreatedb,
                   rolcreaterole
            FROM pg_roles
            WHERE rolcanlogin = true
              AND rolsuper = false
              AND (rolcreatedb = true OR rolcreaterole = true)
              AND rolname NOT LIKE 'pg_%'
            ORDER BY rolname
        """)
        rows = [
            {"rolname": r[0], "rolcreatedb": r[1], "rolcreaterole": r[2]}
            for r in cur.fetchall()
        ]
    except Exception:
        rows = []

    if rows:
        detail = f"Non-superuser login roles with CREATEDB/CREATEROLE: {rows}"
        return CheckResult(
            "3.2", "Restrict CREATEDB and CREATEROLE privileges",
            1, "Privilege Management", WARN, detail,
            "Revoke unneeded privileges: ALTER ROLE <name> NOCREATEDB NOCREATEROLE;",
            str(rows), cis_ref="CIS 4.2"
        )
    return CheckResult(
        "3.2", "Restrict CREATEDB and CREATEROLE privileges",
        1, "Privilege Management", PASS,
        "No non-superuser login roles have CREATEDB or CREATEROLE.",
        "", cis_ref="CIS 4.2"
    )


def check_3_3(cur, args) -> CheckResult:
    """3.3 – PUBLIC schema should not allow CREATE by public role (PG 14 and below risk)."""
    try:
        cur.execute("""
            SELECT has_schema_privilege('public', 'public', 'CREATE') AS pub_create
        """)
        row = cur.fetchone()
        pub_create = row[0] if row else False
    except Exception:
        pub_create = None

    if pub_create is None:
        return CheckResult(
            "3.3", "PUBLIC role cannot CREATE in public schema",
            1, "Privilege Management", MANUAL,
            "Could not check public schema privileges.",
            "Run: REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
            cis_ref="CIS 4.4"
        )
    if pub_create:
        return CheckResult(
            "3.3", "PUBLIC role cannot CREATE in public schema",
            1, "Privilege Management", FAIL,
            "PUBLIC role has CREATE privilege on the public schema.",
            "Run: REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
            cis_ref="CIS 4.4"
        )
    return CheckResult(
        "3.3", "PUBLIC role cannot CREATE in public schema",
        1, "Privilege Management", PASS,
        "PUBLIC role does not have CREATE privilege on public schema.",
        "", cis_ref="CIS 4.4"
    )


def check_3_4(cur, args) -> CheckResult:
    """3.4 – Roles with BYPASSRLS should be reviewed."""
    try:
        cur.execute("""
            SELECT rolname FROM pg_roles
            WHERE rolbypassrls = true AND rolname NOT LIKE 'pg_%'
            ORDER BY rolname
        """)
        rows = [r[0] for r in cur.fetchall()]
    except Exception:
        rows = []

    # Superusers bypass RLS by default, filter them for noise
    try:
        cur.execute("SELECT rolname FROM pg_roles WHERE rolsuper=true")
        supers = {r[0] for r in cur.fetchall()}
    except Exception:
        supers = set()

    non_super_bypass = [r for r in rows if r not in supers]
    if non_super_bypass:
        return CheckResult(
            "3.4", "Non-superuser roles with BYPASSRLS should be reviewed",
            2, "Privilege Management", WARN,
            f"Non-superuser roles with BYPASSRLS: {non_super_bypass}",
            "Review and revoke BYPASSRLS where not required: ALTER ROLE <name> NOBYPASSRLS;",
            str(non_super_bypass), cis_ref="CIS 4.5"
        )
    return CheckResult(
        "3.4", "Non-superuser roles with BYPASSRLS",
        2, "Privilege Management", PASS,
        "No non-superuser roles have BYPASSRLS attribute.",
        "", cis_ref="CIS 4.5"
    )


def check_3_5(cur, args) -> CheckResult:
    """3.5 – Dangerous system file/program grants should not exist."""
    try:
        cur.execute("""
            SELECT rolname FROM pg_roles
            WHERE rolname IN ('pg_read_server_files',
                              'pg_write_server_files',
                              'pg_execute_server_program')
        """)
        dangerous_roles = {r[0] for r in cur.fetchall()}
    except Exception:
        dangerous_roles = set()

    granted = []
    for role in dangerous_roles:
        try:
            cur.execute("""
                SELECT m.roleid::regrole::text AS member
                FROM pg_auth_members m
                JOIN pg_roles r ON r.oid = m.roleid
                WHERE r.rolname = %s
                  AND m.admin_option = false
            """, (role,))
            # Actually need member roles, not roleid
            cur.execute("""
                SELECT r2.rolname AS member
                FROM pg_auth_members m
                JOIN pg_roles r1 ON r1.oid = m.roleid
                JOIN pg_roles r2 ON r2.oid = m.member
                WHERE r1.rolname = %s
            """, (role,))
            members = [r[0] for r in cur.fetchall()]
            if members:
                granted.append(f"{role} → {members}")
        except Exception:
            pass

    if granted:
        return CheckResult(
            "3.5", "No unsafe server-file/program role grants",
            1, "Privilege Management", FAIL,
            f"Dangerous role memberships found: {granted}",
            "Revoke dangerous grants: REVOKE <role> FROM <user>;",
            str(granted), cis_ref="CIS 4.2"
        )
    return CheckResult(
        "3.5", "No unsafe server-file/program role grants",
        1, "Privilege Management", PASS,
        "No roles have been granted pg_read/write_server_files or pg_execute_server_program.",
        "", cis_ref="CIS 4.2"
    )


def check_3_6(cur, args) -> CheckResult:
    """3.6 – Audit roles granted to application users."""
    try:
        cur.execute("""
            SELECT grantee, privilege_type, table_schema, table_name
            FROM information_schema.role_table_grants
            WHERE grantee NOT IN (
                SELECT rolname FROM pg_roles WHERE rolsuper = true
            )
            AND privilege_type IN ('DELETE', 'TRUNCATE', 'UPDATE')
            AND table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
            ORDER BY grantee, table_schema, table_name
            LIMIT 20
        """)
        rows = [
            {"grantee": r[0], "privilege_type": r[1], "table_schema": r[2], "table_name": r[3]}
            for r in cur.fetchall()
        ]
    except Exception:
        rows = []

    if rows:
        detail = f"Found {len(rows)} table-level DELETE/TRUNCATE/UPDATE grants on non-superuser roles. First entries: {rows[:5]}"
        return CheckResult(
            "3.6", "Review high-privilege table grants to application roles",
            2, "Privilege Management", WARN, detail,
            "Audit and revoke overly broad table grants. Use role-based access with minimal privilege.",
            str(len(rows)), cis_ref="CIS 4.4"
        )
    return CheckResult(
        "3.6", "Review high-privilege table grants to application roles",
        2, "Privilege Management", PASS,
        "No excessive DELETE/TRUNCATE/UPDATE grants found on non-superuser roles.",
        "", cis_ref="CIS 4.4"
    )


def check_3_7(cur, args) -> CheckResult:
    """3.7 – Functions with SECURITY DEFINER should be reviewed (CIS 4.3)."""
    try:
        cur.execute("""
            SELECT n.nspname AS schema, p.proname AS function,
                   pg_get_userbyid(p.proowner) AS owner
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE p.prosecdef = true
              AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
            ORDER BY schema, function
        """)
        rows = [(r[0], r[1], r[2]) for r in cur.fetchall()]
    except Exception:
        rows = []

    ev = _rows_ev(args, [f"{r[0]}.{r[1]} (owner: {r[2]})" for r in rows], "SECURITY DEFINER functions")
    if rows:
        funcs = [f"{r[0]}.{r[1]}" for r in rows]
        return CheckResult(
            "3.7", "SECURITY DEFINER functions reviewed",
            2, "Privilege Management", WARN,
            f"{len(rows)} SECURITY DEFINER function(s) found: {funcs[:10]}{'...' if len(funcs) > 10 else ''}",
            "Review each SECURITY DEFINER function. Remove if not required or ensure it cannot be exploited "
            "via search_path: SET search_path = pg_catalog in the function body.",
            str(len(rows)), evidence=ev, cis_ref="CIS 4.3"
        )
    return CheckResult(
        "3.7", "SECURITY DEFINER functions reviewed",
        2, "Privilege Management", PASS,
        "No non-system SECURITY DEFINER functions found.",
        "", evidence=ev, cis_ref="CIS 4.3"
    )


# ─── Section 4: Connection & TLS Security ────────────────────────────────────────

def check_4_1(cur, args) -> CheckResult:
    """4.1 – SSL must be enabled."""
    val, ev = _guc_ev(cur, "ssl", args)
    if val is None:
        # Try tserver conf
        conf_val = yb_gflag_from_conf(args.tserver_conf, "use_client_to_server_encryption", args)
        if conf_val is not None:
            status = PASS if conf_val.lower() == "true" else FAIL
            return CheckResult(
                "4.1", "TLS/SSL enabled for client connections",
                1, "Connection Security", status,
                f"--use_client_to_server_encryption={conf_val} (from tserver conf)",
                "Set --use_client_to_server_encryption=true in tserver configuration.",
                conf_val, evidence=ev, cis_ref="CIS 7.8"
            )
        return CheckResult(
            "4.1", "TLS/SSL enabled for client connections",
            1, "Connection Security", MANUAL,
            "Could not determine SSL status via GUC or tserver conf.",
            "Set --use_client_to_server_encryption=true in YugabyteDB tserver flags.",
            evidence=ev, cis_ref="CIS 7.8"
        )

    status = PASS if val == "on" else FAIL
    detail = f"ssl = '{val}' (from pg_settings)"
    return CheckResult(
        "4.1", "TLS/SSL enabled for client connections",
        1, "Connection Security", status, detail,
        "Enable TLS: set --use_client_to_server_encryption=true and provide ssl_cert_file/ssl_key_file.",
        val, evidence=ev, cis_ref="CIS 7.8"
    )


def check_4_2(cur, args) -> CheckResult:
    """4.2 – Minimum TLS version should be TLS 1.2 or higher."""
    val, ev = _guc_ev(cur, "ssl_min_protocol_version", args)
    if val is None:
        return CheckResult(
            "4.2", "Minimum TLS version is 1.2+",
            1, "Connection Security", MANUAL,
            "Could not read ssl_min_protocol_version GUC.",
            "Set ssl_min_protocol_version = 'TLSv1.2' in ysql_pg_conf_csv.", evidence=ev,
            cis_ref="CIS 7.8"
        )
    acceptable = {"TLSv1.2", "TLSv1.3"}
    status = PASS if val in acceptable else FAIL
    detail = f"ssl_min_protocol_version = '{val}'"
    return CheckResult(
        "4.2", "Minimum TLS version is 1.2+",
        1, "Connection Security", status, detail,
        "Set ssl_min_protocol_version='TLSv1.2' via --ysql_pg_conf_csv flag.",
        val, evidence=ev, cis_ref="CIS 7.8"
    )


def check_4_3(cur, args) -> CheckResult:
    """4.3 – SSL certificate and key files must be configured."""
    cert, ev1 = _guc_ev(cur, "ssl_cert_file", args)
    key, ev2  = _guc_ev(cur, "ssl_key_file", args)
    ev = "\n---\n".join(filter(None, [ev1, ev2]))
    missing = []
    if not cert:
        missing.append("ssl_cert_file")
    if not key:
        missing.append("ssl_key_file")

    if missing:
        return CheckResult(
            "4.3", "SSL cert and key files configured",
            1, "Connection Security", FAIL,
            f"Missing SSL configuration: {missing}",
            "Provide --cert_node_filename and --key_node_filename flags for TLS.",
            str(missing), evidence=ev, cis_ref="CIS 7.8"
        )
    return CheckResult(
        "4.3", "SSL cert and key files configured",
        1, "Connection Security", PASS,
        f"ssl_cert_file='{cert}', ssl_key_file='{key}'",
        "", evidence=ev, cis_ref="CIS 7.8"
    )


def check_4_4(cur, args) -> CheckResult:
    """4.4 – listen_addresses should not be set to '*' without justification."""
    val, ev = _guc_ev(cur, "listen_addresses", args)
    if val is None:
        return CheckResult(
            "4.4", "listen_addresses not unrestricted",
            2, "Connection Security", MANUAL,
            "Could not read listen_addresses.",
            "Restrict listen_addresses to specific interfaces rather than '*'.", evidence=ev,
            cis_ref="CIS 7.2"
        )
    if val == "*":
        return CheckResult(
            "4.4", "listen_addresses not unrestricted",
            2, "Connection Security", WARN,
            f"listen_addresses = '*' — binds to all interfaces.",
            "Restrict to specific IP: set listen_addresses='127.0.0.1,<internal_ip>' via ysql_pg_conf_csv.",
            val, evidence=ev, cis_ref="CIS 7.2"
        )
    return CheckResult(
        "4.4", "listen_addresses not unrestricted",
        2, "Connection Security", PASS,
        f"listen_addresses = '{val}'",
        "", val, evidence=ev, cis_ref="CIS 7.2"
    )


def check_4_5(cur, args) -> CheckResult:
    """4.5 – Node-to-node encryption flag check (via conf file)."""
    conf_val = yb_gflag_from_conf(args.tserver_conf, "use_node_to_node_encryption", args)
    if conf_val is None:
        conf_val = yb_gflag_from_conf(args.master_conf, "use_node_to_node_encryption", args)

    if conf_val is None:
        # If at least one conf file was given but the flag is absent, the default is false → FAIL.
        if args.tserver_conf or args.master_conf:
            return CheckResult(
                "4.5", "Node-to-node encryption enabled",
                2, "Connection Security", FAIL,
                "--use_node_to_node_encryption not set in conf — disabled by default.",
                "Add --use_node_to_node_encryption=true to both master and tserver conf files.",
                "false (default)", cis_ref="CIS 7.7"
            )
        return CheckResult(
            "4.5", "Node-to-node encryption enabled",
            2, "Connection Security", MANUAL,
            "Provide --tserver-conf or --master-conf to check this flag.",
            "Set --use_node_to_node_encryption=true in master and tserver flags.",
            cis_ref="CIS 7.7"
        )
    status = PASS if conf_val.lower() == "true" else FAIL
    return CheckResult(
        "4.5", "Node-to-node encryption enabled",
        2, "Connection Security", status,
        f"--use_node_to_node_encryption={conf_val}",
        "Set --use_node_to_node_encryption=true in both master and tserver configuration.",
        conf_val, cis_ref="CIS 7.7"
    )


def check_4_6(cur, args) -> CheckResult:
    """4.6 – YSQL authentication flag should be enabled."""
    conf_val = yb_gflag_from_conf(args.tserver_conf, "ysql_enable_auth", args)
    if conf_val is not None:
        status = PASS if conf_val.lower() == "true" else FAIL
        return CheckResult(
            "4.6", "--ysql_enable_auth flag enabled",
            1, "Connection Security", status,
            f"--ysql_enable_auth={conf_val} (from tserver conf)",
            "Add --ysql_enable_auth=true to yb-tserver startup flags.",
            conf_val, cis_ref="CIS 6.1"
        )

    # Flag absent from conf — try pg_hba_file_rules as a proxy
    try:
        cur.execute("SELECT count(*) FROM pg_hba_file_rules WHERE auth_method = 'trust'")
        trust_count = cur.fetchone()[0]
        if trust_count == 0:
            return CheckResult(
                "4.6", "--ysql_enable_auth flag enabled",
                1, "Connection Security", PASS,
                "No 'trust' HBA rules found; authentication is effectively enforced.",
                "", cis_ref="CIS 6.1"
            )
    except Exception:
        pass

    # Conf provided but flag not found → not explicitly enabled → FAIL
    if args.tserver_conf:
        conf_path = os.path.expanduser(os.path.expandvars(args.tserver_conf.strip()))
        if not os.path.isfile(conf_path):
            detail = f"tserver conf not accessible: {conf_path}"
        else:
            detail = f"--ysql_enable_auth not found in {conf_path} — authentication may not be enforced."
        return CheckResult(
            "4.6", "--ysql_enable_auth flag enabled",
            1, "Connection Security", FAIL,
            detail,
            "Add --ysql_enable_auth=true to yb-tserver startup flags.",
            cis_ref="CIS 6.1"
        )
    # No conf at all
    return CheckResult(
        "4.6", "--ysql_enable_auth flag enabled",
        1, "Connection Security", MANUAL,
        "Pass --tserver-conf to verify --ysql_enable_auth is set.",
        "Add --ysql_enable_auth=true to yb-tserver startup flags.",
        cis_ref="CIS 6.1"
    )


# ─── Section 5: Logging & Auditing ───────────────────────────────────────────────

def check_5_1(cur, args) -> CheckResult:
    """5.1 – log_connections must be on."""
    val, ev = _guc_ev(cur, "log_connections", args)
    status = PASS if val == "on" else FAIL
    detail = f"log_connections = '{val}'"
    return CheckResult(
        "5.1", "log_connections enabled",
        1, "Logging & Auditing", status, detail,
        "Add 'log_connections=on' to --ysql_pg_conf_csv flag.",
        val or "", evidence=ev, cis_ref="CIS 3.1.18"
    )


def check_5_2(cur, args) -> CheckResult:
    """5.2 – log_disconnections must be on."""
    val, ev = _guc_ev(cur, "log_disconnections", args)
    status = PASS if val == "on" else FAIL
    detail = f"log_disconnections = '{val}'"
    return CheckResult(
        "5.2", "log_disconnections enabled",
        1, "Logging & Auditing", status, detail,
        "Add 'log_disconnections=on' to --ysql_pg_conf_csv flag.",
        val or "", evidence=ev, cis_ref="CIS 3.1.19"
    )


def check_5_3(cur, args) -> CheckResult:
    """5.3 – log_line_prefix should include timestamp, user, db, and client."""
    val, ev = _guc_ev(cur, "log_line_prefix", args)
    # Recommended components: %t (timestamp), %u (user), %d (db), %r (remote)
    required = ["%t", "%u", "%d"]
    missing = [c for c in required if c not in (val or "")]
    if missing:
        return CheckResult(
            "5.3", "log_line_prefix includes required fields",
            1, "Logging & Auditing", WARN,
            f"log_line_prefix='{val}' — missing components: {missing}",
            "Set log_line_prefix='%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h ' via ysql_pg_conf_csv.",
            val or "", evidence=ev, cis_ref="CIS 3.1.22"
        )
    return CheckResult(
        "5.3", "log_line_prefix includes required fields",
        1, "Logging & Auditing", PASS,
        f"log_line_prefix='{val}'",
        "",
        val or "", evidence=ev, cis_ref="CIS 3.1.22"
    )


def check_5_4(cur, args) -> CheckResult:
    """5.4 – log_statement should capture DDL at minimum."""
    val, ev = _guc_ev(cur, "log_statement", args)
    acceptable = {"ddl", "mod", "all"}
    status = PASS if val in acceptable else WARN
    detail = f"log_statement = '{val}'"
    return CheckResult(
        "5.4", "log_statement captures DDL",
        1, "Logging & Auditing", status, detail,
        "Set log_statement='ddl' (minimum) or 'all' in ysql_pg_conf_csv.",
        val or "", evidence=ev, cis_ref="CIS 3.1.23"
    )


def check_5_5(cur, args) -> CheckResult:
    """5.5 – pgaudit extension must be loaded for audit logging."""
    val, ev = _guc_ev(cur, "shared_preload_libraries", args)
    audit_log, ev2 = _guc_ev(cur, "pgaudit.log", args)
    ev_combined = "\n---\n".join(filter(None, [ev, ev2]))
    has_pgaudit = "pgaudit" in (val or "")
    if not has_pgaudit:
        return CheckResult(
            "5.5", "pgaudit loaded for audit logging",
            1, "Logging & Auditing", FAIL,
            f"shared_preload_libraries='{val}' — pgaudit not found.",
            "Add 'pgaudit' to --ysql_pg_conf_csv shared_preload_libraries and restart.",
            val or "", evidence=ev_combined, cis_ref="CIS 3.2"
        )
    # Also check if pgaudit.log is set
    if not audit_log or audit_log == "none":
        return CheckResult(
            "5.5", "pgaudit loaded for audit logging",
            1, "Logging & Auditing", WARN,
            f"pgaudit is loaded but pgaudit.log='{audit_log}' — no audit events configured.",
            "Set pgaudit.log='ddl,role,misc_set' in ysql_pg_conf_csv.",
            audit_log or "none", evidence=ev_combined, cis_ref="CIS 3.2"
        )
    return CheckResult(
        "5.5", "pgaudit loaded for audit logging",
        1, "Logging & Auditing", PASS,
        f"pgaudit loaded, pgaudit.log='{audit_log}'",
        "",
        audit_log or "", evidence=ev_combined, cis_ref="CIS 3.2"
    )


def check_5_6(cur, args) -> CheckResult:
    """5.6 – log_duration or log_min_duration_statement should be configured."""
    dur_stmt, ev1 = _guc_ev(cur, "log_min_duration_statement", args)
    duration, ev2  = _guc_ev(cur, "log_duration", args)
    ev = "\n---\n".join(filter(None, [ev1, ev2]))
    # -1 means disabled for log_min_duration_statement
    dur_ok = dur_stmt is not None and dur_stmt != "-1"
    drn_ok = duration == "on"
    if not dur_ok and not drn_ok:
        return CheckResult(
            "5.6", "Slow query / duration logging configured",
            2, "Logging & Auditing", WARN,
            f"log_min_duration_statement='{dur_stmt}', log_duration='{duration}' — neither enabled.",
            "Set log_min_duration_statement=1000 (1 second) in ysql_pg_conf_csv.",
            dur_stmt or "", evidence=ev, cis_ref="CIS 7.2"
        )
    return CheckResult(
        "5.6", "Slow query / duration logging configured",
        2, "Logging & Auditing", PASS,
        f"log_min_duration_statement='{dur_stmt}', log_duration='{duration}'",
        "", evidence=ev, cis_ref="CIS 7.2"
    )


def check_5_7(cur, args) -> CheckResult:
    """5.7 – log_timezone should be UTC."""
    val, ev = _guc_ev(cur, "log_timezone", args)
    if val and val.upper() != "UTC":
        return CheckResult(
            "5.7", "log_timezone set to UTC",
            2, "Logging & Auditing", WARN,
            f"log_timezone = '{val}'. UTC is recommended for consistent cross-node log correlation.",
            "Set log_timezone='UTC' in ysql_pg_conf_csv.",
            val, evidence=ev, cis_ref="CIS 3.1.24"
        )
    return CheckResult(
        "5.7", "log_timezone set to UTC",
        2, "Logging & Auditing", PASS,
        f"log_timezone = '{val or 'UTC (default)'}'",
        "", evidence=ev, cis_ref="CIS 3.1.24"
    )


def check_5_8(cur, args) -> CheckResult:
    """5.8 – CIS 3.1.2: log_destination should include stderr or csvlog."""
    val, ev = _guc_ev(cur, "log_destination", args)
    acceptable = {"stderr", "csvlog", "jsonlog"}
    current = {v.strip() for v in (val or "").split(",")}
    if not current & acceptable:
        return CheckResult(
            "5.8", "log_destination includes stderr or csvlog",
            1, "Logging & Auditing", WARN,
            f"log_destination='{val}' — none of stderr/csvlog/jsonlog configured.",
            "Set log_destination='stderr' or 'csvlog' in ysql_pg_conf_csv.",
            val or "", evidence=ev, cis_ref="CIS 3.1.2"
        )
    return CheckResult(
        "5.8", "log_destination includes stderr or csvlog",
        1, "Logging & Auditing", PASS,
        f"log_destination='{val}'",
        "", val or "", evidence=ev, cis_ref="CIS 3.1.2"
    )


def check_5_9(cur, args) -> CheckResult:
    """5.9 – CIS 3.1.3: log_filename should be set to a pattern."""
    val, ev = _guc_ev(cur, "log_filename", args)
    if not val or val == "postgresql-%Y-%m-%d_%H%M%S.log":
        # Default is acceptable
        status = PASS
        detail = f"log_filename='{val or 'default'}'"
    elif val:
        status = PASS
        detail = f"log_filename='{val}'"
    else:
        status = WARN
        detail = "log_filename not set."
    return CheckResult(
        "5.9", "log_filename pattern configured",
        1, "Logging & Auditing", status, detail,
        "Set log_filename='yugabyte-%Y-%m-%d_%H%M%S.log' in ysql_pg_conf_csv.",
        val or "", evidence=ev, cis_ref="CIS 3.1.3"
    )


def check_5_10(cur, args) -> CheckResult:
    """5.10 – CIS 3.1.4: log_file_mode should be 0600 or 0640."""
    val, ev = _guc_ev(cur, "log_file_mode", args)
    # pg_settings returns log_file_mode as an octal string starting with '0'
    # (e.g. '0600'). Some builds return the decimal equivalent (384). Detect
    # by leading zero: '0600' → base-8, '384' → base-10.
    try:
        if val and val.startswith('0'):
            mode_int = int(val, 8)    # '0600' → 384, '0640' → 416
        else:
            mode_int = int(val or "-1")  # '384' → 384, '416' → 416
    except (ValueError, TypeError):
        mode_int = -1
    is_ok = mode_int in (0o600, 0o640)   # 384 or 416
    status = PASS if is_ok else WARN
    detail = f"log_file_mode='{val}'"
    return CheckResult(
        "5.10", "log_file_mode is 0600 or 0640",
        1, "Logging & Auditing", status, detail,
        "Set log_file_mode=0600 in ysql_pg_conf_csv to restrict log file access.",
        val or "", evidence=ev, cis_ref="CIS 3.1.4"
    )


def check_5_11(cur, args) -> CheckResult:
    """5.11 – CIS 3.1.5: log_truncate_on_rotation should be on."""
    val, ev = _guc_ev(cur, "log_truncate_on_rotation", args)
    status = PASS if val == "on" else WARN
    detail = f"log_truncate_on_rotation='{val}'"
    return CheckResult(
        "5.11", "log_truncate_on_rotation enabled",
        1, "Logging & Auditing", status, detail,
        "Set log_truncate_on_rotation=on in ysql_pg_conf_csv.",
        val or "", evidence=ev, cis_ref="CIS 3.1.5"
    )


def check_5_12(cur, args) -> CheckResult:
    """5.12 – CIS 3.1.6: log_rotation_age should be set (e.g. 1d)."""
    val, ev = _guc_ev(cur, "log_rotation_age", args)
    # 0 = disabled; any non-zero value is ok
    try:
        ok = val is not None and int(val) > 0
    except (ValueError, TypeError):
        ok = bool(val)
    status = PASS if ok else WARN
    detail = f"log_rotation_age='{val}'" + ("" if ok else " (0 = rotation disabled)")
    return CheckResult(
        "5.12", "log_rotation_age configured",
        1, "Logging & Auditing", status, detail,
        "Set log_rotation_age='1d' in ysql_pg_conf_csv to rotate logs daily.",
        val or "", evidence=ev, cis_ref="CIS 3.1.6"
    )


def check_5_13(cur, args) -> CheckResult:
    """5.13 – CIS 3.1.7: log_rotation_size should be set."""
    val, ev = _guc_ev(cur, "log_rotation_size", args)
    try:
        ok = val is not None and int(val) > 0
    except (ValueError, TypeError):
        ok = bool(val)
    status = PASS if ok else WARN
    detail = f"log_rotation_size='{val}'" + ("" if ok else " (0 = size-based rotation disabled)")
    return CheckResult(
        "5.13", "log_rotation_size configured",
        2, "Logging & Auditing", status, detail,
        "Set log_rotation_size='100MB' in ysql_pg_conf_csv.",
        val or "", evidence=ev, cis_ref="CIS 3.1.7"
    )


def check_5_14(cur, args) -> CheckResult:
    """5.14 – CIS 3.1.12: log_min_messages should be WARNING or stricter."""
    val, ev = _guc_ev(cur, "log_min_messages", args)
    # Ordered: DEBUG5 > DEBUG4 > DEBUG3 > DEBUG2 > DEBUG1 > INFO > NOTICE > WARNING > ERROR > LOG > FATAL > PANIC
    # WARNING or above is recommended
    too_verbose = {"debug5", "debug4", "debug3", "debug2", "debug1", "info", "notice"}
    status = WARN if (val or "").lower() in too_verbose else PASS
    detail = f"log_min_messages='{val}'"
    return CheckResult(
        "5.14", "log_min_messages is WARNING or stricter",
        1, "Logging & Auditing", status, detail,
        "Set log_min_messages=WARNING in ysql_pg_conf_csv. More verbose levels generate excessive log noise.",
        val or "", evidence=ev, cis_ref="CIS 3.1.12"
    )


def check_5_15(cur, args) -> CheckResult:
    """5.15 – CIS 3.1.13: log_min_error_statement should be ERROR or stricter."""
    val, ev = _guc_ev(cur, "log_min_error_statement", args)
    too_verbose = {"debug5", "debug4", "debug3", "debug2", "debug1", "info", "notice", "warning", "log"}
    status = WARN if (val or "").lower() in too_verbose else PASS
    detail = f"log_min_error_statement='{val}'"
    return CheckResult(
        "5.15", "log_min_error_statement is ERROR or stricter",
        1, "Logging & Auditing", status, detail,
        "Set log_min_error_statement=ERROR in ysql_pg_conf_csv.",
        val or "", evidence=ev, cis_ref="CIS 3.1.13"
    )


def check_5_16(cur, args) -> CheckResult:
    """5.16 – CIS 3.1.14-16: debug_print_parse/rewritten/plan must be off."""
    params = ["debug_print_parse", "debug_print_rewritten", "debug_print_plan"]
    enabled = []
    ev_parts = []
    for p in params:
        val, ev = _guc_ev(cur, p, args)
        if ev:
            ev_parts.append(ev)
        if val == "on":
            enabled.append(p)
    ev_combined = "\n---\n".join(ev_parts)
    if enabled:
        return CheckResult(
            "5.16", "debug_print_* options disabled",
            1, "Logging & Auditing", FAIL,
            f"Debug print options enabled (expose query internals): {enabled}",
            "Set debug_print_parse=off, debug_print_rewritten=off, debug_print_plan=off in ysql_pg_conf_csv.",
            str(enabled), evidence=ev_combined, cis_ref="CIS 3.1.14-16"
        )
    return CheckResult(
        "5.16", "debug_print_* options disabled",
        1, "Logging & Auditing", PASS,
        "debug_print_parse, debug_print_rewritten, debug_print_plan are all off.",
        "", evidence=ev_combined, cis_ref="CIS 3.1.14-16"
    )


def check_5_17(cur, args) -> CheckResult:
    """5.17 – CIS 3.1.17: debug_pretty_print should be on."""
    val, ev = _guc_ev(cur, "debug_pretty_print", args)
    status = PASS if val == "on" else WARN
    detail = f"debug_pretty_print='{val}'"
    return CheckResult(
        "5.17", "debug_pretty_print enabled",
        1, "Logging & Auditing", status, detail,
        "Set debug_pretty_print=on in ysql_pg_conf_csv for readable debug output.",
        val or "", evidence=ev, cis_ref="CIS 3.1.17"
    )


def check_5_18(cur, args) -> CheckResult:
    """5.18 – CIS 3.1.20: log_error_verbosity should be DEFAULT or VERBOSE."""
    val, ev = _guc_ev(cur, "log_error_verbosity", args)
    # TERSE hides useful info; DEFAULT or VERBOSE is recommended
    status = WARN if (val or "").lower() == "terse" else PASS
    detail = f"log_error_verbosity='{val}'"
    return CheckResult(
        "5.18", "log_error_verbosity is DEFAULT or VERBOSE",
        1, "Logging & Auditing", status, detail,
        "Set log_error_verbosity=DEFAULT in ysql_pg_conf_csv.",
        val or "", evidence=ev, cis_ref="CIS 3.1.20"
    )


def check_5_19(cur, args) -> CheckResult:
    """5.19 – CIS 3.1.21: log_hostname should be off (reduces DNS lookup overhead)."""
    val, ev = _guc_ev(cur, "log_hostname", args)
    # CIS recommends 'off' to avoid DNS lookups that can slow logging
    status = WARN if val == "on" else PASS
    detail = f"log_hostname='{val}'"
    return CheckResult(
        "5.19", "log_hostname is off",
        2, "Logging & Auditing", status, detail,
        "Set log_hostname=off in ysql_pg_conf_csv to prevent DNS lookup overhead during logging.",
        val or "", evidence=ev, cis_ref="CIS 3.1.21"
    )


# ─── Section 6: Configuration Hardening ──────────────────────────────────────────

def check_6_1(cur, args) -> CheckResult:
    """6.1 – statement_timeout should be set to limit runaway queries."""
    val, ev = _guc_ev(cur, "statement_timeout", args)
    # 0 = disabled
    if val == "0" or val is None:
        return CheckResult(
            "6.1", "statement_timeout configured",
            2, "Configuration Hardening", WARN,
            f"statement_timeout = '{val}' (unlimited). Long-running queries are unconstrained.",
            "Set statement_timeout to an appropriate value, e.g. '30min' in ysql_pg_conf_csv.",
            val or "0", evidence=ev, cis_ref="CIS 7.2"
        )
    return CheckResult(
        "6.1", "statement_timeout configured",
        2, "Configuration Hardening", PASS,
        f"statement_timeout = '{val}'",
        "",
        val, evidence=ev, cis_ref="CIS 7.2"
    )


def check_6_2(cur, args) -> CheckResult:
    """6.2 – idle_in_transaction_session_timeout should be set."""
    val, ev = _guc_ev(cur, "idle_in_transaction_session_timeout", args)
    if val == "0" or val is None:
        return CheckResult(
            "6.2", "idle_in_transaction_session_timeout configured",
            2, "Configuration Hardening", WARN,
            f"idle_in_transaction_session_timeout = '{val}' (unlimited). Stale transactions can hold locks.",
            "Set idle_in_transaction_session_timeout='5min' in ysql_pg_conf_csv.",
            val or "0", evidence=ev, cis_ref="CIS 7.2"
        )
    return CheckResult(
        "6.2", "idle_in_transaction_session_timeout configured",
        2, "Configuration Hardening", PASS,
        f"idle_in_transaction_session_timeout = '{val}'",
        "",
        val, evidence=ev, cis_ref="CIS 7.2"
    )


def check_6_3(cur, args) -> CheckResult:
    """6.3 – track_activities must be on to observe sessions."""
    val, ev = _guc_ev(cur, "track_activities", args)
    status = PASS if val == "on" else FAIL
    detail = f"track_activities = '{val}'"
    return CheckResult(
        "6.3", "track_activities enabled",
        1, "Configuration Hardening", status, detail,
        "Set track_activities=on in ysql_pg_conf_csv.",
        val or "", evidence=ev, cis_ref="CIS 7.2"
    )


def check_6_4(cur, args) -> CheckResult:
    """6.4 – track_counts should be on for table statistics."""
    val, ev = _guc_ev(cur, "track_counts", args)
    status = PASS if val == "on" else WARN
    detail = f"track_counts = '{val}'"
    return CheckResult(
        "6.4", "track_counts enabled",
        1, "Configuration Hardening", status, detail,
        "Set track_counts=on in ysql_pg_conf_csv.",
        val or "", evidence=ev, cis_ref="CIS 7.2"
    )


def check_6_5(cur, args) -> CheckResult:
    """6.5 – Ensure ysql_enable_pg_perm_extensions flag is reviewed (allows permissive security)."""
    conf_val = yb_gflag_from_conf(args.tserver_conf, "ysql_enable_pg_perm_extensions", args)
    if conf_val is None:
        return CheckResult(
            "6.5", "ysql_enable_pg_perm_extensions not enabled",
            2, "Configuration Hardening", PASS,
            "Flag --ysql_enable_pg_perm_extensions not found in tserver conf (default off = secure).",
            "", cis_ref="CIS 7.2"
        )
    status = FAIL if conf_val.lower() == "true" else PASS
    detail = f"--ysql_enable_pg_perm_extensions={conf_val}"
    return CheckResult(
        "6.5", "ysql_enable_pg_perm_extensions not enabled",
        2, "Configuration Hardening", status, detail,
        "Remove --ysql_enable_pg_perm_extensions=true unless explicitly required.",
        conf_val, cis_ref="CIS 7.2"
    )


def check_6_6(cur, args) -> CheckResult:
    """6.6 – Ensure no dangerous extensions are installed."""
    dangerous_exts = {"adminpack", "file_fdw", "dblink", "postgres_fdw"}
    try:
        cur.execute("SELECT extname FROM pg_extension ORDER BY extname")
        installed = {r[0] for r in cur.fetchall()}
    except Exception:
        installed = set()

    found = installed & dangerous_exts
    ev = _rows_ev(args, sorted(installed), "installed extensions")
    if found:
        return CheckResult(
            "6.6", "No potentially dangerous extensions installed",
            2, "Configuration Hardening", WARN,
            f"Potentially risky extension(s) installed: {sorted(found)}. Verify these are required.",
            "Drop unused extensions: DROP EXTENSION <name>;",
            str(sorted(found)), evidence=ev, cis_ref="CIS 4.4"
        )
    return CheckResult(
        "6.6", "No potentially dangerous extensions installed",
        2, "Configuration Hardening", PASS,
        f"Installed extensions: {sorted(installed)}. None are in the high-risk list.",
        "",
        str(sorted(installed)), evidence=ev, cis_ref="CIS 4.4"
    )


def check_6_7(cur, args) -> CheckResult:
    """6.7 – max_connections should be explicitly set (not left at default)."""
    val, ev = _guc_ev(cur, "max_connections", args)
    # YugabyteDB default is 300; if it's exactly 100 that's the PG default (unusual in YB)
    detail = f"max_connections = '{val}'"
    return CheckResult(
        "6.7", "max_connections reviewed",
        2, "Configuration Hardening", INFO if val else MANUAL,
        detail,
        "Set max_connections explicitly to match expected workload capacity.",
        val or "", evidence=ev, cis_ref="CIS 7.2"
    )


# ─── Section 7: YugabyteDB-Specific ─────────────────────────────────────────────

def check_7_1(args) -> CheckResult:
    """7.1 – allow_non_tls_admin_requests should be false."""
    conf_val = yb_gflag_from_conf(args.master_conf, "allow_non_tls_admin_requests", args)
    if conf_val is None:
        conf_val = yb_gflag_from_conf(args.tserver_conf, "allow_non_tls_admin_requests", args)

    if conf_val is None:
        # Absent from conf — default is 'true' (non-TLS allowed) → insecure
        status = WARN if (args.master_conf or args.tserver_conf) else MANUAL
        detail = ("--allow_non_tls_admin_requests not set in conf — default may permit non-TLS admin requests."
                  if status == WARN else
                  "Provide --master-conf or --tserver-conf to check this flag.")
        return CheckResult(
            "7.1", "allow_non_tls_admin_requests disabled",
            1, "YugabyteDB Specific", status, detail,
            "Set --allow_non_tls_admin_requests=false in master and tserver flags.",
            cis_ref="CIS 7.2"
        )
    status = PASS if conf_val.lower() == "false" else FAIL
    detail = f"--allow_non_tls_admin_requests={conf_val}"
    return CheckResult(
        "7.1", "allow_non_tls_admin_requests disabled",
        1, "YugabyteDB Specific", status, detail,
        "Set --allow_non_tls_admin_requests=false in master and tserver flags.",
        conf_val, cis_ref="CIS 7.2"
    )


def check_7_2(args) -> CheckResult:
    """7.2 – Ensure metrics webserver is not exposed on all interfaces."""
    conf_val = yb_gflag_from_conf(args.tserver_conf, "webserver_interface", args)
    if conf_val is None:
        conf_val = yb_gflag_from_conf(args.master_conf, "webserver_interface", args)

    if conf_val is None:
        # Absent from conf — default binds to all interfaces (0.0.0.0)
        status = WARN if (args.tserver_conf or args.master_conf) else MANUAL
        detail = ("--webserver_interface not set in conf — default exposes metrics on all interfaces (0.0.0.0)."
                  if status == WARN else
                  "Provide --tserver-conf or --master-conf to check this flag.")
        return CheckResult(
            "7.2", "Metrics webserver interface restricted",
            2, "YugabyteDB Specific", status, detail,
            "Set --webserver_interface=<internal_ip> to restrict metrics endpoint.",
            cis_ref="CIS 7.2"
        )
    if conf_val in ("0.0.0.0", ""):
        return CheckResult(
            "7.2", "Metrics webserver interface restricted",
            2, "YugabyteDB Specific", WARN,
            f"--webserver_interface='{conf_val}' — metrics exposed on all interfaces.",
            "Bind metrics to internal IP: --webserver_interface=<internal_ip>",
            conf_val, cis_ref="CIS 7.2"
        )
    return CheckResult(
        "7.2", "Metrics webserver interface restricted",
        2, "YugabyteDB Specific", PASS,
        f"--webserver_interface={conf_val}",
        "",
        conf_val, cis_ref="CIS 7.2"
    )


def check_7_3(args) -> CheckResult:
    """7.3 – use_cassandra_authentication should be enabled if YCQL is used."""
    conf_val = yb_gflag_from_conf(args.tserver_conf, "use_cassandra_authentication", args)
    if conf_val is None:
        status = WARN if args.tserver_conf else MANUAL
        detail = ("--use_cassandra_authentication not found in tserver conf — YCQL auth is not explicitly enabled."
                  if status == WARN else
                  "Provide --tserver-conf to check --use_cassandra_authentication.")
        return CheckResult(
            "7.3", "YCQL authentication enabled (if YCQL used)",
            1, "YugabyteDB Specific", status, detail,
            "Set --use_cassandra_authentication=true in tserver flags if YCQL is enabled.",
            cis_ref="CIS 5.1"
        )
    status = PASS if conf_val.lower() == "true" else WARN
    detail = f"--use_cassandra_authentication={conf_val}"
    return CheckResult(
        "7.3", "YCQL authentication enabled (if YCQL used)",
        1, "YugabyteDB Specific", status, detail,
        "If YCQL API is enabled, set --use_cassandra_authentication=true.",
        conf_val, cis_ref="CIS 5.1"
    )


def check_7_4(cur, args) -> CheckResult:
    """7.4 / CIS 1.6 – YugabyteDB version should be current and supported."""
    try:
        cur.execute("SELECT version()")
        ver_str = cur.fetchone()[0]
    except Exception:
        ver_str = "unknown"

    ev = ver_str if getattr(args, "evidence", False) else ""

    # Extract the YB-X.Y.Z.W version number from version()
    m = re.search(r'YB-(\d+)\.(\d+)\.(\d+)', ver_str)
    if not m:
        return CheckResult(
            "7.4", "YugabyteDB version is current",
            1, "YugabyteDB Specific", INFO,
            f"Could not parse YugabyteDB version from: {ver_str[:120]}",
            "Verify against https://docs.yugabyte.com/preview/releases/",
            ver_str[:80], evidence=ev, cis_ref="CIS 1.6"
        )

    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    yb_version = f"{major}.{minor}.{patch}"

    # Versions before 2.14 are EOL as of 2024
    if major < 2 or (major == 2 and minor < 14):
        return CheckResult(
            "7.4", "YugabyteDB version is current",
            1, "YugabyteDB Specific", FAIL,
            f"YugabyteDB {yb_version} is end-of-life. Upgrade immediately.",
            "Upgrade to a supported long-term stable release: https://docs.yugabyte.com/preview/releases/",
            yb_version, evidence=ev, cis_ref="CIS 1.6"
        )

    # 2.14–2.18 are stable but aging; 2.20+ or 2024.x are current LTS
    if major == 2 and minor < 20:
        return CheckResult(
            "7.4", "YugabyteDB version is current",
            2, "YugabyteDB Specific", WARN,
            f"YugabyteDB {yb_version} — consider upgrading to the latest LTS (2.20+).",
            "Check https://docs.yugabyte.com/preview/releases/ for the current stable release.",
            yb_version, evidence=ev, cis_ref="CIS 1.6"
        )

    return CheckResult(
        "7.4", "YugabyteDB version is current",
        1, "YugabyteDB Specific", PASS,
        f"YugabyteDB {yb_version}",
        "", yb_version, evidence=ev, cis_ref="CIS 1.6"
    )


def check_cis5_5(args) -> CheckResult:
    """CIS 5.5 – YCQL should not listen on all interfaces (0.0.0.0)."""
    conf_val = yb_gflag_from_conf(args.tserver_conf, "cql_proxy_bind_address", args)
    if conf_val is None:
        return CheckResult(
            "cis5.5", "YCQL bind address not unrestricted",
            1, "YCQL Auth", MANUAL,
            "Could not read --cql_proxy_bind_address from tserver conf. Pass --tserver-conf.",
            "Set --cql_proxy_bind_address=<internal_ip>:9042 in tserver configuration.",
            cis_ref="CIS 5.5"
        )
    ip = conf_val.split(":")[0].strip()
    if ip in ("0.0.0.0", "[::]", "::"):
        return CheckResult(
            "cis5.5", "YCQL bind address not unrestricted",
            1, "YCQL Auth", FAIL,
            f"--cql_proxy_bind_address={conf_val} — YCQL listens on all interfaces.",
            "Restrict to a specific internal IP: --cql_proxy_bind_address=<internal_ip>:9042",
            conf_val, cis_ref="CIS 5.5"
        )
    return CheckResult(
        "cis5.5", "YCQL bind address not unrestricted",
        1, "YCQL Auth", PASS,
        f"--cql_proxy_bind_address={conf_val}",
        "", conf_val, cis_ref="CIS 5.5"
    )


def _parse_hba_trust(hba_csv: str, conn_types: set) -> List[str]:
    """Return HBA entries from a comma-separated ysql_hba_conf_csv value that match
    the given connection types AND use 'trust' auth."""
    hits = []
    for entry in hba_csv.split(","):
        entry = entry.strip()
        tokens = entry.split()
        if len(tokens) >= 4 and tokens[0].lower() in conn_types and tokens[-1].lower() == "trust":
            hits.append(entry)
    return hits


def check_cis6_1(cur, args) -> CheckResult:
    """CIS 6.1 – No 'trust' auth for local UNIX socket connections in pg_hba."""
    # Primary: read ysql_hba_conf_csv from tserver conf
    hba_csv = yb_gflag_from_conf(args.tserver_conf, "ysql_hba_conf_csv", args)
    if hba_csv is not None:
        trust = _parse_hba_trust(hba_csv, {"local"})
        ev = hba_csv if args.evidence else ""
        if trust:
            return CheckResult(
                "cis6.1", "No 'trust' auth for local socket connections",
                1, "Connection", FAIL,
                f"Local 'trust' entries in ysql_hba_conf_csv: {trust}",
                "Replace 'local trust' with 'local scram-sha-256' in --ysql_hba_conf_csv.",
                str(len(trust)), evidence=ev, cis_ref="CIS 6.1"
            )
        return CheckResult(
            "cis6.1", "No 'trust' auth for local socket connections",
            1, "Connection", PASS,
            "No local 'trust' entries found in ysql_hba_conf_csv.",
            "", evidence=ev, cis_ref="CIS 6.1"
        )
    # Fallback: pg_hba_file_rules (PostgreSQL-compatible installs)
    try:
        cur.execute(
            "SELECT address, auth_method FROM pg_hba_file_rules "
            "WHERE type = 'local' AND auth_method = 'trust'"
        )
        trust_rows = cur.fetchall()
        ev = "\n".join(str(r) for r in trust_rows) if args.evidence else ""
        if trust_rows:
            return CheckResult(
                "cis6.1", "No 'trust' auth for local socket connections",
                1, "Connection", FAIL,
                f"{len(trust_rows)} local 'trust' rule(s) found in pg_hba.",
                "Change local auth_method to 'scram-sha-256' in --ysql_hba_conf_csv.",
                str(len(trust_rows)), evidence=ev, cis_ref="CIS 6.1"
            )
        return CheckResult(
            "cis6.1", "No 'trust' auth for local socket connections",
            1, "Connection", PASS,
            "No local 'trust' entries found in pg_hba.",
            "", evidence=ev, cis_ref="CIS 6.1"
        )
    except Exception:
        pass
    return CheckResult(
        "cis6.1", "No 'trust' auth for local socket connections",
        1, "Connection", MANUAL,
        "Pass --tserver-conf to check ysql_hba_conf_csv for local 'trust' entries.",
        "Set --ysql_enable_auth=true and avoid 'local trust' in --ysql_hba_conf_csv.",
        cis_ref="CIS 6.1"
    )


def check_cis6_2(cur, args) -> CheckResult:
    """CIS 6.2 – No 'trust' auth for TCP/IP connections in pg_hba."""
    TCP_TYPES = {"host", "hostssl", "hostnossl"}
    hba_csv = yb_gflag_from_conf(args.tserver_conf, "ysql_hba_conf_csv", args)
    if hba_csv is not None:
        trust = _parse_hba_trust(hba_csv, TCP_TYPES)
        ev = hba_csv if args.evidence else ""
        if trust:
            return CheckResult(
                "cis6.2", "No 'trust' auth for TCP/IP connections",
                1, "Connection", FAIL,
                f"TCP 'trust' entries in ysql_hba_conf_csv: {trust}",
                "Replace 'host trust' entries with 'host scram-sha-256' in --ysql_hba_conf_csv.",
                str(len(trust)), evidence=ev, cis_ref="CIS 6.2"
            )
        return CheckResult(
            "cis6.2", "No 'trust' auth for TCP/IP connections",
            1, "Connection", PASS,
            "No TCP 'trust' entries found in ysql_hba_conf_csv.",
            "", evidence=ev, cis_ref="CIS 6.2"
        )
    try:
        cur.execute(
            "SELECT address, auth_method FROM pg_hba_file_rules "
            "WHERE type IN ('host', 'hostssl', 'hostnossl') AND auth_method = 'trust'"
        )
        trust_rows = cur.fetchall()
        ev = "\n".join(str(r) for r in trust_rows) if args.evidence else ""
        if trust_rows:
            return CheckResult(
                "cis6.2", "No 'trust' auth for TCP/IP connections",
                1, "Connection", FAIL,
                f"{len(trust_rows)} TCP 'trust' rule(s) found in pg_hba.",
                "Change auth_method to 'scram-sha-256' for all host entries in --ysql_hba_conf_csv.",
                str(len(trust_rows)), evidence=ev, cis_ref="CIS 6.2"
            )
        return CheckResult(
            "cis6.2", "No 'trust' auth for TCP/IP connections",
            1, "Connection", PASS,
            "No TCP 'trust' entries found in pg_hba.",
            "", evidence=ev, cis_ref="CIS 6.2"
        )
    except Exception:
        pass
    return CheckResult(
        "cis6.2", "No 'trust' auth for TCP/IP connections",
        1, "Connection", MANUAL,
        "Pass --tserver-conf to check ysql_hba_conf_csv for TCP 'trust' entries.",
        "Avoid 'host trust' in --ysql_hba_conf_csv; use 'scram-sha-256' or 'md5'.",
        cis_ref="CIS 6.2"
    )


def check_cis7_9(cur, args) -> CheckResult:
    """CIS 7.9 – pgcrypto extension reviewed."""
    try:
        cur.execute("SELECT extname, extversion FROM pg_extension WHERE extname = 'pgcrypto'")
        row = cur.fetchone()
        ev = (f"pgcrypto {'installed: v' + row[1] if row else 'not installed'}") if args.evidence else ""
    except Exception as e:
        return CheckResult(
            "cis7.9", "pgcrypto extension reviewed",
            2, "YB Settings", MANUAL,
            f"Could not query pg_extension: {e}",
            "Run: SELECT extname, extversion FROM pg_extension WHERE extname='pgcrypto';",
            cis_ref="CIS 7.9"
        )
    if row:
        return CheckResult(
            "cis7.9", "pgcrypto extension reviewed",
            2, "YB Settings", PASS,
            f"pgcrypto v{row[1]} installed — confirm it is used for approved application-layer encryption.",
            "Verify that pgcrypto functions encrypt all sensitive columns requiring at-rest protection.",
            f"v{row[1]}", evidence=ev, cis_ref="CIS 7.9"
        )
    return CheckResult(
        "cis7.9", "pgcrypto extension reviewed",
        2, "YB Settings", WARN,
        "pgcrypto extension is not installed.",
        "If column-level encryption is required: CREATE EXTENSION pgcrypto;",
        evidence=ev, cis_ref="CIS 7.9"
    )


# ─── Section 8: OS Hardening (per-node) ─────────────────────────────────────────
# These checks run locally or via SSH. Thresholds from YugabyteDB ops best practice
# and CIS YugabyteDB 2.x document recommendations.

_IS_LINUX = sys.platform.startswith("linux")

_NOFILE_MIN  = 1_048_576   # 1 M open files
_NPROC_MIN   = 12_000      # minimum thread/process limit


def _parse_proc_limit(limits_text: str, field_name: str) -> Tuple[Optional[int], Optional[int]]:
    """Parse soft/hard limits from /proc/<pid>/limits output. Returns (soft, hard) or (None, None)."""
    _UNLIMITED = 10**9
    for line in limits_text.splitlines():
        if field_name.lower() not in line.lower():
            continue
        # Format: <Name...>  <Soft Limit>  <Hard Limit>  <Units>
        # Use regex to capture the two numeric/unlimited columns before the trailing units word.
        m = re.search(r'(\d+|unlimited)\s+(\d+|unlimited)\s+\w+\s*$', line, re.IGNORECASE)
        if m:
            def _val(s: str) -> int:
                return _UNLIMITED if s.lower() == "unlimited" else int(s)
            try:
                return _val(m.group(1)), _val(m.group(2))
            except ValueError:
                pass
    return None, None


def check_8_1(host: str, args, is_local: bool = True) -> CheckResult:
    """8.1 – nofile (open files) ulimit for yb-tserver >= 1048576."""
    node = "" if is_local else host
    cmd = "cat /proc/$(pgrep -f yb-tserver | head -1)/limits 2>/dev/null"
    stdout, stderr, rc = run_cmd_on_node(host, cmd, args, is_local)
    ev = stdout if args.evidence else ""

    if not _IS_LINUX and is_local:
        return CheckResult("8.1", "nofile ulimit for yb-tserver", 1, "OS Hardening",
                           MANUAL, "Check not applicable on non-Linux host.",
                           "Ensure nofile >= 1048576 in /etc/security/limits.d/yugabyte.conf",
                           node=node, evidence=ev, cis_ref="CIS 1.7")
    if not stdout:
        return CheckResult("8.1", "nofile ulimit for yb-tserver", 1, "OS Hardening",
                           WARN, f"[{host}] Could not read process limits: {stderr or 'yb-tserver not running?'}",
                           "Add 'yugabyte soft nofile 1048576' and 'yugabyte hard nofile 1048576' to limits.d.",
                           node=node, evidence=ev, cis_ref="CIS 1.7")

    soft, hard = _parse_proc_limit(stdout, "Max open files")
    if soft is None:
        return CheckResult("8.1", "nofile ulimit for yb-tserver", 1, "OS Hardening",
                           WARN, f"[{host}] Could not parse 'Max open files' from /proc limits.",
                           "Check /etc/security/limits.d/yugabyte.conf for nofile settings.",
                           node=node, evidence=ev, cis_ref="CIS 1.7")

    val = f"soft={soft}, hard={hard}"
    if soft < _NOFILE_MIN or hard < _NOFILE_MIN:
        return CheckResult("8.1", "nofile ulimit for yb-tserver", 1, "OS Hardening", FAIL,
                           f"[{host}] Max open files: {val} (minimum: {_NOFILE_MIN:,})",
                           f"Set 'yugabyte soft nofile {_NOFILE_MIN}' and hard in /etc/security/limits.d/yugabyte.conf",
                           value=val, node=node, evidence=ev, cis_ref="CIS 1.7")
    return CheckResult("8.1", "nofile ulimit for yb-tserver", 1, "OS Hardening", PASS,
                       f"[{host}] Max open files: {val}", "", value=val, node=node, evidence=ev,
                       cis_ref="CIS 1.7")


def check_8_2(host: str, args, is_local: bool = True) -> CheckResult:
    """8.2 – nproc (max processes/threads) ulimit for yb-tserver >= 12000."""
    node = "" if is_local else host
    cmd = "cat /proc/$(pgrep -f yb-tserver | head -1)/limits 2>/dev/null"
    stdout, stderr, rc = run_cmd_on_node(host, cmd, args, is_local)
    ev = stdout if args.evidence else ""

    if not _IS_LINUX and is_local:
        return CheckResult("8.2", "nproc ulimit for yb-tserver", 1, "OS Hardening",
                           MANUAL, "Not applicable on non-Linux host.",
                           "Ensure nproc >= 12000 in /etc/security/limits.d/yugabyte.conf",
                           node=node, evidence=ev, cis_ref="CIS 1.7")
    if not stdout:
        return CheckResult("8.2", "nproc ulimit for yb-tserver", 1, "OS Hardening",
                           WARN, f"[{host}] Could not read process limits: {stderr or 'yb-tserver not running?'}",
                           "Add 'yugabyte soft nproc 12000' and hard in limits.d.",
                           node=node, evidence=ev, cis_ref="CIS 1.7")

    soft, hard = _parse_proc_limit(stdout, "Max processes")
    if soft is None:
        return CheckResult("8.2", "nproc ulimit for yb-tserver", 1, "OS Hardening",
                           WARN, f"[{host}] Could not parse 'Max processes' from /proc limits.",
                           "Check /etc/security/limits.d/yugabyte.conf for nproc settings.",
                           node=node, evidence=ev, cis_ref="CIS 1.7")

    val = f"soft={soft}, hard={hard}"
    if soft < _NPROC_MIN or hard < _NPROC_MIN:
        return CheckResult("8.2", "nproc ulimit for yb-tserver", 1, "OS Hardening", FAIL,
                           f"[{host}] Max processes: {val} (minimum: {_NPROC_MIN:,})",
                           f"Set 'yugabyte soft nproc {_NPROC_MIN}' and hard in /etc/security/limits.d/yugabyte.conf",
                           value=val, node=node, evidence=ev, cis_ref="CIS 1.7")
    return CheckResult("8.2", "nproc ulimit for yb-tserver", 1, "OS Hardening", PASS,
                       f"[{host}] Max processes: {val}", "", value=val, node=node, evidence=ev,
                       cis_ref="CIS 1.7")


def check_8_6(host: str, args, is_local: bool = True) -> CheckResult:
    """8.6 – yb-tserver systemd user service should be active."""
    node = "" if is_local else host
    # YugabyteDB uses systemd --user (not system), so run as yugabyte user
    systemctl_cmd = "XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user is-active yb-tserver 2>&1"
    stdout, stderr, rc = run_cmd_as_yugabyte_on_node(host, systemctl_cmd, args, is_local)
    ev = stdout if args.evidence else ""

    if rc == 127 or "not found" in (stdout + stderr).lower():
        # systemctl not available or not a systemd system — fall back to process check
        proc_stdout, _, proc_rc = run_cmd_on_node(
            host, "pgrep -c -f yb-tserver 2>/dev/null", args, is_local
        )
        if proc_rc == 0 and proc_stdout.strip().isdigit() and int(proc_stdout.strip()) > 0:
            return CheckResult("8.6", "yb-tserver service active", 1, "OS Hardening", PASS,
                               f"[{host}] yb-tserver process running (systemctl --user not available).",
                               "", node=node, evidence=ev, cis_ref="CIS 1.2")
        return CheckResult("8.6", "yb-tserver service active", 1, "OS Hardening", WARN,
                           f"[{host}] systemctl --user not available and yb-tserver process not detected.",
                           "Enable yb-tserver as a systemd user service for the yugabyte user.",
                           node=node, evidence=ev, cis_ref="CIS 1.2")

    active = stdout.strip().lower() == "active"
    status = PASS if active else FAIL
    detail = f"[{host}] systemctl --user yb-tserver: {stdout.strip() or 'unknown'}"
    return CheckResult("8.6", "yb-tserver service active", 1, "OS Hardening", status, detail,
                       "Enable and start: systemctl --user enable --now yb-tserver (as yugabyte)",
                       value=stdout.strip(), node=node, evidence=ev, cis_ref="CIS 1.2")


def check_8_7(host: str, args, is_local: bool = True) -> CheckResult:
    """8.7 – yb-master systemd user service active (on master-eligible nodes)."""
    node = "" if is_local else host
    # First check if yb-master process is running at all
    proc_stdout, _, proc_rc = run_cmd_on_node(
        host, "pgrep -c -f yb-master 2>/dev/null", args, is_local
    )
    if proc_rc != 0 or not proc_stdout.strip().isdigit() or int(proc_stdout.strip()) == 0:
        return CheckResult("8.7", "yb-master service active (if applicable)", 1, "OS Hardening",
                           NA, f"[{host}] yb-master not running — not a master node, skipping.",
                           "", node=node, cis_ref="CIS 1.2")

    systemctl_cmd = "XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user is-active yb-master 2>&1"
    stdout, stderr, rc = run_cmd_as_yugabyte_on_node(host, systemctl_cmd, args, is_local)
    ev = stdout if args.evidence else ""

    if rc == 127 or "not found" in (stdout + stderr).lower():
        return CheckResult("8.7", "yb-master service active (if applicable)", 1, "OS Hardening", PASS,
                           f"[{host}] yb-master process running (systemctl --user not available).",
                           "", node=node, evidence=ev, cis_ref="CIS 1.2")

    active = stdout.strip().lower() == "active"
    status = PASS if active else FAIL
    detail = f"[{host}] systemctl --user yb-master: {stdout.strip() or 'unknown'}"
    return CheckResult("8.7", "yb-master service active (if applicable)", 1, "OS Hardening", status, detail,
                       "Enable and start: systemctl --user enable --now yb-master (as yugabyte)",
                       value=stdout.strip(), node=node, evidence=ev, cis_ref="CIS 1.2")


def check_cis1_4(host: str, args, is_local: bool = True) -> CheckResult:
    """CIS 1.4 – Dedicated 'yugabyte' OS user and group must exist."""
    node = "" if is_local else host
    u_out, _, u_rc = run_cmd_on_node(host, "getent passwd yugabyte 2>/dev/null", args, is_local)
    g_out, _, g_rc = run_cmd_on_node(host, "getent group  yugabyte 2>/dev/null", args, is_local)
    ev = f"passwd: {u_out}\ngroup:  {g_out}" if getattr(args, "evidence", False) else ""
    issues = []
    if not u_out:
        issues.append("'yugabyte' OS user not found")
    if not g_out:
        issues.append("'yugabyte' OS group not found")
    if issues:
        return CheckResult(
            "cis1.4", "Dedicated yugabyte OS user/group exists",
            1, "Installation", FAIL,
            f"[{host}] {'; '.join(issues)}",
            "Create: useradd -r -m -g yugabyte -s /bin/bash yugabyte",
            node=node, evidence=ev, cis_ref="CIS 1.4"
        )
    return CheckResult(
        "cis1.4", "Dedicated yugabyte OS user/group exists",
        1, "Installation", PASS,
        f"[{host}] yugabyte user and group both exist.",
        "", node=node, evidence=ev, cis_ref="CIS 1.4"
    )


def check_cis1_5(host: str, args, is_local: bool = True) -> CheckResult:
    """CIS 1.5 – Python 3.6+ must be installed (required by YugabyteDB tooling)."""
    node = "" if is_local else host
    out, _, rc = run_cmd_on_node(host, "python3 --version 2>&1", args, is_local)
    ev = out if getattr(args, "evidence", False) else ""
    if rc != 0 or not out:
        return CheckResult(
            "cis1.5", "Python 3.6+ installed",
            1, "Installation", FAIL,
            f"[{host}] python3 not found in PATH.",
            "Install Python 3.6+: apt install python3 / yum install python3",
            node=node, evidence=ev, cis_ref="CIS 1.5"
        )
    match = re.search(r'(\d+)\.(\d+)', out)
    if not match:
        return CheckResult(
            "cis1.5", "Python 3.6+ installed",
            1, "Installation", WARN,
            f"[{host}] Cannot parse Python version from: {out}",
            "", node=node, evidence=ev, cis_ref="CIS 1.5"
        )
    major, minor = int(match.group(1)), int(match.group(2))
    ver_str = out.strip()
    if major < 3 or (major == 3 and minor < 6):
        return CheckResult(
            "cis1.5", "Python 3.6+ installed",
            1, "Installation", FAIL,
            f"[{host}] {ver_str} is too old — YugabyteDB requires Python 3.6+.",
            "Upgrade Python: https://www.python.org/downloads/",
            ver_str, node=node, evidence=ev, cis_ref="CIS 1.5"
        )
    return CheckResult(
        "cis1.5", "Python 3.6+ installed",
        1, "Installation", PASS,
        f"[{host}] {ver_str}",
        "", ver_str, node=node, evidence=ev, cis_ref="CIS 1.5"
    )


def check_cis1_8(host: str, args, is_local: bool = True) -> CheckResult:
    """CIS 1.8 – Clocks must be NTP-synchronized on all nodes."""
    node = "" if is_local else host
    # timedatectl show gives machine-parseable output on modern systemd
    out, _, rc = run_cmd_on_node(
        host,
        "timedatectl show --property=NTPSynchronized --value 2>/dev/null"
        " || timedatectl status 2>/dev/null",
        args, is_local
    )
    ev = out if getattr(args, "evidence", False) else ""

    if out:
        synced = out.strip().lower() in ("yes",) or "synchronized: yes" in out.lower()
        not_synced = out.strip().lower() in ("no",) or "synchronized: no" in out.lower()
        if synced:
            return CheckResult(
                "cis1.8", "Clocks NTP-synchronized",
                1, "Installation", PASS,
                f"[{host}] NTP synchronized.",
                "", node=node, evidence=ev, cis_ref="CIS 1.8"
            )
        if not_synced:
            return CheckResult(
                "cis1.8", "Clocks NTP-synchronized",
                1, "Installation", FAIL,
                f"[{host}] NTP NOT synchronized — clock skew causes distributed transaction errors.",
                "Enable and start: systemctl enable --now chronyd",
                node=node, evidence=ev, cis_ref="CIS 1.8"
            )

    # Fall back: check if chronyd or ntpd service is active
    svc_out, _, svc_rc = run_cmd_on_node(
        host,
        "systemctl is-active chronyd 2>/dev/null || systemctl is-active ntpd 2>/dev/null",
        args, is_local
    )
    if svc_out.strip() == "active":
        return CheckResult(
            "cis1.8", "Clocks NTP-synchronized",
            1, "Installation", PASS,
            f"[{host}] NTP service (chronyd/ntpd) is active.",
            "", node=node, evidence=ev or svc_out, cis_ref="CIS 1.8"
        )

    return CheckResult(
        "cis1.8", "Clocks NTP-synchronized",
        1, "Installation", WARN,
        f"[{host}] Could not confirm NTP sync — timedatectl/chronyd/ntpd not available or inconclusive.",
        "Install and enable chronyd: yum install chrony && systemctl enable --now chronyd",
        node=node, evidence=ev, cis_ref="CIS 1.8"
    )


def run_os_checks_on_node(host: str, args, is_local: bool = True) -> List[CheckResult]:
    """Run all OS-level and OS-hardening checks for a single node (local or via SSH)."""
    node = "" if is_local else host
    results = []

    # ── Section 1 OS checks (SSH variants) ──────────────────────────────────────
    # 1.1 – Process user
    cmd = "ps -eo user,comm | grep -v grep | grep -E 'yb-tserver|postgres' | head -3"
    stdout, stderr, _ = run_cmd_on_node(host, cmd, args, is_local)
    ev = stdout if args.evidence else ""
    if not stdout:
        results.append(CheckResult("1.1", "YugabyteDB process not running as root", 1, "OS Security",
                                   MANUAL, f"[{host}] Could not detect yb-tserver process: {stderr}",
                                   "Run YugabyteDB as a dedicated non-root OS user.", node=node, evidence=ev,
                                   cis_ref="CIS 1.7"))
    else:
        user = stdout.split()[0] if stdout.split() else None
        status = FAIL if user == "root" else PASS
        results.append(CheckResult("1.1", "YugabyteDB process not running as root", 1, "OS Security",
                                   status, f"[{host}] yb-tserver running as '{user}'",
                                   "Run as dedicated 'yugabyte' OS user.", value=user or "", node=node, evidence=ev,
                                   cis_ref="CIS 1.7"))

    # 1.4 – TLS key file permissions
    key_file = getattr(args, "ssl_key_file", None)
    if not key_file:
        results.append(CheckResult("1.4", "TLS private key file permissions", 1, "OS Security",
                                   MANUAL, f"[{host}] No --ssl-key-file provided.",
                                   "chmod 600 <key_file>", node=node, cis_ref="CIS 7.8"))
    else:
        kout, _, _ = run_cmd_on_node(
            host, f"stat -c '%a' {shlex.quote(key_file)} 2>/dev/null", args, is_local
        )
        ev4 = kout if args.evidence else ""
        if not kout:
            results.append(CheckResult("1.4", "TLS private key file permissions", 1, "OS Security",
                                       WARN, f"[{host}] Key file not found at: {key_file}",
                                       "chmod 600 <key_file>", node=node, evidence=ev4,
                                       cis_ref="CIS 7.8"))
        else:
            ok = kout.strip() in ("600", "400")
            status = PASS if ok else FAIL
            results.append(CheckResult("1.4", "TLS private key file permissions", 1, "OS Security",
                                       status, f"[{host}] {key_file}: perms={kout.strip()}",
                                       "chmod 600 <ssl_key_file>", value=kout.strip(), node=node, evidence=ev4,
                                       cis_ref="CIS 7.8"))

    # ── CIS 1.4 / 1.5 / 1.8 — Installation checks ──────────────────────────────
    results += [
        check_cis1_4(host, args, is_local),
        check_cis1_5(host, args, is_local),
        check_cis1_8(host, args, is_local),
    ]

    # ── CIS 1.7: resource limits; CIS 1.2: service active ───────────────────────
    results += [
        check_8_1(host, args, is_local),
        check_8_2(host, args, is_local),
        check_8_6(host, args, is_local),
        check_8_7(host, args, is_local),
    ]

    return results


# ─── Runner ──────────────────────────────────────────────────────────────────────

def run_all_checks(conn, args, nodes: Optional[List[NodeInfo]] = None) -> List[CheckResult]:
    cur = conn.cursor()
    dict_cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    results = []

    # ── Warn early if local conf paths were supplied but files are not found ─────
    # (Skip this check in SSH mode — conf files are read from the remote host.)
    _has_ssh = bool(getattr(args, 'ssh_key', None))
    if not _has_ssh:
        for label, raw_path in [("--tserver-conf", args.tserver_conf),
                                 ("--master-conf",  args.master_conf)]:
            if raw_path:
                resolved = os.path.expanduser(os.path.expandvars(raw_path.strip()))
                if not os.path.isfile(resolved):
                    print(f"[!] WARNING: {label} file not found locally: {resolved!r} "
                          "(pass --ssh-key to read conf files from the remote host)")

    # ── OS-level checks ──────────────────────────────────────────────────────────
    # Rule: if SSH credentials are provided, always use SSH for OS checks
    # (script may run from a jump host; never assume the seed is local in that case).
    # Only treat a host as local when no SSH info is given AND it resolves to this machine.
    has_ssh = bool(getattr(args, "ssh_key", None))

    def _is_local(host: str) -> bool:
        if has_ssh:
            return False  # jump-host mode: all nodes via SSH
        local_names = {"127.0.0.1", "localhost", "::1", socket.gethostname()}
        try:
            local_names.add(socket.gethostbyname(socket.gethostname()))
        except Exception:
            pass
        return host in local_names

    if nodes:
        # Multi-node: OS checks on every discovered node
        print(f"[*] Running OS checks on {len(nodes)} node(s) ...")
        for node in nodes:
            local = _is_local(node.host)
            print(f"    → {node.host} ({'local' if local else 'SSH'})")
            results += run_os_checks_on_node(node.host, args, local)
    else:
        # Single-node: seed host only
        seed_host = args.host
        local = _is_local(seed_host)
        if not local and not getattr(args, "ssh_key", None):
            print(f"[!] Seed {seed_host} is remote but no --ssh-key provided. "
                  "OS checks will try SSH with the default key; pass --ssh-user/--ssh-key if needed.")
        print(f"[*] Running OS checks on seed {seed_host} ({'local' if local else 'SSH'}) ...")
        results += run_os_checks_on_node(seed_host, args, local)

    # ── DB-level checks (cluster-wide — run once against args.host) ──────────────

    # Authentication
    results += [
        check_2_1(dict_cur, args),
        check_2_2(cur, args),
        check_2_3(cur, args),
        check_2_4(cur, args),
        check_2_5(cur, args),
    ]

    # Privilege management
    results += [
        check_3_1(cur, args),
        check_3_2(cur, args),
        check_3_3(cur, args),
        check_3_4(cur, args),
        check_3_5(cur, args),
        check_3_6(cur, args),
        check_3_7(cur, args),
    ]

    # Connection & TLS
    results += [
        check_4_1(cur, args),
        check_4_2(cur, args),
        check_4_3(cur, args),
        check_4_4(cur, args),
        check_4_5(cur, args),
        check_4_6(cur, args),
    ]

    # Logging & auditing
    results += [
        check_5_1(cur, args),
        check_5_2(cur, args),
        check_5_3(cur, args),
        check_5_4(cur, args),
        check_5_5(cur, args),
        check_5_6(cur, args),
        check_5_7(cur, args),
        check_5_8(cur, args),
        check_5_9(cur, args),
        check_5_10(cur, args),
        check_5_11(cur, args),
        check_5_12(cur, args),
        check_5_13(cur, args),
        check_5_14(cur, args),
        check_5_15(cur, args),
        check_5_16(cur, args),
        check_5_17(cur, args),
        check_5_18(cur, args),
        check_5_19(cur, args),
    ]

    # Configuration hardening
    results += [
        check_6_1(cur, args),
        check_6_2(cur, args),
        check_6_3(cur, args),
        check_6_4(cur, args),
        check_6_5(cur, args),
        check_6_6(cur, args),
        check_6_7(cur, args),
    ]

    # YugabyteDB-specific (no YBA checks)
    # Fix: check_7_1/7_2/7_3 signatures had unused `cur` param; corrected below
    results += [
        check_7_1(args),
        check_7_2(args),
        check_7_4(cur, args),
        check_cis7_9(cur, args),
    ]

    # YCQL checks — 5.5 always; 5.1 (use_cassandra_authentication) opt-in via --check-ycql
    results.append(check_cis5_5(args))
    if getattr(args, "check_ycql", False):
        results.append(check_7_3(args))

    # pg_hba trust rules — CIS 6.1 (local) and 6.2 (TCP)
    results += [
        check_cis6_1(cur, args),
        check_cis6_2(cur, args),
    ]

    # Manual stubs — all unautomatable CIS checks
    results += get_manual_checks()

    # Sort by CIS doc section order
    results.sort(key=lambda r: _cis_sort_key(r.cis_ref))

    return results


# ─── HTML Report Generator ───────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>YugabyteDB CIS Benchmark Report</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:        #0d1117;
    --bg2:       #161b22;
    --bg3:       #1c2430;
    --border:    #30363d;
    --text:      #e6edf3;
    --text2:     #8b949e;
    --pass:      #3fb950;
    --fail:      #f85149;
    --warn:      #d29922;
    --manual:    #58a6ff;
    --na:        #6e7681;
    --accent:    #1bb3e0;
    --yb:        #0066ff;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'IBM Plex Sans', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
  }

  /* ── Header ── */
  .header {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1b35 50%, #0a1628 100%);
    border-bottom: 1px solid var(--border);
    padding: 2.5rem 3rem 2rem;
    position: relative;
    overflow: hidden;
  }
  .header::before {
    content: '';
    position: absolute;
    top: -60px; right: -60px;
    width: 300px; height: 300px;
    background: radial-gradient(circle, rgba(27,179,224,0.08) 0%, transparent 70%);
    pointer-events: none;
  }
  .header-top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 1.5rem;
  }
  .logo-area {
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  .logo-icon {
    width: 48px; height: 48px;
    background: linear-gradient(135deg, var(--yb), var(--accent));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.4rem;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 600;
    flex-shrink: 0;
  }
  .logo-text h1 {
    font-size: 1.4rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--text);
  }
  .logo-text p {
    font-size: 0.8rem;
    color: var(--text2);
    margin-top: 2px;
    font-family: 'IBM Plex Mono', monospace;
  }
  .meta-pills {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: center;
  }
  .pill {
    background: rgba(255,255,255,0.05);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 4px 12px;
    font-size: 0.75rem;
    color: var(--text2);
    font-family: 'IBM Plex Mono', monospace;
  }
  .pill strong { color: var(--text); font-weight: 500; }

  /* ── Score Banner ── */
  .score-banner {
    display: flex;
    gap: 1px;
    margin-top: 2rem;
    background: var(--border);
    border-radius: 10px;
    overflow: hidden;
    border: 1px solid var(--border);
  }
  .score-cell {
    flex: 1;
    padding: 1.2rem 1rem;
    text-align: center;
    background: var(--bg2);
    transition: background 0.15s;
  }
  .score-cell:hover { background: var(--bg3); }
  .score-num {
    font-size: 2rem;
    font-weight: 700;
    font-family: 'IBM Plex Mono', monospace;
    line-height: 1;
  }
  .score-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 4px;
    color: var(--text2);
  }
  .score-cell.pass  .score-num { color: var(--pass); }
  .score-cell.fail  .score-num { color: var(--fail); }
  .score-cell.warn  .score-num { color: var(--warn); }
  .score-cell.manual .score-num { color: var(--manual); }
  .score-cell.total .score-num { color: var(--text); }

  /* ── Progress bar ── */
  .progress-area { margin-top: 1.5rem; }
  .progress-label {
    display: flex;
    justify-content: space-between;
    font-size: 0.75rem;
    color: var(--text2);
    margin-bottom: 6px;
  }
  .progress-bar {
    height: 8px;
    background: var(--bg3);
    border-radius: 4px;
    overflow: hidden;
    display: flex;
  }
  .progress-pass  { background: var(--pass); }
  .progress-fail  { background: var(--fail); }
  .progress-warn  { background: var(--warn); }
  .progress-manual { background: var(--manual); }

  /* ── Main content ── */
  .container {
    max-width: 1100px;
    margin: 2.5rem auto;
    padding: 0 2rem;
  }

  /* ── Section heading ── */
  .section-group {
    margin-bottom: 2.5rem;
  }
  .section-title {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text2);
    padding: 0.4rem 0;
    margin-bottom: 0.75rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .section-icon {
    width: 20px; height: 20px;
    border-radius: 4px;
    background: var(--bg3);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 0.65rem;
  }

  /* ── Check card ── */
  .check-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 0.5rem;
    overflow: hidden;
    transition: border-color 0.15s;
  }
  .check-card:hover { border-color: rgba(255,255,255,0.15); }
  .check-card.fail  { border-left: 3px solid var(--fail); }
  .check-card.pass  { border-left: 3px solid var(--pass); }
  .check-card.warn  { border-left: 3px solid var(--warn); }
  .check-card.manual { border-left: 3px solid var(--manual); }
  .check-card.na    { border-left: 3px solid var(--na); }

  .check-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.85rem 1rem;
    cursor: pointer;
    user-select: none;
  }
  .check-id {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.7rem;
    color: var(--text2);
    min-width: 28px;
  }
  .check-title {
    flex: 1;
    font-size: 0.9rem;
    font-weight: 500;
    color: var(--text);
  }
  .level-badge {
    font-size: 0.6rem;
    padding: 2px 7px;
    border-radius: 10px;
    font-family: 'IBM Plex Mono', monospace;
    background: rgba(255,255,255,0.06);
    color: var(--text2);
    border: 1px solid var(--border);
    white-space: nowrap;
  }
  .status-badge {
    font-size: 0.65rem;
    padding: 3px 10px;
    border-radius: 10px;
    font-weight: 600;
    font-family: 'IBM Plex Mono', monospace;
    letter-spacing: 0.04em;
    white-space: nowrap;
  }
  .status-badge.pass   { background: rgba(63,185,80,0.15);  color: var(--pass);   border: 1px solid rgba(63,185,80,0.3);  }
  .status-badge.fail   { background: rgba(248,81,73,0.15);  color: var(--fail);   border: 1px solid rgba(248,81,73,0.3);  }
  .status-badge.warn   { background: rgba(210,153,34,0.15); color: var(--warn);   border: 1px solid rgba(210,153,34,0.3); }
  .status-badge.manual { background: rgba(88,166,255,0.15); color: var(--manual); border: 1px solid rgba(88,166,255,0.3); }
  .status-badge.na     { background: rgba(110,118,129,0.15); color: var(--na);    border: 1px solid rgba(110,118,129,0.3); }

  .chevron {
    color: var(--text2);
    font-size: 0.7rem;
    transition: transform 0.2s;
  }
  .check-card.open .chevron { transform: rotate(90deg); }

  .check-body {
    display: none;
    padding: 0 1rem 1rem 1rem;
    border-top: 1px solid var(--border);
  }
  .check-card.open .check-body { display: block; }

  .detail-row {
    display: flex;
    gap: 1rem;
    margin-top: 0.75rem;
    flex-wrap: wrap;
  }
  .detail-block {
    flex: 1;
    min-width: 200px;
  }
  .detail-label {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text2);
    margin-bottom: 4px;
  }
  .detail-value {
    font-size: 0.82rem;
    color: var(--text);
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 0.5rem 0.75rem;
    font-family: 'IBM Plex Mono', monospace;
    word-break: break-word;
    white-space: pre-wrap;
  }
  .remediation-box {
    margin-top: 0.75rem;
    background: rgba(248,81,73,0.06);
    border: 1px solid rgba(248,81,73,0.2);
    border-radius: 5px;
    padding: 0.6rem 0.75rem;
    font-size: 0.82rem;
    color: #ffb3b0;
    display: none;
  }
  .check-card.fail .remediation-box,
  .check-card.warn .remediation-box { display: block; }

  /* ── Filters ── */
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
    align-items: center;
  }
  .filter-btn {
    padding: 5px 14px;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--bg2);
    color: var(--text2);
    font-size: 0.78rem;
    cursor: pointer;
    font-family: 'IBM Plex Sans', sans-serif;
    transition: all 0.15s;
  }
  .filter-btn:hover,
  .filter-btn.active { background: var(--bg3); color: var(--text); border-color: rgba(255,255,255,0.2); }
  .filter-btn.active { font-weight: 600; }

  /* ── Footer ── */
  .footer {
    text-align: center;
    padding: 2rem;
    color: var(--text2);
    font-size: 0.75rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
  }
  .footer a { color: var(--accent); text-decoration: none; }

  /* ── Tool check ID (secondary label) ── */
  .tool-check-id {
    font-size: 0.65rem;
    font-family: 'IBM Plex Mono', monospace;
    color: var(--text2);
    opacity: 0.55;
    margin-left: 4px;
    white-space: nowrap;
  }

  /* ── Node badge ── */
  .node-badge {
    font-size: 0.6rem;
    padding: 2px 8px;
    border-radius: 10px;
    background: rgba(27,179,224,0.12);
    color: var(--accent);
    border: 1px solid rgba(27,179,224,0.3);
    font-family: 'IBM Plex Mono', monospace;
    white-space: nowrap;
    max-width: 160px;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* ── Evidence block ── */
  .evidence-toggle {
    margin-top: 0.6rem;
    font-size: 0.72rem;
    color: var(--accent);
    cursor: pointer;
    user-select: none;
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .evidence-toggle:hover { text-decoration: underline; }
  .evidence-content {
    display: none;
    margin-top: 0.4rem;
    background: #0a0e18;
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 0.6rem 0.75rem;
    font-size: 0.75rem;
    font-family: 'IBM Plex Mono', monospace;
    color: #adbac7;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 300px;
    overflow-y: auto;
  }
  .evidence-block.open .evidence-content { display: block; }
  .evidence-block.open .evidence-toggle .ev-arrow { transform: rotate(90deg); display: inline-block; }
  .ev-arrow { display: inline-block; transition: transform 0.15s; }

  /* ── Coverage table ── */
  .coverage-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 8px;
    margin-top: 1.5rem;
  }
  .cov-cell {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem 1rem;
  }
  .cov-section-name {
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--text);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 0.4rem;
  }
  .cov-stats {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-top: 4px;
  }
  .cov-tag {
    font-size: 0.62rem;
    padding: 2px 7px;
    border-radius: 8px;
    font-family: 'IBM Plex Mono', monospace;
  }
  .cov-tag.pass   { background: rgba(63,185,80,0.12);  color: var(--pass);   border: 1px solid rgba(63,185,80,0.25); }
  .cov-tag.fail   { background: rgba(248,81,73,0.12);  color: var(--fail);   border: 1px solid rgba(248,81,73,0.25); }
  .cov-tag.warn   { background: rgba(210,153,34,0.12); color: var(--warn);   border: 1px solid rgba(210,153,34,0.25); }
  .cov-tag.manual { background: rgba(88,166,255,0.12); color: var(--manual); border: 1px solid rgba(88,166,255,0.25); }
  .cov-tag.na     { background: rgba(110,118,129,0.12);color: var(--na);     border: 1px solid rgba(110,118,129,0.25); }

  /* ── Node filter pills ── */
  .node-filters {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin-top: 0.75rem;
    align-items: center;
  }
  .node-filter-label { font-size: 0.72rem; color: var(--text2); margin-right: 4px; }
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="logo-area">
      <div class="logo-icon">YB</div>
      <div class="logo-text">
        <h1>CIS Benchmark Report</h1>
        <p>YugabyteDB 2.x · CIS Security Audit · {{NODE_MODE}}</p>
      </div>
    </div>
    <div class="meta-pills">
      <div class="pill">Host: <strong>{{HOST}}</strong></div>
      <div class="pill">Port: <strong>{{PORT}}</strong></div>
      <div class="pill">Generated: <strong>{{GENERATED}}</strong></div>
      <div class="pill">Benchmark: <strong>CIS YugabyteDB v1.0.0</strong></div>
    </div>
  </div>

  <div class="score-banner">
    <div class="score-cell total">
      <div class="score-num">{{TOTAL}}</div>
      <div class="score-label">Total Checks</div>
    </div>
    <div class="score-cell pass">
      <div class="score-num">{{PASS_COUNT}}</div>
      <div class="score-label">Pass</div>
    </div>
    <div class="score-cell fail">
      <div class="score-num">{{FAIL_COUNT}}</div>
      <div class="score-label">Fail</div>
    </div>
    <div class="score-cell warn">
      <div class="score-num">{{WARN_COUNT}}</div>
      <div class="score-label">Warning</div>
    </div>
    <div class="score-cell manual">
      <div class="score-num">{{MANUAL_COUNT}}</div>
      <div class="score-label">Manual</div>
    </div>
  </div>

  <div class="progress-area">
    <div class="progress-label">
      <span>Compliance progress (automated checks)</span>
      <span>{{SCORE_PCT}}% passed</span>
    </div>
    <div class="progress-bar">
      <div class="progress-pass"  style="width:{{PASS_PCT}}%"></div>
      <div class="progress-warn"  style="width:{{WARN_PCT}}%"></div>
      <div class="progress-fail"  style="width:{{FAIL_PCT}}%"></div>
      <div class="progress-manual" style="width:{{MANUAL_PCT}}%"></div>
    </div>
  </div>
</div>

<div class="container">

  <!-- Coverage summary -->
  {{COVERAGE_HTML}}

  <div class="toolbar" style="margin-top:1.5rem">
    <span style="font-size:0.78rem;color:var(--text2);margin-right:4px;">Filter:</span>
    <button class="filter-btn active" onclick="filterChecks('all', this)">All</button>
    <button class="filter-btn" onclick="filterChecks('fail', this)">Fail</button>
    <button class="filter-btn" onclick="filterChecks('warn', this)">Warn</button>
    <button class="filter-btn" onclick="filterChecks('pass', this)">Pass</button>
    <button class="filter-btn" onclick="filterChecks('manual', this)">Manual</button>
    <button class="filter-btn" style="margin-left:auto" onclick="expandAll()">Expand All</button>
    <button class="filter-btn" onclick="collapseAll()">Collapse All</button>
  </div>
  {{NODE_FILTER_HTML}}

  {{SECTIONS_HTML}}
</div>

<div class="footer">
  Generated by <strong>YugabyteDB CIS Checker</strong> ·
  Based on <a href="https://www.cisecurity.org/benchmark/yugabytedb" target="_blank">CIS YugabyteDB 2.x Benchmark v1.0.0</a> ·
  {{GENERATED}}
</div>

<script>
let _activeStatus = 'all';
let _activeNode   = 'all';

function toggleCard(card) { card.classList.toggle('open'); }

function toggleEvidence(el, ev) {
  ev.stopPropagation();   // prevent bubbling up to toggleCard
  el.closest('.evidence-block').classList.toggle('open');
}

function applyFilters() {
  document.querySelectorAll('.check-card').forEach(card => {
    const statusOk = _activeStatus === 'all' || card.dataset.status === _activeStatus;
    // Cluster-wide checks (no data-node) are always shown; per-node checks are filtered
    const nodeOk   = _activeNode === 'all' || !card.dataset.node || card.dataset.node === _activeNode;
    card.style.display = (statusOk && nodeOk) ? '' : 'none';
  });
  document.querySelectorAll('.section-group').forEach(g => {
    const visible = [...g.querySelectorAll('.check-card')].some(c => c.style.display !== 'none');
    g.style.display = visible ? '' : 'none';
  });
}

function filterChecks(status, btn) {
  // Only clear active on status buttons, not on node pills
  document.querySelectorAll('.filter-btn:not(.node-pill)').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  _activeStatus = status;
  applyFilters();
}

function filterNode(node, btn) {
  document.querySelectorAll('.node-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  _activeNode = node;
  applyFilters();
}

function expandAll()   { document.querySelectorAll('.check-card').forEach(c => c.classList.add('open')); }
function collapseAll() { document.querySelectorAll('.check-card').forEach(c => c.classList.remove('open')); }
</script>
</body>
</html>
"""

# ─── CIS section ordering helpers ────────────────────────────────────────────────

_CIS_SECTIONS_ORDERED = [
    ("1", "Section 1  Installation and Patches"),
    ("2", "Section 2  Directory and File Permissions"),
    ("3", "Section 3  Logging Monitoring and Auditing"),
    ("4", "Section 4  User Access and Authorization"),
    ("5", "Section 5  Access Control / Password Policies"),
    ("6", "Section 6  Connection and Login"),
    ("7", "Section 7  YugabyteDB Settings"),
    ("8", "Section 8  Special Configuration Considerations"),
]
_CIS_SECTION_MAP = {k: v for k, v in _CIS_SECTIONS_ORDERED}


def _cis_sort_key(cis_ref: str) -> tuple:
    """Numeric sort key for CIS refs like 'CIS 3.1.18', 'CIS 7.2'."""
    if not cis_ref:
        return (999, 999, 999, 999)
    s = cis_ref.replace("CIS ", "").replace("-", ".")
    parts = []
    for p in s.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(999)
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def _cis_section_label(cis_ref: str) -> str:
    """Return the CIS top-level section label from a ref string."""
    if not cis_ref:
        return "Section ?  Tool-Specific"
    top = cis_ref.replace("CIS ", "").split(".")[0]
    return _CIS_SECTION_MAP.get(top, "Section ?  Tool-Specific")


# ─── Manual check stubs (CIS sections not automatable) ────────────────────────

def get_manual_checks() -> List[CheckResult]:
    """Return MANUAL placeholder entries for CIS sections that require human review."""
    M = MANUAL
    stubs = [
        # Section 1 Installation and Patches
        CheckResult("m1.1",  "Packages from authorized repositories",   1, "Installation", M,
                    "Verify all YugabyteDB packages are from official Yugabyte repositories.",
                    "Use official repos: https://download.yugabyte.com. Check: apt policy yugabyte-* / rpm -qi yugabyte*",
                    cis_ref="CIS 1.1"),
        CheckResult("m1.3",  "Data cluster initialized successfully",    1, "Installation", M,
                    "Verify the data cluster was initialized with 'yugabyted start' and no errors.",
                    "Review yugabyted logs and confirm cluster health with 'yugabyted status'.",
                    cis_ref="CIS 1.3"),
        # Section 2 Directory and File Permissions
        CheckResult("m2.1",  "File permissions mask (umask) reviewed",  1, "File Permissions", M,
                    "Confirm the OS umask for the yugabyte user prevents world-readable file creation.",
                    "Verify 'umask' output as yugabyte user is 027 or stricter. Set in /etc/profile.d/yugabyte.sh.",
                    cis_ref="CIS 2.1"),
        # Section 3 Logging
        CheckResult("m3.1.1", "Logging configuration rationale reviewed", 1, "Logging", M,
                    "Review the overall logging strategy: destinations, rotation policy, retention, and syslog integration.",
                    "Ensure log files are shipped off-node to a centralized log management system (e.g. Splunk, ELK).",
                    cis_ref="CIS 3.1.1"),
        CheckResult("m3.1.8", "Correct syslog facility selected",        1, "Logging", M,
                    "If using syslog logging, verify log_facility is set to an appropriate facility (e.g. LOCAL0).",
                    "Set log_facility=LOCAL0 in ysql_pg_conf_csv and configure syslog to capture that facility.",
                    cis_ref="CIS 3.1.8"),
        CheckResult("m3.1.9",  "Syslog messages not suppressed",         1, "Logging", M,
                    "Verify syslog is not configured to drop YugabyteDB log messages.",
                    "Check /etc/rsyslog.conf or /etc/syslog.conf for any discard rules affecting the DB facility.",
                    cis_ref="CIS 3.1.9"),
        CheckResult("m3.1.10", "Syslog messages not lost due to size",   1, "Logging", M,
                    "Confirm syslog is configured to handle large log messages without truncation.",
                    "Set $MaxMessageSize 64k in rsyslog.conf if using syslog as log_destination.",
                    cis_ref="CIS 3.1.10"),
        CheckResult("m3.1.11", "syslog_ident set to identifiable program name", 1, "Logging", M,
                    "If log_destination includes 'syslog', confirm syslog_ident is set to a recognizable string "
                    "(e.g. 'yugabyte') so DB messages are distinguishable in the syslog stream.",
                    "Run: SHOW syslog_ident; — set via ysql_pg_conf_csv='syslog_ident=yugabyte'.",
                    cis_ref="CIS 3.1.11"),
        CheckResult("m3.3",   "YCQL auditing enabled (if YCQL used)",   1, "Logging", M,
                    "If the YCQL API is in use, verify audit logging is configured for CQL operations.",
                    "Enable YCQL audit via --ycql_enable_audit_log=true in tserver flags.",
                    cis_ref="CIS 3.3"),
        # Section 4 User Access and Authorization
        CheckResult("m4.1",  "sudo configured correctly",               1, "Access Control", M,
                    "Review /etc/sudoers to ensure the yugabyte OS user has minimal sudo rights.",
                    "Run: sudo -l -U yugabyte. Remove any NOPASSWD or ALL=(ALL) grants not required.",
                    cis_ref="CIS 4.1"),
        CheckResult("m4.5",  "Row Level Security (RLS) reviewed",       2, "Access Control", M,
                    "Verify that tables containing sensitive data use Row Level Security policies.",
                    "Run: SELECT tablename, rowsecurity FROM pg_tables WHERE rowsecurity=false AND schemaname='public';",
                    cis_ref="CIS 4.5"),
        CheckResult("m4.6",  "Predefined roles used appropriately",     2, "Access Control", M,
                    "Review pg_monitor, pg_read_all_stats, etc. predefined roles and ensure they are granted to appropriate users only.",
                    "Run: SELECT rolname, pg_get_userbyid(member) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid WHERE r.rolname LIKE 'pg_%';",
                    cis_ref="CIS 4.6"),
        # Section 5 Access Control / Password Policies (YCQL)
        CheckResult("m5.2",  "Default cassandra role password changed",  1, "YCQL Auth", M,
                    "If YCQL is enabled, the default 'cassandra' superuser password must be changed.",
                    "Connect via cqlsh and run: ALTER ROLE cassandra WITH PASSWORD '<strong_pwd>';",
                    cis_ref="CIS 5.2"),
        CheckResult("m5.3",  "Cassandra and superuser roles are separate", 1, "YCQL Auth", M,
                    "Do not use the cassandra role for application workloads. Create dedicated application roles.",
                    "Create a dedicated role: CREATE ROLE app_user WITH LOGIN=true AND PASSWORD='<pwd>';",
                    cis_ref="CIS 5.3"),
        CheckResult("m5.4",  "No unnecessary YCQL roles",               1, "YCQL Auth", M,
                    "Review all YCQL roles and revoke/drop any that are no longer needed.",
                    "Via cqlsh: LIST ROLES; DROP ROLE <unused>;",
                    cis_ref="CIS 5.4"),
        # Section 6 Connection and Login
        # Section 7 YugabyteDB Settings
        CheckResult("m7.1",  "Attack vectors and GFLAGs reviewed",       1, "YB Settings", M,
                    "Review all enabled GFLAGs for attack surface. Disable any experimental or permissive flags.",
                    "Check: curl -s http://localhost:9000/varz | grep -E 'enable|allow|trust' — review carefully.",
                    cis_ref="CIS 7.1"),
        CheckResult("m7.3",  "Postmaster runtime parameters reviewed",   1, "YB Settings", M,
                    "Review GFLAGs that require a Postmaster restart. Changes need a controlled maintenance window.",
                    "Compare running GFLAGs (via /varz) against documented baseline values.",
                    cis_ref="CIS 7.3"),
        CheckResult("m7.4",  "SIGHUP runtime parameters reviewed",       1, "YB Settings", M,
                    "Review GFLAGs reloadable via SIGHUP. Ensure no unauthorized changes are pending.",
                    "Compare: pg_settings source='configuration file' vs known-good values.",
                    cis_ref="CIS 7.4"),
        CheckResult("m7.5",  "Superuser runtime parameters reviewed",    2, "YB Settings", M,
                    "Review GFLAGs settable by superusers. Ensure application users cannot override security settings.",
                    "Run: SELECT name, setting, source FROM pg_settings WHERE context='superuser' ORDER BY name;",
                    cis_ref="CIS 7.5"),
        CheckResult("m7.6",  "User runtime parameters reviewed",         2, "YB Settings", M,
                    "Review GFLAGs settable by regular users. Ensure these cannot be exploited.",
                    "Run: SELECT name, setting FROM pg_settings WHERE context='user' ORDER BY name;",
                    cis_ref="CIS 7.6"),
        # Section 8 Special Configuration Considerations
        CheckResult("m8.1",  "Base backups configured and tested",        1, "Special Config", M,
                    "Confirm automated backups are configured and restoration has been tested.",
                    "Verify backup schedule in YugabyteDB backup configuration. Test: perform a restore to a test cluster.",
                    cis_ref="CIS 8.1"),
        CheckResult("m8.2",  "Config files outside data cluster directory", 1, "Special Config", M,
                    "YugabyteDB conf files should not be inside the data directory to avoid accidental deletion.",
                    "Verify --fs_data_dirs does not contain the path to tserver.conf / master.conf.",
                    cis_ref="CIS 8.2"),
        CheckResult("m8.3",  "Subdirectory locations outside data cluster", 1, "Special Config", M,
                    "Ensure WAL and data subdirectories are on separate mount points from the OS.",
                    "Run: df -h $(yugabyted config get data_dir). Confirm separate disk/volume.",
                    cis_ref="CIS 8.3"),
        CheckResult("m8.4",  "Miscellaneous configuration settings reviewed", 1, "Special Config", M,
                    "Review remaining GFLAGs not covered by other checks: memory limits, CPU pinning, NUMA settings.",
                    "Compare running flags (curl http://localhost:9000/varz) against documented best-practice baseline.",
                    cis_ref="CIS 8.4"),
    ]
    return stubs


SECTION_ICONS = {
    "Section 1  Installation and Patches":          "🖥",
    "Section 2  Directory and File Permissions":    "📁",
    "Section 3  Logging Monitoring and Auditing":   "📋",
    "Section 4  User Access and Authorization":     "🛡",
    "Section 5  Access Control / Password Policies":"🔑",
    "Section 6  Connection and Login":              "🔒",
    "Section 7  YugabyteDB Settings":               "⚙",
    "Section 8  Special Configuration Considerations":"🔧",
    "Section ?  Tool-Specific":                     "🐘",
}

def generate_html(results: List[CheckResult], args) -> str:
    counts = {PASS: 0, FAIL: 0, WARN: 0, MANUAL: 0, NA: 0, INFO: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    total      = len(results)
    automated  = total - counts.get(MANUAL, 0) - counts.get(NA, 0)
    pass_pct   = round(counts[PASS]   / total * 100) if total else 0
    fail_pct   = round(counts[FAIL]   / total * 100) if total else 0
    warn_pct   = round(counts[WARN]   / total * 100) if total else 0
    manual_pct = round((counts[MANUAL] + counts.get(INFO, 0)) / total * 100) if total else 0
    score_pct  = round(counts[PASS] / automated * 100) if automated > 0 else 0

    # ── Coverage table — grouped by CIS doc section ───────────────────────────────
    section_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in results:
        section_counts[_cis_section_label(r.cis_ref)][r.status] += 1

    cov_cells = []
    # Iterate in CIS doc order
    ordered_sections = [v for _, v in _CIS_SECTIONS_ORDERED if v in section_counts]
    if "Section ?  Tool-Specific" in section_counts:
        ordered_sections.append("Section ?  Tool-Specific")
    for section in ordered_sections:
        sc = section_counts[section]
        tags = ""
        for st, cls in [(PASS, "pass"), (FAIL, "fail"), (WARN, "warn"), (MANUAL, "manual"), (NA, "na")]:
            if sc.get(st, 0):
                tags += f'<span class="cov-tag {cls}">{sc[st]} {st}</span>'
        cov_cells.append(
            f'<div class="cov-cell"><div class="cov-section-name">{_esc(section)}</div>'
            f'<div class="cov-stats">{tags}</div></div>'
        )

    auto_checks   = automated
    pass_auto     = counts[PASS]
    coverage_pct  = round(pass_auto / auto_checks * 100) if auto_checks else 0
    has_evidence  = any(r.evidence for r in results)

    coverage_html = f"""
<div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:1.25rem 1.5rem;margin-bottom:1.5rem">
  <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:0.75rem">
    <span style="font-size:0.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text2);font-weight:600">Coverage Summary</span>
    <span style="font-size:0.78rem;color:var(--text2)">{auto_checks} automated · {counts[MANUAL]} manual · {counts.get(NA,0)} N/A · <strong style="color:var(--pass)">{coverage_pct}% pass rate</strong></span>
  </div>
  <div class="coverage-grid">{''.join(cov_cells)}</div>
  {'<div style="margin-top:0.6rem;font-size:0.72rem;color:var(--accent)">⚡ Evidence collected — expand a check card to view raw output.</div>' if has_evidence else ''}
</div>"""

    # ── Node filter pills ─────────────────────────────────────────────────────────
    all_nodes = sorted({r.node for r in results if r.node})
    node_filter_html = ""
    if all_nodes:
        pills = '<button class="filter-btn node-pill active" data-node="all" onclick="filterNode(this.dataset.node,this)">All Nodes</button>'
        for n in all_nodes:
            pills += f'<button class="filter-btn node-pill" data-node="{_esc(n)}" onclick="filterNode(this.dataset.node,this)">{_esc(n)}</button>'
        node_filter_html = f'<div class="node-filters"><span class="node-filter-label">Node:</span>{pills}</div>'

    # ── Check cards — grouped by CIS doc section ──────────────────────────────────
    grouped: Dict[str, List[CheckResult]] = defaultdict(list)
    for r in results:
        grouped[_cis_section_label(r.cis_ref)].append(r)

    # CIS doc order: Section 1 → Section 2 → … Section 8 → tool-specific
    section_order = [v for _, v in _CIS_SECTIONS_ORDERED if v in grouped]
    if "Section ?  Tool-Specific" in grouped:
        section_order.append("Section ?  Tool-Specific")

    sections_html = []
    for section in section_order:
        checks = grouped[section]
        icon = SECTION_ICONS.get(section, "•")
        cards_html = []
        for c in checks:
            status_cls = c.status.lower().replace("/", "")
            node_attr  = f' data-node="{_esc(c.node)}"' if c.node else ''
            node_badge = f'<span class="node-badge" title="{_esc(c.node)}">{_esc(c.node)}</span>' if c.node else ''

            body_parts = []
            if c.value:
                body_parts.append(
                    f'<div class="detail-block"><div class="detail-label">Observed Value</div>'
                    f'<div class="detail-value">{_esc(c.value)}</div></div>'
                )
            body_parts.append(
                f'<div class="detail-block" style="flex:2"><div class="detail-label">Finding</div>'
                f'<div class="detail-value">{_esc(c.detail)}</div></div>'
            )

            remediation_html = ""
            if c.remediation and c.status in (FAIL, WARN):
                remediation_html = (
                    f'<div class="remediation-box"><strong>Remediation:</strong> {_esc(c.remediation)}</div>'
                )

            evidence_html = ""
            if c.evidence:
                evidence_html = (
                    f'<div class="evidence-block">'
                    f'<div class="evidence-toggle" onclick="toggleEvidence(this, event)">'
                    f'<span class="ev-arrow">▶</span> Evidence</div>'
                    f'<pre class="evidence-content">{_esc(c.evidence)}</pre>'
                    f'</div>'
                )

            cis_id_span = (f'<span class="check-id">{_esc(c.cis_ref)}</span>'
                           if c.cis_ref else
                           f'<span class="check-id">{_esc(c.check_id)}</span>')
            tool_id_note = (f'<span class="tool-check-id" title="Tool check ID">{_esc(c.check_id)}</span>'
                            if c.cis_ref else '')

            cards_html.append(f"""
  <div class="check-card {status_cls}" data-status="{status_cls}"{node_attr} onclick="toggleCard(this)">
    <div class="check-header">
      {cis_id_span}
      <span class="check-title">{_esc(c.title)}</span>
      {tool_id_note}
      {node_badge}
      <span class="level-badge">L{c.level}</span>
      <span class="status-badge {status_cls}">{c.status}</span>
      <span class="chevron">▶</span>
    </div>
    <div class="check-body">
      <div class="detail-row">{''.join(body_parts)}</div>
      {remediation_html}
      {evidence_html}
    </div>
  </div>""")

        # Section check count (unique check IDs, not per-node duplicates)
        unique_ids = len({c.check_id for c in checks})
        node_count = len({c.node for c in checks if c.node})
        node_note  = f" · {node_count} nodes" if node_count > 1 else ""
        sections_html.append(f"""
<div class="section-group">
  <div class="section-title">
    <span class="section-icon">{icon}</span>
    {_esc(section)}
    <span style="color:var(--text2);font-weight:400">({unique_ids} checks{node_note})</span>
  </div>
  {''.join(cards_html)}
</div>""")

    node_mode = f"{len(all_nodes)} nodes" if all_nodes else "Single Node"
    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = HTML_TEMPLATE
    html = html.replace("{{HOST}}",          _esc(args.host))
    html = html.replace("{{PORT}}",          str(args.port))
    html = html.replace("{{GENERATED}}",     generated)
    html = html.replace("{{TOTAL}}",         str(total))
    html = html.replace("{{PASS_COUNT}}",    str(counts[PASS]))
    html = html.replace("{{FAIL_COUNT}}",    str(counts[FAIL]))
    html = html.replace("{{WARN_COUNT}}",    str(counts[WARN]))
    html = html.replace("{{MANUAL_COUNT}}",  str(counts[MANUAL]))
    html = html.replace("{{SCORE_PCT}}",     str(score_pct))
    html = html.replace("{{PASS_PCT}}",      str(pass_pct))
    html = html.replace("{{FAIL_PCT}}",      str(fail_pct))
    html = html.replace("{{WARN_PCT}}",      str(warn_pct))
    html = html.replace("{{MANUAL_PCT}}",    str(manual_pct))
    html = html.replace("{{NODE_MODE}}",     node_mode)
    html = html.replace("{{COVERAGE_HTML}}", coverage_html)
    html = html.replace("{{NODE_FILTER_HTML}}", node_filter_html)
    html = html.replace("{{SECTIONS_HTML}}", "\n".join(sections_html))
    return html


def _esc(s: str) -> str:
    """Minimal HTML escaping."""
    if not s:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ─── JSON Output ─────────────────────────────────────────────────────────────────

def generate_json(results: List[CheckResult], args) -> str:
    nodes = sorted({r.node for r in results if r.node})
    data = {
        "generated":  datetime.datetime.now().isoformat(),
        "host":       args.host,
        "port":       args.port,
        "benchmark":  "CIS YugabyteDB 2.x Benchmark v1.0.0",
        "mode":       f"{len(nodes)}-node" if nodes else "single-node",
        "nodes":      nodes,
        "summary": {
            s: sum(1 for r in results if r.status == s)
            for s in [PASS, FAIL, WARN, MANUAL, NA, INFO]
        },
        "checks": [
            {
                "id":          r.check_id,
                "title":       r.title,
                "level":       r.level,
                "section":     r.section,
                "status":      r.status,
                "detail":      r.detail,
                "value":       r.value,
                "node":        r.node,
                "evidence":    r.evidence,
                "remediation": r.remediation,
                "cis_ref":     r.cis_ref,
            }
            for r in results
        ],
    }
    return json.dumps(data, indent=2)


# ─── CLI ─────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="YugabyteDB CIS Benchmark Checker — Multi-Node",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Minimal — SQL checks only against a single node:
  python3 yugabytedb_cis_checker.py --seed 127.0.0.1 --port 5433 \\
      --user yugabyte --password secret --output report.html

  # Full single-node with OS + conf checks:
  python3 yugabytedb_cis_checker.py --seed 127.0.0.1 --port 5433 \\
      --user yugabyte --password secret \\
      --tserver-conf /home/yugabyte/tserver/conf/server.conf \\
      --master-conf  /home/yugabyte/master/conf/server.conf \\
      --ssl-key-file /home/yugabyte/certs/node.key \\
      --evidence --output report.html

  # Multi-node — discover all nodes via yb_servers() and SSH into each:
  python3 yugabytedb_cis_checker.py --seed 10.0.0.1 --port 5433 \\
      --user yugabyte --password secret \\
      --all-nodes --ssh-user yugabyte --ssh-key ~/.ssh/yb_rsa \\
      --evidence --output report.html

  # Include YCQL authentication check:
  python3 yugabytedb_cis_checker.py ... --check-ycql \\
      --tserver-conf /home/yugabyte/tserver/conf/server.conf

  # JSON output:
  python3 yugabytedb_cis_checker.py ... --format json --output report.json
""",
    )

    # ── Database connection ──────────────────────────────────────────────────────
    p.add_argument("--seed",         dest="host", default="127.0.0.1",
                   help="Seed node host/IP — YSQL connection and cluster discovery entry point")
    p.add_argument("--port",         type=int, default=5433, help="YSQL port (default: 5433)")
    p.add_argument("--user",         default="yugabyte",   help="Database user")
    p.add_argument("--password",     default="",           help="Database password")
    p.add_argument("--dbname",       default="yugabyte",   help="Database name")
    p.add_argument("--sslmode",      default="prefer",     help="psycopg2 sslmode (prefer/require/disable)")

    # ── File paths for conf/TLS checks ──────────────────────────────────────────
    p.add_argument("--tserver-conf", dest="tserver_conf",  help="Path to yb-tserver server.conf")
    p.add_argument("--master-conf",  dest="master_conf",   help="Path to yb-master server.conf")
    p.add_argument("--ssl-key-file", dest="ssl_key_file",  help="Path to TLS private key file")

    # ── Multi-node SSH options ───────────────────────────────────────────────────
    p.add_argument("--all-nodes",    dest="all_nodes",     action="store_true",
                   help="Discover all cluster nodes via yb_servers() and run OS checks on each via SSH")
    p.add_argument("--ssh-user",     dest="ssh_user",      default="yugabyte",
                   help="SSH username for remote OS checks (default: yugabyte)")
    p.add_argument("--ssh-key",      dest="ssh_key",       default=None,
                   help="Path to SSH private key file")
    p.add_argument("--ssh-port",     dest="ssh_port",      type=int, default=22,
                   help="SSH port (default: 22)")

    # ── API scope ────────────────────────────────────────────────────────────────
    p.add_argument("--check-ycql",   dest="check_ycql",    action="store_true",
                   help="Include YCQL authentication check (7.3); requires --tserver-conf")

    # ── Evidence & output ────────────────────────────────────────────────────────
    p.add_argument("--evidence",     action="store_true",
                   help="Capture raw command/query output as evidence in the report")
    p.add_argument("--output",  "-o", default="yb_cis_report.html", help="Output file path")
    p.add_argument("--format",       choices=["html", "json"], default="html",
                   help="Output format (default: html)")
    p.add_argument("--level",        type=int, choices=[1, 2], default=1,
                   help="CIS level filter: 1 = Level-1 checks only (default), 2 = include Level-2 checks")
    return p.parse_args()


def main():
    args = parse_args()

    print(f"[*] Connecting to YugabyteDB at {args.host}:{args.port} (db={args.dbname}) ...")
    try:
        conn = psycopg2.connect(
            host=args.host,
            port=args.port,
            user=args.user,
            password=args.password,
            dbname=args.dbname,
            sslmode=args.sslmode,
            connect_timeout=10,
        )
        conn.autocommit = True
        print("[+] Connected.")
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)

    # ── Node discovery ───────────────────────────────────────────────────────────
    nodes: Optional[List[NodeInfo]] = None
    if args.all_nodes:
        nodes = discover_nodes(conn)
        if not nodes:
            print("[!] yb_servers() returned no results — falling back to single-node mode.")
            nodes = None
        else:
            print(f"[+] Discovered {len(nodes)} node(s):")
            for n in nodes:
                print(f"    {n.host}:{n.port}  type={n.node_type}  region={n.region}/{n.zone}")

    if args.evidence:
        print("[*] Evidence collection enabled — raw output will be captured.")
    if args.check_ycql:
        print("[*] YCQL checks enabled.")

    # ── Run checks ───────────────────────────────────────────────────────────────
    print("[*] Running CIS benchmark checks ...")
    results = run_all_checks(conn, args, nodes)
    conn.close()

    # Filter by CIS level
    results = [r for r in results if r.level <= args.level]

    # ── Console summary ──────────────────────────────────────────────────────────
    counts: Dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    all_nodes_found = sorted({r.node for r in results if r.node})
    mode_str = f"{len(all_nodes_found)} nodes" if all_nodes_found else "single-node"
    automated = len(results) - counts.get(MANUAL, 0) - counts.get(NA, 0)
    score = round(counts.get(PASS, 0) / automated * 100) if automated else 0

    print(f"\n{'─'*56}")
    print(f"  CIS BENCHMARK RESULTS  [{mode_str}]  Level ≤ {args.level}")
    print(f"{'─'*56}")
    print(f"  Total checks : {len(results)}")
    print(f"  PASS         : {counts.get(PASS,0)}")
    print(f"  FAIL         : {counts.get(FAIL,0)}")
    print(f"  WARN         : {counts.get(WARN,0)}")
    print(f"  MANUAL       : {counts.get(MANUAL,0)}")
    print(f"  N/A          : {counts.get(NA,0)}")
    print(f"  Score        : {score}% (automated checks)")
    if all_nodes_found:
        print(f"  Nodes        : {', '.join(all_nodes_found)}")
    print(f"{'─'*56}")

    # ── Generate report ──────────────────────────────────────────────────────────
    if args.format == "html":
        report = generate_html(results, args)
    else:
        report = generate_json(results, args)

    with open(args.output, "w") as f:
        f.write(report)

    print(f"\n[+] Report saved to: {args.output}")


if __name__ == "__main__":
    main()
