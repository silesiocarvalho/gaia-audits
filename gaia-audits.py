#!/usr/bin/env python3
"""
CIS Check Point Firewall Benchmark v1.1.0 Audit Tool
Targets: Check Point Gaia R82 Standalone
Author : Silesio Carvalho
Usage  : python audit_tool.py -m <ip> -u <user> -p <pass> [options]
"""

from __future__ import print_function

import argparse
import datetime
import getpass
import json
import os
import re
import sys
import time

# ---------------------------------------------------------------------------
# Optional imports – SSH (paramiko) and CP Management API SDK
# ---------------------------------------------------------------------------
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cp_mgmt_api_python_sdk'))
    from cpapi import APIClient, APIClientArgs
    HAS_CPAPI = True
except ImportError:
    HAS_CPAPI = False

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
RESET  = "\033[0m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def colorize(text, color):
    if sys.stdout.isatty():
        return f"{color}{text}{RESET}"
    return text

# ---------------------------------------------------------------------------
# Result constants
# ---------------------------------------------------------------------------
PASS    = "PASS"
FAIL    = "FAIL"
MANUAL  = "MANUAL"
SKIPPED = "SKIPPED"
ERROR   = "ERROR"

STATUS_ICON = {
    PASS:    colorize("✅ PASS",    GREEN),
    FAIL:    colorize("❌ FAIL",    RED),
    MANUAL:  colorize("⚠️  MANUAL", YELLOW),
    SKIPPED: colorize("⏭️  SKIPPED", DIM),
    ERROR:   colorize("🔴 ERROR",   RED),
}

# ---------------------------------------------------------------------------
# SSH helper
# ---------------------------------------------------------------------------
class GaiaClishSession:
    """Thin wrapper around a Paramiko SSH connection that runs Gaia Clish cmds."""

    PROMPT_RE = re.compile(r'[\w\-\.]+[>#]\s*$')
    TIMEOUT   = 15

    def __init__(self, host, port=22):
        if not HAS_PARAMIKO:
            raise RuntimeError("paramiko is required for SSH connectivity. "
                               "Install with: pip install paramiko --break-system-packages")
        self.host   = host
        self.port   = port
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.channel = None

    def connect(self, username, password=None, key_filename=None):
        kwargs = dict(hostname=self.host, port=self.port, username=username,
                      timeout=10, look_for_keys=False, allow_agent=False)
        if password:
            kwargs['password'] = password
        if key_filename:
            kwargs['key_filename'] = key_filename
        self.client.connect(**kwargs)
        self.channel = self.client.invoke_shell()
        self.channel.settimeout(self.TIMEOUT)
        self._drain()                   # eat login banner / prompt

    def _drain(self):
        """Read until we see a shell prompt."""
        buf = ""
        deadline = time.time() + self.TIMEOUT
        while time.time() < deadline:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096).decode('utf-8', errors='replace')
                buf += chunk
                if self.PROMPT_RE.search(buf.splitlines()[-1] if buf.splitlines() else ""):
                    break
            else:
                time.sleep(0.1)
        return buf

    def run(self, command):
        """Send a Clish command and return the output lines (stripped)."""
        self.channel.send(command + "\n")
        time.sleep(0.2)
        output = self._drain()
        # Remove the echoed command and trailing prompt
        lines = output.splitlines()
        result_lines = []
        skip_first = True
        for line in lines:
            stripped = line.strip()
            if skip_first and command.strip() in stripped:
                skip_first = False
                continue
            if self.PROMPT_RE.match(stripped):
                continue
            result_lines.append(stripped)
        return "\n".join(result_lines).strip()

    def close(self):
        if self.channel:
            self.channel.close()
        self.client.close()


# ---------------------------------------------------------------------------
# Audit result dataclass (plain dict for Python 2/3 compat)
# ---------------------------------------------------------------------------
def make_result(control_id, description, level, status,
                expected=None, actual=None, remediation="", notes=""):
    return {
        "control_id":   control_id,
        "description":  description,
        "level":        level,
        "status":       status,
        "expected":     expected,
        "actual":       actual,
        "remediation":  remediation,
        "notes":        notes,
        "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# Core audit checks
# ---------------------------------------------------------------------------
class CISAudit:

    def __init__(self, ssh_session, mgmt_client=None):
        self.ssh     = ssh_session
        self.mgmt    = mgmt_client   # CP API client (optional)
        self.results = []

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------
    def _cmd(self, command):
        try:
            return self.ssh.run(command)
        except Exception as e:
            return f"__ERROR__: {e}"

    def _extract_value(self, output, pattern):
        """Return first capture group from regex search, or None."""
        m = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    def _is_on(self, value):
        return str(value).lower() in ('on', 'true', 'yes', 'enabled', '1')

    def _numeric_le(self, value, threshold):
        try:
            return int(value) <= threshold
        except (TypeError, ValueError):
            return False

    def _numeric_ge(self, value, threshold):
        try:
            return int(value) >= threshold
        except (TypeError, ValueError):
            return False

    def _add(self, result):
        self.results.append(result)

    def _manual(self, control_id, description, level, notes="", remediation=""):
        self._add(make_result(control_id, description, level, MANUAL,
                               notes=notes, remediation=remediation))

    def _error(self, control_id, description, level, err):
        self._add(make_result(control_id, description, level, ERROR,
                               notes=str(err)))

    # -----------------------------------------------------------------------
    # Section 1 – Password Policy
    # -----------------------------------------------------------------------
    def check_1_1(self):
        cid, desc, level = "1.1", "Ensure Minimum Password Length is set to 14 or higher", "L1"
        out = self._cmd("show password-controls min-password-length")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_ge(val, 14) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≥ 14", actual=val,
                               remediation="set password-controls min-password-length 14"))

    def check_1_2(self):
        cid, desc, level = "1.2", "Ensure Disallow Palindromes is selected", "L1"
        out = self._cmd("show password-controls palindrome-check")
        val = self._extract_value(out, r'(on|off|true|false)', ) or out
        status = PASS if self._is_on(val) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="on", actual=val,
                               remediation="set password-controls palindrome-check on"))

    def check_1_3(self):
        cid, desc, level = "1.3", "Ensure Password Complexity is set to 3", "L1"
        out = self._cmd("show password-controls complexity")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if int(val) >= 3 else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≥ 3", actual=val,
                               remediation="set password-controls complexity 3"))

    def check_1_4_history_checking(self):
        cid, desc, level = "1.4a", "Ensure Check for Password Reuse is selected", "L1"
        out = self._cmd("show password-controls history-checking")
        val = self._extract_value(out, r'(on|off|true|false)') or out
        status = PASS if self._is_on(val) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="on", actual=val,
                               remediation="set password-controls history-checking on"))

    def check_1_4_history_length(self):
        cid, desc, level = "1.4b", "Ensure History Length is set to 12 or more", "L1"
        out = self._cmd("show password-controls history-length")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_ge(val, 12) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≥ 12", actual=val,
                               remediation="set password-controls history-length 12"))

    def check_1_5(self):
        cid, desc, level = "1.5", "Ensure Password Expiration is set to 90 days or less", "L1"
        out = self._cmd("show password-controls password-expiration")
        # "never" or a number
        if 'never' in out.lower():
            status = FAIL
            val = "never"
        else:
            val = self._extract_value(out, r'(\d+)')
            if val is None:
                self._error(cid, desc, level, f"Unexpected output: {out}")
                return
            status = PASS if self._numeric_le(val, 90) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 90 days", actual=val,
                               remediation="set password-controls password-expiration 90"))

    def check_1_6(self):
        cid, desc, level = "1.6", "Ensure Warn users before password expiration is set to 7 days or less", "L1"
        out = self._cmd("show password-controls expiration-warning-days")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_le(val, 7) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 7 days", actual=val,
                               remediation="set password-controls expiration-warning-days 7"))

    def check_1_7(self):
        cid, desc, level = "1.7", "Ensure Lockout users after password expiration is set to 1", "L1"
        out = self._cmd("show password-controls expiration-lockout-days")
        if 'never' in out.lower():
            status = FAIL
            val = "never"
        else:
            val = self._extract_value(out, r'(\d+)')
            if val is None:
                self._error(cid, desc, level, f"Unexpected output: {out}")
                return
            status = PASS if int(val) == 1 else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="1 day", actual=val,
                               remediation="set password-controls expiration-lockout-days 1"))

    def check_1_8(self):
        cid, desc, level = "1.8", "Ensure Deny access to unused accounts is selected", "L1"
        out = self._cmd("show password-controls deny-on-nonuse enable")
        val = self._extract_value(out, r'(on|off|true|false)') or out
        status = PASS if self._is_on(val) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="on", actual=val,
                               remediation="set password-controls deny-on-nonuse enable on"))

    def check_1_9(self):
        cid, desc, level = "1.9", "Ensure Days of non-use before lock-out is set to 30 or less", "L1"
        out = self._cmd("show password-controls deny-on-nonuse allowed-days")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_le(val, 30) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 30 days", actual=val,
                               remediation="set password-controls deny-on-nonuse allowed-days 30"))

    def check_1_10(self):
        cid, desc, level = "1.10", "Ensure Force users to change password at first login", "L1"
        out = self._cmd("show password-controls force-change-when")
        status = PASS if 'password' in out.lower() else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="password", actual=out,
                               remediation="set password-controls force-change-when password"))

    def check_1_11(self):
        cid, desc, level = "1.11", "Ensure Deny access after failed login attempts is selected", "L1"
        out = self._cmd("show password-controls deny-on-fail enable")
        val = self._extract_value(out, r'(on|off|true|false)') or out
        status = PASS if self._is_on(val) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="on", actual=val,
                               remediation="set password-controls deny-on-fail enable on"))

    def check_1_12(self):
        cid, desc, level = "1.12", "Ensure Maximum number of failed attempts allowed is set to 5 or fewer", "L1"
        out = self._cmd("show password-controls deny-on-fail failures-allowed")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_le(val, 5) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 5", actual=val,
                               remediation="set password-controls deny-on-fail failures-allowed 5"))

    def check_1_13(self):
        cid, desc, level = "1.13", "Ensure Allow access again after time is set to 300 or more seconds", "L1"
        out = self._cmd("show password-controls deny-on-fail allow-after")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_ge(val, 300) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≥ 300 sec", actual=val,
                               remediation="set password-controls deny-on-fail allow-after 300"))

    # -----------------------------------------------------------------------
    # Section 2.1 – General Settings
    # -----------------------------------------------------------------------
    def check_2_1_1(self):
        cid, desc, level = "2.1.1", "Ensure 'Login Banner' is set", "L1"
        out = self._cmd("show configuration message")
        banner_on   = bool(re.search(r'set message banner on', out, re.IGNORECASE))
        has_content = bool(re.search(r'set message banner on.*msgvalue', out, re.IGNORECASE | re.DOTALL))
        if banner_on and has_content:
            status = PASS
        elif banner_on:
            status = FAIL
            out = "Banner on but no msgvalue configured"
        else:
            status = FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="message banner on + msgvalue set", actual=out[:120],
                               remediation='set message banner on msgvalue "Unauthorized access prohibited"'))

    def check_2_1_2(self):
        cid, desc, level = "2.1.2", "Ensure 'Message Of The Day (MOTD)' is set", "L1"
        out = self._cmd("show configuration message")
        motd_on     = bool(re.search(r'set message motd on', out, re.IGNORECASE))
        has_content = bool(re.search(r'set message motd on.*msgvalue', out, re.IGNORECASE | re.DOTALL))
        status = PASS if (motd_on and has_content) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="message motd on + msgvalue set", actual=out[:120],
                               remediation='set message motd on msgvalue "Unauthorized access prohibited"'))

    def check_2_1_3(self):
        cid, desc, level = "2.1.3", "Ensure Core Dump is enabled", "L1"
        out = self._cmd("show core-dump status")
        status = PASS if 'enable' in out.lower() else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="enabled", actual=out,
                               remediation="set core-dump enable"))

    def check_2_1_4(self):
        cid, desc, level = "2.1.4", "Ensure Config-state is saved", "L1"
        self._manual(cid, desc, level,
                     notes="Run 'show config-state' manually. If unsaved, run 'save config'.",
                     remediation="save config")

    def check_2_1_5(self):
        cid, desc, level = "2.1.5", "Ensure unused interfaces are disabled", "L1"
        out = self._cmd("show interfaces all")
        self._add(make_result(cid, desc, level, MANUAL,
                               actual=out[:300],
                               notes="Review output and disable unused interfaces.",
                               remediation="set interface <Interface_Number> state off"))

    def check_2_1_6(self):
        cid, desc, level = "2.1.6", "Ensure DNS server is configured", "L1"
        primary   = self._cmd("show dns primary")
        secondary = self._cmd("show dns secondary")
        p_ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', primary)
        s_ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', secondary)
        status = PASS if p_ip and s_ip else FAIL
        actual = f"primary={p_ip.group(1) if p_ip else 'NOT SET'}, secondary={s_ip.group(1) if s_ip else 'NOT SET'}"
        self._add(make_result(cid, desc, level, status,
                               expected="Primary and Secondary DNS set", actual=actual,
                               remediation="set dns primary <IP> ; set dns secondary <IP>"))

    def check_2_1_7(self):
        cid, desc, level = "2.1.7", "Ensure IPv6 is disabled if not used", "L1"
        out = self._cmd("show ipv6-state")
        val = self._extract_value(out, r'(on|off)') or out
        status = PASS if val.lower() == 'off' else MANUAL
        notes = "" if status == PASS else "IPv6 is enabled. Verify this is intentional."
        self._add(make_result(cid, desc, level, status,
                               expected="off (if not used)", actual=val,
                               remediation="set ipv6-state off",
                               notes=notes))

    def check_2_1_8(self):
        cid, desc, level = "2.1.8", "Ensure Host Name is set", "L1"
        out = self._cmd("show hostname")
        val = out.strip()
        status = PASS if val and val not in ('', 'localhost', 'gaia') else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="Non-default hostname", actual=val,
                               remediation="set hostname <descriptive-name>"))

    def check_2_1_9(self):
        cid, desc, level = "2.1.9", "Ensure Telnet is disabled", "L1"
        out = self._cmd("show net-access telnet")
        val = self._extract_value(out, r'(on|off)') or out
        status = PASS if val.lower() == 'off' else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="off", actual=val,
                               remediation="set net-access telnet off"))

    def check_2_1_10(self):
        cid, desc, level = "2.1.10", "Ensure DHCP is disabled", "L1"
        out = self._cmd("show dhcp server status")
        status = FAIL if re.search(r'enable', out, re.IGNORECASE) else PASS
        self._add(make_result(cid, desc, level, status,
                               expected="DHCP Server Disabled", actual=out,
                               remediation="set dhcp server disable"))

    # -----------------------------------------------------------------------
    # Section 2.2 – SNMP
    # -----------------------------------------------------------------------
    def check_2_2_1(self):
        cid, desc, level = "2.2.1", "Ensure SNMP agent is disabled (or v3-only)", "L1"
        out = self._cmd("show snmp agent")
        agent_off = bool(re.search(r'disabled', out, re.IGNORECASE))
        self._snmp_agent_off = agent_off   # used by dependent checks
        status = PASS if agent_off else MANUAL
        notes = "" if agent_off else "SNMP agent is ON. Ensure v3-only is configured (see 2.2.2)."
        self._add(make_result(cid, desc, level, status,
                               expected="disabled (or v3-only if required)", actual=out,
                               remediation="set snmp agent off",
                               notes=notes))

    def check_2_2_2(self):
        cid, desc, level = "2.2.2", "Ensure SNMP version is set to v3-Only", "L1"
        if getattr(self, '_snmp_agent_off', True):
            self._add(make_result(cid, desc, level, SKIPPED,
                                   notes="SNMP agent is disabled; v3-only not applicable."))
            return
        out = self._cmd("show snmp agent-version")
        status = PASS if 'v3' in out.lower() else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="v3-Only", actual=out,
                               remediation="set snmp agent-version v3-Only"))

    def check_2_2_3(self):
        cid, desc, level = "2.2.3", "Ensure SNMP traps are enabled", "L1"
        if getattr(self, '_snmp_agent_off', True):
            self._add(make_result(cid, desc, level, SKIPPED,
                                   notes="SNMP agent is disabled; traps not applicable."))
            return
        out = self._cmd("show snmp traps enabled-traps")
        required = ['authorizationError', 'coldStart', 'configurationChange',
                    'configurationSave', 'linkUpLinkDown', 'lowDiskSpace']
        missing = [t for t in required if t.lower() not in out.lower()]
        status = PASS if not missing else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="All 6 traps enabled", actual=out[:200],
                               notes=f"Missing traps: {missing}" if missing else "",
                               remediation="set snmp traps trap <trapName> enable"))

    def check_2_2_4(self):
        cid, desc, level = "2.2.4", "Ensure SNMP traps receivers is set", "L1"
        if getattr(self, '_snmp_agent_off', True):
            self._add(make_result(cid, desc, level, SKIPPED,
                                   notes="SNMP agent is disabled; trap receivers not applicable."))
            return
        out = self._cmd("show snmp traps receivers")
        has_receiver = bool(re.search(r'trap receiver', out, re.IGNORECASE))
        status = PASS if has_receiver else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="At least one trap receiver configured", actual=out,
                               remediation="add snmp traps receiver <IP> version v3"))

    # -----------------------------------------------------------------------
    # Section 2.3 – NTP
    # -----------------------------------------------------------------------
    def check_2_3_1(self):
        cid, desc, level = "2.3.1", "Ensure NTP is enabled with Primary and Secondary servers", "L1"
        active = self._cmd("show ntp active")
        servers = self._cmd("show ntp servers")
        ntp_on  = bool(re.search(r'\byes\b', active, re.IGNORECASE))
        has_pri = bool(re.search(r'primary', servers, re.IGNORECASE))
        has_sec = bool(re.search(r'secondary', servers, re.IGNORECASE))
        status  = PASS if (ntp_on and has_pri and has_sec) else FAIL
        actual  = f"active={active.strip()}, servers=\n{servers[:200]}"
        self._add(make_result(cid, desc, level, status,
                               expected="NTP active with primary+secondary servers",
                               actual=actual,
                               remediation="set ntp active on ; set ntp server primary <host> version 3 ; set ntp server secondary <host> version 3"))

    def check_2_3_2(self):
        cid, desc, level = "2.3.2", "Ensure timezone is properly configured", "L1"
        out = self._cmd("show timezone")
        status = PASS if out.strip() and 'UTC' in out.upper() or '/' in out else MANUAL
        self._add(make_result(cid, desc, level, MANUAL if '/' not in out else PASS,
                               expected="Organization-appropriate timezone",
                               actual=out,
                               notes="Verify timezone matches organizational policy.",
                               remediation="set timezone <Area> / <Region>"))

    # -----------------------------------------------------------------------
    # Section 2.4 – Backup
    # -----------------------------------------------------------------------
    def check_2_4_1(self):
        self._manual("2.4.1", "Ensure 'System Backup' is set", "L1",
                     notes="Run 'show backup last-successful' to verify.",
                     remediation="add backup local")

    def check_2_4_2(self):
        out = self._cmd("show snapshots")
        has_snap = bool(re.search(r'restore points|snap', out, re.IGNORECASE))
        status = PASS if has_snap else FAIL
        self._add(make_result("2.4.2", "Ensure 'Snapshot' is set", "L1", status,
                               expected="At least one snapshot", actual=out[:200],
                               remediation="add snapshot <name>"))

    def check_2_4_3(self):
        self._manual("2.4.3", "Configuring Scheduled Backups", "L1",
                     notes="Navigate to Maintenance > System Backup > Scheduled Backup.",
                     remediation="Configure via Gaia Portal or 'add backup-scheduled name ...'")

    # -----------------------------------------------------------------------
    # Section 2.5 – Authentication Settings
    # -----------------------------------------------------------------------
    def check_2_5_1(self):
        cid, desc, level = "2.5.1", "Ensure CLI session timeout is set to ≤ 10 minutes", "L1"
        out = self._cmd("show inactivity-timeout")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_le(val, 10) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 10 minutes", actual=val,
                               remediation="set inactivity-timeout 10"))

    def check_2_5_2(self):
        cid, desc, level = "2.5.2", "Ensure Web session timeout is set to ≤ 10 minutes", "L1"
        out = self._cmd("show web session-timeout")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_le(val, 10) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 10 minutes", actual=val,
                               remediation="set web session-timeout 10"))

    def check_2_5_3(self):
        self._manual("2.5.3", "Ensure Client Authentication is secured (HTTPS)", "L1",
                     notes="Verify $FWDIR/conf/fwauthd.conf: port 259 should be commented out "
                           "and port 900 should have ssl:defaultCert.",
                     remediation="Edit $FWDIR/conf/fwauthd.conf in Expert mode.")

    def check_2_5_4(self):
        cid, desc, level = "2.5.4", "Ensure RADIUS or TACACS+ server is configured", "L1"
        tacacs = self._cmd("show aaa tacacs-servers state")
        radius = self._cmd("show aaa radius-servers list")
        tacacs_on  = bool(re.search(r'\bon\b', tacacs, re.IGNORECASE))
        radius_cfg = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', radius))
        status = PASS if (tacacs_on or radius_cfg) else FAIL
        actual = f"TACACS+ state: {tacacs.strip()[:60]} | RADIUS: {radius.strip()[:60]}"
        self._add(make_result(cid, desc, level, status,
                               expected="RADIUS or TACACS+ configured", actual=actual,
                               remediation="set aaa tacacs-servers state on ; add aaa tacacs-servers ..."))

    def check_2_5_5(self):
        cid, desc, level = "2.5.5", "Ensure allowed-client is restricted to necessary hosts", "L2"
        out = self._cmd("show allowed-client all")
        has_any = bool(re.search(r'\bany\b', out, re.IGNORECASE))
        status = MANUAL if has_any else PASS
        notes = "Allowed clients includes 'Any'. Review and restrict to management IPs." if has_any else ""
        self._add(make_result(cid, desc, level, status,
                               expected="Specific management IPs only", actual=out[:200],
                               notes=notes,
                               remediation="delete allowed-client host any-host ; add allowed-client host ipv4-address <IP>"))

    # -----------------------------------------------------------------------
    # Section 2.6 – Logging
    # -----------------------------------------------------------------------
    def check_2_6_1(self):
        cid, desc, level = "2.6.1", "Ensure mgmtauditlogs is set to on", "L1"
        out = self._cmd("show syslog mgmtauditlogs")
        status = PASS if 'enabled' in out.lower() or re.search(r'\bon\b', out, re.IGNORECASE) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="enabled/on", actual=out,
                               remediation="set syslog mgmtauditlogs on"))

    def check_2_6_2(self):
        cid, desc, level = "2.6.2", "Ensure auditlog is set to permanent", "L1"
        out = self._cmd("show syslog auditlog")
        status = PASS if 'permanent' in out.lower() else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="permanent", actual=out,
                               remediation="set syslog auditlog permanent"))

    def check_2_6_3(self):
        cid, desc, level = "2.6.3", "Ensure cplogs is set to on", "L1"
        out = self._cmd("show syslog cplogs")
        status = PASS if 'enabled' in out.lower() or re.search(r'\bon\b', out, re.IGNORECASE) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="on/enabled", actual=out,
                               remediation="set syslog cplogs on"))

    # -----------------------------------------------------------------------
    # Section 3 – Firewall Secure Settings
    # (Many require SmartConsole access or manual verification)
    # -----------------------------------------------------------------------
    def check_3_1(self):
        self._manual("3.1", "Enable the Firewall Stealth Rule", "L2",
                     notes="Verify in SmartConsole that a stealth rule exists at the top of the rulebase.",
                     remediation="Create a rule in SmartConsole that drops all traffic to the gateway.")

    def check_3_2(self):
        self._manual("3.2", "Configure a Default Drop/Cleanup Rule", "L2",
                     notes="Verify in SmartConsole that the last rule drops all traffic.",
                     remediation="Create a cleanup rule as the last rule in the rulebase.")

    def check_3_3(self):
        self._manual("3.3", "Use Checkpoint Sections and Titles", "L1",
                     notes="Verify in SmartConsole that the policy uses sections with descriptive titles.",
                     remediation="Organize rules into sections in SmartConsole.")

    def _check_global_prop_via_api(self, cid, desc, level, api_field, expected_val, remediation):
        """Generic helper for Global Properties checks via CP MGMT API."""
        if not self.mgmt:
            self._manual(cid, desc, level,
                         notes="CP Management API not connected. Verify manually in SmartConsole.",
                         remediation=remediation)
            return None
        try:
            resp = self.mgmt.api_call("show-generic-objects",
                                      {"class-name": "com.checkpoint.objects.classes.dummy.CpmiFirewallProperties",
                                       "details-level": "full"})
            if resp.success and resp.data.get('objects'):
                obj = resp.data['objects'][0]
                actual = obj.get(api_field)
                status = PASS if actual == expected_val else FAIL
                self._add(make_result(cid, desc, level, status,
                                       expected=expected_val, actual=actual,
                                       remediation=remediation))
            else:
                self._manual(cid, desc, level,
                             notes="Unable to retrieve Global Properties.",
                             remediation=remediation)
        except Exception as e:
            self._manual(cid, desc, level,
                         notes=f"API error: {e}",
                         remediation=remediation)

    def check_3_4(self):
        cid, desc, level = "3.4", "Ensure Hit Count is enabled for the rules", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'enableHitCount', True,
                                         "In SmartConsole > Global Properties > Hit Count: enable 'Enable Hit Count'")
        if not self.mgmt:
            return
        # If API not available, stay as manual
        existing = next((r for r in self.results if r['control_id'] == cid), None)
        if existing and existing['status'] == MANUAL:
            pass  # already added

    def check_3_5(self):
        self._manual("3.5", "Ensure no Allow Rule with Any in Destination", "L2",
                     notes="Review rulebase in SmartConsole for rules with Any in destination.",
                     remediation="Replace 'Any' in destination with specific network objects.")

    def check_3_6(self):
        self._manual("3.6", "Ensure no Allow Rule with Any in Source", "L2",
                     notes="Review rulebase in SmartConsole for rules with Any in source.",
                     remediation="Replace 'Any' in source with specific network objects.")

    def check_3_7(self):
        self._manual("3.7", "Ensure no Allow Rule with Any in Services", "L2",
                     notes="Review rulebase in SmartConsole for rules with Any in services.",
                     remediation="Replace 'Any' in services with specific service objects.")

    def check_3_8(self):
        self._manual("3.8", "Logging should be enabled for all Firewall Rules", "L2",
                     notes="Review Track field in all firewall rules in SmartConsole.",
                     remediation="Set Track field to 'Log' for all rules in SmartConsole.")

    def check_3_9(self):
        cid, desc, level = "3.9", "Review and Log Implied Rules", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'logImpliedRules', True,
                                         "In SmartConsole > Global Properties > Firewall: enable 'Log Implied Rules'")
        # Fallback
        if not self.mgmt:
            pass

    def check_3_10(self):
        cid, desc, level = "3.10", "Ensure Drop Out of State TCP Packets is enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'dropOutOfStateTcpPackets', True,
                                         "SmartConsole > Global Properties > Stateful Inspection: enable Drop Out of State TCP Packets")

    def check_3_11(self):
        cid, desc, level = "3.11", "Ensure Drop Out of State ICMP Packets is enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'dropOutOfStateIcmpPackets', True,
                                         "SmartConsole > Global Properties > Stateful Inspection: enable Drop Out of State ICMP Packets")

    def check_3_12(self):
        cid, desc, level = "3.12", "Ensure Anti-Spoofing is enabled (Prevent) on all interfaces", "L2"
        out = self._cmd("show interfaces all")
        self._add(make_result(cid, desc, level, MANUAL,
                               actual=out[:300],
                               notes="Verify Anti-Spoofing is set to 'Prevent' on each interface in SmartConsole.",
                               remediation="SmartConsole > Gateway object > Network Management > Interface > General > set Anti-Spoofing to Prevent"))

    def check_3_13(self):
        self._manual("3.13", "Ensure Disk Space Alert is set", "L1",
                     notes="SmartConsole > Gateway > Logs > Local Storage: configure disk space alert.",
                     remediation="Configure disk space alert in SmartConsole.")

    def check_3_14(self):
        cid, desc, level = "3.14", "Ensure Accept RIP is not enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'acceptRip', False,
                                         "SmartConsole > Gateway > Firewall: uncheck 'Accept RIP'")

    def check_3_15(self):
        cid, desc, level = "3.15", "Ensure Accept Domain Name over TCP (Zone Transfer) is not enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'acceptDomainNameOverTcp', False,
                                         "SmartConsole > Gateway > Firewall: uncheck 'Accept Domain Name over TCP'")

    def check_3_16(self):
        cid, desc, level = "3.16", "Ensure Accept Domain Name over UDP (Queries) is not enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'acceptDomainNameOverUdp', False,
                                         "SmartConsole > Gateway > Firewall: uncheck 'Accept Domain Name over UDP'")

    def check_3_17(self):
        cid, desc, level = "3.17", "Ensure Accept ICMP Requests is not enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'acceptIcmpRequests', False,
                                         "SmartConsole > Gateway > Firewall: uncheck 'Accept ICMP Requests'")

    def check_3_18(self):
        cid, desc, level = "3.18", "Ensure Allow bi-directional NAT is enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'allowBidirectionalNat', True,
                                         "SmartConsole > Gateway > NAT: check 'Allow bi-directional NAT'")

    def check_3_19(self):
        cid, desc, level = "3.19", "Ensure Automatic ARP Configuration NAT is enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'automaticArpConfiguration', True,
                                         "SmartConsole > Gateway > NAT: check 'Automatic ARP Configuration'")

    def check_3_20(self):
        self._manual("3.20", "Ensure Logging is enabled for Track Options of Global Properties", "L1",
                     notes="Verify in SmartConsole > Global Properties > Log and Alert > Track Options.",
                     remediation="Set logging for VPN, IP Options, Admin Notifications, SAM, etc. in Global Properties.")

    # -----------------------------------------------------------------------
    # Run all checks
    # -----------------------------------------------------------------------
    def run_all(self, level_filter="all"):
        """Execute all checks, filtered by level."""
        checks = [
            self.check_1_1,  self.check_1_2,  self.check_1_3,
            self.check_1_4_history_checking, self.check_1_4_history_length,
            self.check_1_5,  self.check_1_6,  self.check_1_7,
            self.check_1_8,  self.check_1_9,  self.check_1_10,
            self.check_1_11, self.check_1_12, self.check_1_13,
            self.check_2_1_1, self.check_2_1_2, self.check_2_1_3,
            self.check_2_1_4, self.check_2_1_5, self.check_2_1_6,
            self.check_2_1_7, self.check_2_1_8, self.check_2_1_9,
            self.check_2_1_10,
            self.check_2_2_1, self.check_2_2_2, self.check_2_2_3, self.check_2_2_4,
            self.check_2_3_1, self.check_2_3_2,
            self.check_2_4_1, self.check_2_4_2, self.check_2_4_3,
            self.check_2_5_1, self.check_2_5_2, self.check_2_5_3,
            self.check_2_5_4, self.check_2_5_5,
            self.check_2_6_1, self.check_2_6_2, self.check_2_6_3,
            self.check_3_1,  self.check_3_2,  self.check_3_3,  self.check_3_4,
            self.check_3_5,  self.check_3_6,  self.check_3_7,  self.check_3_8,
            self.check_3_9,  self.check_3_10, self.check_3_11, self.check_3_12,
            self.check_3_13, self.check_3_14, self.check_3_15, self.check_3_16,
            self.check_3_17, self.check_3_18, self.check_3_19, self.check_3_20,
        ]
        for fn in checks:
            try:
                fn()
            except Exception as e:
                cid = fn.__name__.replace('check_', '').replace('_', '.')
                self._error(cid, fn.__name__, "?", str(e))

        # Apply level filter
        if level_filter == "1":
            self.results = [r for r in self.results if r['level'] in ('L1', '?')]
        elif level_filter == "2":
            self.results = [r for r in self.results if r['level'] == 'L2']


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
SECTION_TITLES = {
    "1":   "Password Policy",
    "2.1": "Device Setup – General Settings",
    "2.2": "Device Setup – SNMP",
    "2.3": "Device Setup – NTP",
    "2.4": "Device Setup – Backup",
    "2.5": "Device Setup – Authentication Settings",
    "2.6": "Device Setup – Logging",
    "3":   "Firewall Secure Settings",
}

def get_section(cid):
    parts = cid.split('.')
    for key in ['2.1', '2.2', '2.3', '2.4', '2.5', '2.6']:
        if cid.startswith(key):
            return key
    return parts[0]


def print_report(results, target):
    counts = {PASS: 0, FAIL: 0, MANUAL: 0, SKIPPED: 0, ERROR: 0}
    for r in results:
        counts[r['status']] = counts.get(r['status'], 0) + 1

    print()
    print(colorize("=" * 70, CYAN))
    print(colorize(f"  CIS Check Point Firewall Benchmark v1.1.0 – Audit Report", BOLD))
    print(colorize(f"  Target : {target}", BOLD))
    print(colorize(f"  Time   : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", BOLD))
    print(colorize("=" * 70, CYAN))

    current_section = None
    for r in results:
        sec = get_section(r['control_id'])
        if sec != current_section:
            current_section = sec
            title = SECTION_TITLES.get(sec, f"Section {sec}")
            print()
            print(colorize(f"  ── {title} ──", BOLD))
        icon = STATUS_ICON.get(r['status'], r['status'])
        line = f"  [{r['control_id']:6s}] {icon}  {r['description']}"
        print(line)
        if r['status'] == FAIL:
            print(colorize(f"           Expected : {r['expected']}", DIM))
            print(colorize(f"           Actual   : {str(r['actual'])[:80]}", RED))
            if r['remediation']:
                print(colorize(f"           Fix      : {r['remediation']}", YELLOW))
        elif r['status'] == MANUAL:
            if r['notes']:
                print(colorize(f"           Note     : {r['notes'][:100]}", YELLOW))
        elif r['status'] == ERROR:
            print(colorize(f"           Error    : {r['notes'][:80]}", RED))

    print()
    print(colorize("=" * 70, CYAN))
    total = len(results)
    pct   = round(counts[PASS] / total * 100, 1) if total else 0
    print(colorize(f"  SUMMARY  Total:{total}  "
                   f"Pass:{counts[PASS]}  Fail:{counts[FAIL]}  "
                   f"Manual:{counts[MANUAL]}  Skipped:{counts[SKIPPED]}  "
                   f"Error:{counts[ERROR]}  "
                   f"Score:{pct}%", BOLD))
    print(colorize("=" * 70, CYAN))
    print()


def write_json_report(results, target, output_file):
    report = {
        "meta": {
            "benchmark": "CIS Check Point Firewall Benchmark v1.1.0",
            "target":    target,
            "generated": datetime.datetime.utcnow().isoformat() + "Z",
            "tool":      "cis_gaia_audit_tool",
        },
        "summary": {
            PASS:    sum(1 for r in results if r['status'] == PASS),
            FAIL:    sum(1 for r in results if r['status'] == FAIL),
            MANUAL:  sum(1 for r in results if r['status'] == MANUAL),
            SKIPPED: sum(1 for r in results if r['status'] == SKIPPED),
            ERROR:   sum(1 for r in results if r['status'] == ERROR),
            "total": len(results),
        },
        "results": results,
    }
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(colorize(f"  JSON report saved → {os.path.abspath(output_file)}", CYAN))


# ---------------------------------------------------------------------------
# Argument parsing (mirrors policyCleanUp.py style)
# ---------------------------------------------------------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="CIS Check Point Firewall Benchmark v1.1.0 Audit Tool",
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('--management', '-m', default='127.0.0.1', metavar="",
                        help='Management server IP address or hostname. Default: 127.0.0.1')
    parser.add_argument('--port', default=22, type=int, metavar="",
                        help='SSH port. Default: 22')
    parser.add_argument('--api-port', default=443, type=int, metavar="",
                        help='Management API HTTPS port. Default: 443')
    parser.add_argument('--user', '-u', dest='username', metavar="",
                        help='Gaia/Management administrator username.')
    parser.add_argument('--password', '-p', metavar="",
                        help='Administrator password.')
    parser.add_argument('--api-key', metavar="",
                        help='Management API key (used for API checks, not SSH).')
    parser.add_argument('--level', choices=['1', '2', 'all'], default='all', metavar="",
                        help='{1|2|all}  CIS level filter. Default: all')
    parser.add_argument('--output-file', '-o', default=None, metavar="",
                        help='Output JSON report file. Default: cis_audit_<timestamp>.json')
    parser.add_argument('--no-api', action='store_true',
                        help='Skip Management API checks (SSH only).')
    parser.add_argument('--domain', '-d', metavar="",
                        help='Management domain (for MDS environments).')

    args = parser.parse_args()

    # Prompt for username if missing
    if args.api_key is None:
        if args.username is None:
            try:
                args.username = input("Username: ")
            except EOFError:
                args.username = "admin"
        if args.password is None:
            if sys.stdin.isatty():
                args.password = getpass.getpass("Password: ")
            else:
                args.password = input("Password: ")

    if args.output_file is None:
        ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        args.output_file = f"cis_audit_{ts}.json"

    return args


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_arguments()
    target = args.management

    print(colorize(f"\n[*] CIS Gaia R82 Audit Tool", BOLD))
    print(colorize(f"[*] Target  : {target}:{args.port}", CYAN))
    print(colorize(f"[*] Level   : {args.level}", CYAN))
    print()

    # ------------------------------------------------------------------
    # 1. SSH / Gaia Clish connection
    # ------------------------------------------------------------------
    if not HAS_PARAMIKO:
        print(colorize("[!] paramiko not installed. Run: pip install paramiko --break-system-packages", RED))
        sys.exit(1)

    print(colorize("[*] Connecting via SSH...", CYAN))
    ssh = GaiaClishSession(target, port=args.port)
    try:
        ssh.connect(username=args.username, password=args.password)
        print(colorize("[✓] SSH connected.", GREEN))
    except Exception as e:
        print(colorize(f"[✗] SSH connection failed: {e}", RED))
        sys.exit(1)

    # ------------------------------------------------------------------
    # 2. Optional Management API connection
    # ------------------------------------------------------------------
    mgmt_client = None
    if not args.no_api and HAS_CPAPI:
        print(colorize("[*] Connecting to Management API...", CYAN))
        try:
            client_args = APIClientArgs(server=target, port=args.api_port)
            mgmt_client = APIClient(client_args)
            # check_fingerprint is non-interactive; skip cert check for audit
            mgmt_client.check_fingerprint = lambda: True
            if args.api_key:
                login_res = mgmt_client.login_with_api_key(args.api_key,
                                                            domain=args.domain,
                                                            read_only=True)
            else:
                login_res = mgmt_client.login(args.username, args.password,
                                               domain=args.domain, read_only=True)
            if login_res.success:
                print(colorize("[✓] Management API connected.", GREEN))
            else:
                print(colorize(f"[!] API login failed: {login_res.error_message}. API checks will be skipped.", YELLOW))
                mgmt_client = None
        except Exception as e:
            print(colorize(f"[!] API connection error: {e}. API checks will be skipped.", YELLOW))
            mgmt_client = None
    elif args.no_api:
        print(colorize("[*] Management API skipped (--no-api).", DIM))
    elif not HAS_CPAPI:
        print(colorize("[*] cp_mgmt_api_python_sdk not found. API checks will be MANUAL.", YELLOW))

    # ------------------------------------------------------------------
    # 3. Run audit
    # ------------------------------------------------------------------
    print(colorize("[*] Running audit checks...\n", CYAN))
    audit = CISAudit(ssh_session=ssh, mgmt_client=mgmt_client)
    audit.run_all(level_filter=args.level)

    ssh.close()
    if mgmt_client:
        try:
            mgmt_client.api_call("logout")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 4. Report
    # ------------------------------------------------------------------
    print_report(audit.results, target)
    write_json_report(audit.results, target, args.output_file)


if __name__ == "__main__":
    main()
