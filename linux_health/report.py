from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from .checks import CheckResult, SystemInfo, DetailedSecurityInfo
from .scanner import PortStatus

STATUS_ICON = {
    "pass": "✅",
    "warn": "⚠️",
    "fail": "❌",
}

STATUS_SYMBOL = {
    "pass": "[PASS]",
    "warn": "[WARN]",
    "fail": "[FAIL]",
}


def _status_icon(status: str) -> str:
    return STATUS_ICON.get(status, "⬜")


def render_report_text(
    system: SystemInfo,
    checks: Iterable[CheckResult],
    ports: Iterable[PortStatus],
    detailed: DetailedSecurityInfo | None = None,
) -> str:
    """Render a clean text-based report."""
    checks_list = list(checks)
    ports_list = list(ports)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    total = len(checks_list)
    passed = sum(1 for c in checks_list if c.status == "pass")
    warned = sum(1 for c in checks_list if c.status == "warn")
    failed = sum(1 for c in checks_list if c.status == "fail")

    sep = "=" * 80

    lines: list[str] = []
    lines.append(sep)
    lines.append(f"LINUX HOST HEALTH REPORT: {system.hostname.upper()}")
    lines.append(sep)
    lines.append(f"Generated: {ts}\n")

    lines.append("SYSTEM INFORMATION")
    lines.append("-" * 80)
    lines.append(f"  Hostname:      {system.hostname}")
    lines.append(f"  OS:            {system.os}")
    lines.append(f"  Kernel:        {system.kernel}")
    lines.append(f"  Uptime:        {system.uptime}")
    lines.append(f"  Logged-in:     {system.users}\n")

    lines.append("SUMMARY")
    lines.append("-" * 80)
    lines.append(f"  Total Checks:  {total}")
    lines.append(f"  ✅ Passed:     {passed}")
    lines.append(f"  ⚠️  Warnings:   {warned}")
    lines.append(f"  ❌ Failed:     {failed}")
    open_ports = [p.port for p in ports_list if p.open]
    ports_info = f"({', '.join(map(str, open_ports))})" if open_ports else "(none)"
    lines.append(f"  Open Ports:    {len(open_ports)} {ports_info}\n")

    lines.append("HEALTH CHECKS")
    lines.append("-" * 80)
    # Sort by status: fail, warn, pass
    status_order = {"fail": 0, "warn": 1, "pass": 2}
    sorted_checks = sorted(
        checks_list, key=lambda c: status_order.get(c.status.lower(), 3)
    )
    for check in sorted_checks:
        status_sym = STATUS_SYMBOL.get(check.status, "????")
        lines.append(f"{status_sym} {check.item:<25} | {check.category}")
        lines.append(f"    Details: {check.details}")
        lines.append(f"    Action:  {check.recommendation}\n")

    lines.append("PORT SCAN RESULTS")
    lines.append("-" * 80)
    open_only = [p for p in ports_list if p.open]
    if not open_only:
        lines.append("  No open ports found (all scanned ports were closed/filtered)")
    else:
        for port in open_only:
            lines.append(f"  Port {port.port:5d}  OPEN      {port.reason or ''}")
    lines.append("")

    if detailed:
        lines.append("DETAILED SECURITY FINDINGS")
        lines.append("-" * 80)

        lines.append("\nTOP PROCESSES BY CPU/MEMORY")
        lines.append("~" * 80)
        for line in detailed.top_processes.splitlines()[:20]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("DISK USAGE BY DIRECTORY")
        lines.append("~" * 80)
        for line in detailed.disk_usage_dirs.splitlines()[:20]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("AVAILABLE UPDATES")
        lines.append("~" * 80)
        lines.append(f"  {detailed.available_updates}")
        lines.append("")

        lines.append("FIREWALL RULES/STATUS")
        lines.append("~" * 80)
        for line in detailed.firewall_rules.splitlines()[:15]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("SSH DAEMON CONFIG CHECK")
        lines.append("~" * 80)
        for line in detailed.sshd_config_check.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("FAILED SYSTEMD UNITS")
        lines.append("~" * 80)
        for line in detailed.failed_systemd_units.splitlines()[:10]:
            lines.append(f"  {line}")
        if not detailed.failed_systemd_units.strip():
            lines.append("  No failed units")
        lines.append("")

        lines.append("SUDOERS CONFIGURATION")
        lines.append("~" * 80)
        for line in detailed.sudoers_info.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("CRITICAL FILE PERMISSIONS")
        lines.append("~" * 80)
        for line in detailed.critical_file_permissions.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

        if detailed.rootkit_scan is not None:
            lines.append("RKHUNTER ROOTKIT SCAN")
            lines.append("~" * 80)
            for line in detailed.rootkit_scan.splitlines()[:30]:
                lines.append(f"  {line}")
            if len(detailed.rootkit_scan.splitlines()) > 30:
                lines.append(
                    f"  ... (showing first 30 of {len(detailed.rootkit_scan.splitlines())} lines)"
                )
            lines.append("")

        if detailed.unused_packages is not None:
            lines.append("PACKAGE HYGIENE")
            lines.append("~" * 80)
            for line in detailed.unused_packages.splitlines()[:30]:
                lines.append(f"  {line}")
            if len(detailed.unused_packages.splitlines()) > 30:
                lines.append(
                    f"  ... (showing first 30 of {len(detailed.unused_packages.splitlines())} lines)"
                )
            lines.append("")

        lines.append("SUID BINARIES (recent activity)")
        lines.append("~" * 80)
        for line in detailed.suid_binaries.splitlines()[:15]:
            lines.append(f"  {line}")
        if len(detailed.suid_binaries.splitlines()) > 15:
            lines.append(
                f"  ... and {len(detailed.suid_binaries.splitlines()) - 15} more"
            )
        lines.append("")

        lines.append("RECENT ROOT LOGINS")
        lines.append("~" * 80)
        for line in detailed.root_logins.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("SUCCESSFUL SSH LOGINS (last 7 days)")
        lines.append("~" * 80)
        for line in detailed.successful_ssh_logins.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

        lines.append("FAILED SSH LOGIN ATTEMPTS (last 7 days)")
        lines.append("~" * 80)
        for line in detailed.failed_ssh_logins.splitlines()[:10]:
            lines.append(f"  {line}")
        lines.append("")

    lines.append("RECOMMENDED NEXT STEPS")
    lines.append("-" * 80)
    lines.append(
        "  • ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head     (inspect top processes)"
    )
    lines.append(
        "  • sudo du -xhd1 / | sort -h                        (disk usage by directory)"
    )
    lines.append(
        "  • sudo apt-get update && apt-get upgrade           (apply security updates)"
    )
    lines.append(
        "  • sudo ufw status verbose                          (review firewall rules)"
    )
    lines.append(
        "  • sudo sshd -T                                     (verify SSH config)"
    )
    lines.append("")

    lines.append(sep)
    lines.append("End of Report")
    lines.append(sep)

    return "\n".join(lines)


def render_report(
    system: SystemInfo,
    checks: Iterable[CheckResult],
    ports: Iterable[PortStatus],
    detailed: DetailedSecurityInfo | None = None,
) -> str:
    checks_list = list(checks)
    ports_list = list(ports)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    total = len(checks_list)
    passed = sum(1 for c in checks_list if c.status == "pass")
    warned = sum(1 for c in checks_list if c.status == "warn")
    failed = sum(1 for c in checks_list if c.status == "fail")

    lines: list[str] = []
    lines.append(f"# Linux Host Health Report: {system.hostname}")
    lines.append("")
    lines.append(f"Generated: {ts}")
    lines.append("")
    lines.append("## System")
    lines.append(f"- Hostname: {system.hostname}")
    lines.append(f"- OS: {system.os}")
    lines.append(f"- Kernel: {system.kernel}")
    lines.append(f"- Uptime: {system.uptime}")
    lines.append(f"- Logged-in users: {system.users}")
    lines.append("")

    lines.append("## Summary")
    lines.append(f"- Checks: {total} (✅ {passed} / ⚠️ {warned} / ❌ {failed})")
    open_ports = [p.port for p in ports_list if p.open]
    lines.append(
        f"- Open ports (scanned): {len(open_ports)} -> {', '.join(map(str, open_ports)) if open_ports else 'none'}"
    )
    lines.append("")

    lines.append("## Checklist")
    lines.append("| Status | Item | Details | Recommendation | Category |")
    lines.append("| --- | --- | --- | --- | --- |")
    # Sort by status: fail, warn, pass
    status_order = {"fail": 0, "warn": 1, "pass": 2}
    sorted_checks = sorted(
        checks_list, key=lambda c: status_order.get(c.status.lower(), 3)
    )
    for check in sorted_checks:
        lines.append(
            f"| {_status_icon(check.status)} {check.status.upper()} | {check.item} | {check.details} | {check.recommendation} | {check.category} |"
        )
    lines.append("")

    lines.append("## Port Scan (lightweight)")
    lines.append("| Port | State | Notes |")
    lines.append("| --- | --- | --- |")
    open_only = [p for p in ports_list if p.open]
    if not open_only:
        lines.append(
            "| none | closed/filtered | No open ports found (all scanned ports were closed/filtered) |"
        )
    else:
        for port in open_only:
            lines.append(f"| {port.port} | open | {port.reason or ''} |")
    lines.append("")

    if detailed:
        lines.append("## Detailed Security Findings")
        lines.append("")
        lines.append("### Top Processes by CPU/Memory")
        lines.append("```")
        lines.append(detailed.top_processes)
        lines.append("```")
        lines.append("")
        lines.append("### Disk Usage by Directory")
        lines.append("```")
        lines.append(detailed.disk_usage_dirs)
        lines.append("```")
        lines.append("")
        lines.append("### Available Updates")
        lines.append(detailed.available_updates)
        lines.append("")
        lines.append("### Firewall Rules/Status")
        lines.append("```")
        lines.append(detailed.firewall_rules)
        lines.append("```")
        lines.append("")
        lines.append("### SSH Daemon Configuration Check")
        lines.append("```")
        lines.append(detailed.sshd_config_check)
        lines.append("```")
        lines.append("")
        lines.append("### Failed Systemd Units")
        lines.append("```")
        lines.append(detailed.failed_systemd_units or "No failed units")
        lines.append("```")
        lines.append("")
        lines.append("### Sudoers Configuration")
        lines.append("```")
        lines.append(detailed.sudoers_info)
        lines.append("```")
        lines.append("")
        lines.append("### Critical File Permissions")
        lines.append("```")
        lines.append(detailed.critical_file_permissions)
        lines.append("```")
        lines.append("")
        if detailed.rootkit_scan is not None:
            lines.append("### Rkhunter Rootkit Scan")
            lines.append("```")
            lines.append(detailed.rootkit_scan)
            lines.append("```")
            lines.append("")
        if detailed.unused_packages is not None:
            lines.append("### Package Hygiene & Unused Packages")
            lines.append("```")
            lines.append(detailed.unused_packages)
            lines.append("```")
            lines.append("")
        lines.append("### SUID Binaries (recent activity)")
        lines.append("```")
        lines.append(detailed.suid_binaries)
        lines.append("```")
        lines.append("")
        lines.append("### Recent Root Logins")
        lines.append("```")
        lines.append(detailed.root_logins)
        lines.append("```")
        lines.append("")
        lines.append("### Recent Successful SSH Logins (last 7 days)")
        lines.append("```")
        lines.append(detailed.successful_ssh_logins)
        lines.append("```")
        lines.append("")
        lines.append("### Recent Failed SSH Login Attempts (last 7 days)")
        lines.append("```")
        lines.append(detailed.failed_ssh_logins)
        lines.append("```")
        lines.append("")

    lines.append("## Suggested Next Commands")
    lines.append(
        "- Inspect top CPU/mem: `ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head`"
    )
    lines.append("- Disk usage by dir: `sudo du -xhd1 / | sort -h`")
    lines.append(
        "- Pending updates (Debian/Ubuntu): `sudo apt-get update && sudo apt-get upgrade`"
    )
    lines.append("- Firewall (ufw): `sudo ufw status verbose`")
    lines.append(
        "- SSH hardening: edit `/etc/ssh/sshd_config` then `sudo systemctl reload sshd`"
    )
    lines.append("")
    lines.append(
        "Notes: Port scan is TCP connect scan on provided/common ports; results may be filtered by firewalls."
    )
    return "\n".join(lines)
