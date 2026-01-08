from __future__ import annotations

import argparse
import sys
from pathlib import Path
import getpass

from .checks import (
    gather_system_info,
    run_all_checks,
    gather_suid_binaries,
    gather_root_logins,
    gather_successful_ssh_logins,
    gather_failed_ssh_logins,
    gather_top_processes,
    gather_disk_usage_dirs,
    gather_available_updates,
    gather_firewall_rules,
    gather_sshd_config_check,
    gather_failed_systemd_units,
    gather_sudoers_info,
    gather_critical_file_permissions,
    gather_rkhunter_scan,
    gather_unused_packages,
    DetailedSecurityInfo,
)
from .report import render_report, render_report_text
from .scanner import COMMON_PORTS, scan_ports
from .ssh_client import SSHSession


def parse_ports(raw: str | None) -> list[int]:
    if not raw:
        return COMMON_PORTS
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ports.append(int(part))
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid port: {part}")
    if not ports:
        return COMMON_PORTS
    return ports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Linux host health checker over SSH")
    parser.add_argument("hostname", help="Target host")
    parser.add_argument("username", help="SSH username")
    parser.add_argument("password", help="SSH password (prefer key auth in production; use '-' with --ask-password to prompt)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--scan-ports", dest="scan_ports", type=str, default=None, help="Comma-separated ports to scan; default uses common ports")
    parser.add_argument("--timeout", type=float, default=5.0, help="SSH connect timeout seconds")
    parser.add_argument("--output", type=str, default=None, help="Path to write report; prints to stdout if omitted")
    parser.add_argument("--format", choices=["md", "text"], default="text", help="Report format (md or text)")
    parser.add_argument("--ask-password", action="store_true", help="Prompt for SSH password (ignores positional password if set)")
    parser.add_argument("--enable-rootkit-scan", action="store_true", help="Enable rkhunter rootkit scan (if available on target)")
    parser.add_argument("--check-package-hygiene", action="store_true", help="Check for unused/orphaned packages and bloat")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ports = parse_ports(args.scan_ports)

    password = args.password
    if args.ask_password or password == "-":
        password = getpass.getpass("SSH password: ")

    try:
        with SSHSession(
            hostname=args.hostname,
            username=args.username,
            password=password,
            port=args.port,
            timeout=args.timeout,
        ) as ssh:
            system_info = gather_system_info(ssh)
            check_results = run_all_checks(ssh, password)
            detailed_security = DetailedSecurityInfo(
                suid_binaries=gather_suid_binaries(ssh),
                root_logins=gather_root_logins(ssh),
                successful_ssh_logins=gather_successful_ssh_logins(ssh, password),
                failed_ssh_logins=gather_failed_ssh_logins(ssh, password),
                top_processes=gather_top_processes(ssh),
                disk_usage_dirs=gather_disk_usage_dirs(ssh, password),
                available_updates=gather_available_updates(ssh, password),
                firewall_rules=gather_firewall_rules(ssh, password),
                sshd_config_check=gather_sshd_config_check(ssh, password),
                failed_systemd_units=gather_failed_systemd_units(ssh),
                sudoers_info=gather_sudoers_info(ssh, password),
                critical_file_permissions=gather_critical_file_permissions(ssh),
                rootkit_scan=gather_rkhunter_scan(ssh, password) if args.enable_rootkit_scan else None,
                unused_packages=gather_unused_packages(ssh, password) if args.check_package_hygiene else None,
            )
    except Exception as exc:  # pylint: disable=broad-except
        parser.error(f"SSH failed: {exc}")
        return 2

    port_results = scan_ports(args.hostname, ports)
    if args.format == "text":
        report = render_report_text(system_info, check_results, port_results, detailed_security)
    else:
        report = render_report(system_info, check_results, port_results, detailed_security)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        # Print to stdout with UTF-8 encoding to handle Unicode characters on Windows
        import sys
        sys.stdout.reconfigure(encoding='utf-8')
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
