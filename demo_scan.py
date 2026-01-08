#!/usr/bin/env python3
"""
Demonstration of the enhanced Linux Health security scanner
with all new security checks.
"""

from unittest.mock import Mock, MagicMock
from linux_health.checks import CheckResult, SystemInfo, DetailedSecurityInfo, run_all_checks
from linux_health.report import render_report_text
from linux_health.scanner import PortStatus

# Create mock SSH session
mock_ssh = Mock()

# Mock all check results to simulate a scan
mock_results = []

# Set up the mock to return different values for different commands
mock_ssh.run = MagicMock(side_effect=[
    # System info
    (0, "test-server", ""),  # hostname
    (0, "5.15.0-1234-generic", ""),  # kernel
    (0, "Ubuntu 22.04 LTS", ""),  # os
    (0, "15 days, 3 hours", ""),  # uptime
    (0, "2 users logged in", ""),  # users
    # Then responses for all checks...
])

# Create sample check results to demonstrate output
sample_results = [
    CheckResult("System Resources", "Disk usage", "pass", "Root filesystem at 45%", "Monitor regularly"),
    CheckResult("System Resources", "Memory", "pass", "65% available", "No action needed"),
    CheckResult("System Resources", "System load", "warn", "Load: 1m=2.5, 5m=3.2, 15m=2.1", "Check running processes"),
    CheckResult("Patching", "Pending updates", "fail", "12 packages pending (3 security)", "Apply updates immediately"),
    CheckResult("SSH", "PasswordAuthentication", "warn", "Password authentication enabled", "Use key-based auth"),
    CheckResult("SSH", "PermitRootLogin", "pass", "PermitRootLogin no", "Good security posture"),
    CheckResult("Network Security", "Firewall status", "pass", "UFW enabled", "Continue monitoring"),
    CheckResult("Network Security", "Suspicious connections", "pass", "5 external connections", "Normal for this system"),
    CheckResult("Network Security", "ARP spoofing", "pass", "ARP table clean", "No duplicates detected"),
    CheckResult("Network Security", "DNS tampering", "pass", "DNS OK (8.8.8.8, 8.8.4.4)", "Normal configuration"),
    CheckResult("Authentication", "Auth failures", "warn", "12 failed logins in 24h", "Monitor for brute force"),
    CheckResult("Authentication", "Root logins", "pass", "No recent root logins", "Good"),
    CheckResult("User Accounts", "Active accounts", "pass", "8 user accounts", "Review regularly"),
    CheckResult("User Accounts", "Stale accounts", "pass", "No stale accounts", "All accounts active"),
    CheckResult("Malware/Backdoors", "Reverse shell detection", "pass", "No reverse shells", "System clean"),
    CheckResult("Malware/Backdoors", "Crypto miners", "pass", "No mining processes", "Normal CPU usage"),
    CheckResult("Malware/Backdoors", "Hidden files", "pass", "No hidden system files", "No backdoors detected"),
    CheckResult("Malware/Backdoors", "Deleted file handles", "pass", "No rootkit indicators", "Clean"),
    CheckResult("File Integrity", "Critical binary integrity", "pass", "No recent modifications", "System intact"),
    CheckResult("File Integrity", "World-writable files", "pass", "No insecure files", "Permissions correct"),
    CheckResult("Privilege Escalation", "Escalation vectors", "warn", "NOPASSWD sudo entry found", "Review sudoers"),
    CheckResult("Privilege Escalation", "Sudo version", "pass", "Sudo 1.9.10p1 (current)", "Not vulnerable"),
    CheckResult("Container Security", "Container status", "pass", "Not in container", "Physical/VM system"),
    CheckResult("Log Security", "Log tampering", "pass", "Logs intact (500+ entries)", "Audit trail good"),
    CheckResult("Kernel Security", "Kernel modules", "pass", "42 modules loaded", "All in standard paths"),
    CheckResult("Password Policy", "Password strength", "warn", "minlen=8 (should be 12+)", "Tighten policy"),
    CheckResult("Process Security", "Listening services", "pass", "SSH, HTTP, HTTPS only", "Expected services"),
    CheckResult("Process Security", "Network processes", "pass", "Normal processes only", "No suspicious activity"),
    CheckResult("Scheduled Tasks", "Cron/timers", "pass", "Routine maintenance tasks", "Scheduled appropriately"),
]

# Create mock port scan results
port_results = [
    PortStatus(22, True, "SSH"),
    PortStatus(80, True, "HTTP"),
    PortStatus(443, True, "HTTPS"),
    PortStatus(3306, False, "timeout"),
    PortStatus(5432, False, "timeout"),
]

# Create system info
system = SystemInfo(
    hostname="security-demo.local",
    os="Ubuntu 22.04 LTS",
    kernel="5.15.0-1234-generic",
    uptime="15 days, 3 hours",
    users="2 users"
)

# Create detailed security info
detailed = DetailedSecurityInfo(
    suid_binaries="12 SUID files (normal count)",
    root_logins="None in last 30 days",
    successful_ssh_logins="3 logins from 192.168.1.100",
    failed_ssh_logins="12 failed attempts from various IPs",
    top_processes="python (2.5% CPU), sshd (0.1% CPU), systemd (0.0% CPU)",
    disk_usage_dirs="/var: 12GB, /home: 8GB, /opt: 2GB",
    available_updates="12 packages (3 security updates available)",
    firewall_rules="UFW enabled, SSH allowed, HTTP/HTTPS allowed",
    sshd_config_check="PasswordAuthentication yes, PermitRootLogin no",
    failed_systemd_units="None",
    sudoers_info="%sudo ALL=(ALL) ALL (standard)",
    critical_file_permissions="/etc/passwd: 644 (OK), /etc/shadow: 640 (OK)",
    rootkit_scan="Rkhunter scan: No rootkits detected",
    unused_packages="build-essential (can be removed if not needed)"
)

# Generate and display report
report = render_report_text(system, sample_results, port_results, detailed)

print(report)

# Save to file
with open("security_scan_demo.txt", "w", encoding="utf-8") as f:
    f.write(report)

print("\n" + "="*80)
print("Report saved to security_scan_demo.txt")
print("="*80)
