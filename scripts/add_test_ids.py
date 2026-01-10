#!/usr/bin/env python3
"""Script to add test IDs to all check functions in checks.py"""

import re

# Map of check function names to test IDs (Lynis-inspired)
TEST_ID_MAP = {
    "check_disk_usage": "STOR-6310",
    "check_memory": "MEM-2914",
    "check_load": "CPU-1620",
    "check_reboot_required": "KERN-5830",
    "check_updates": "PKGS-7380",
    "check_ssh_config": "SSH-7408",
    "check_firewall": "FIRE-4512",
    "check_time_sync": "TIME-3104",
    "check_accounts": "AUTH-9234",
    "check_auth_failures": "AUTH-9252",
    "check_root_logins": "AUTH-9262",
    "check_listening_services": "NETW-3030",
    "check_abnormal_network_processes": "NETW-3032",
    "check_suspicious_process_locations": "MALW-3280",
    "check_unexpected_sudo_usage": "AUTH-9328",
    "check_recently_created_accounts": "AUTH-9340",
    "check_system_binary_modifications": "FINT-4350",
    "check_failed_login_spike": "AUTH-9408",
    "check_suid_files": "FILE-6310",
    "check_cron_and_timers": "SCHD-7230",
    "check_stale_user_accounts": "AUTH-9408",
    "check_process_resource_usage": "PROC-3612",
    "check_suspicious_network_connections": "NETW-3200",
    "check_hidden_files_in_system_dirs": "FILE-6374",
    "check_kernel_module_integrity": "KRNL-5788",
    "check_active_reverse_shells": "MALW-3288",
    "check_weak_password_policy": "AUTH-9230",
    "check_container_escape_indicators": "CONT-8104",
    "check_arp_spoofing": "NETW-3032",
    "check_dns_tampering": "NETW-3035",
    "check_crypto_miners": "MALW-3292",
    "check_file_integrity_critical_binaries": "FINT-4402",
    "check_log_tampering": "LOGG-2154",
    "check_privilege_escalation_vectors": "AUTH-9283",
    "check_world_writable_system_files": "FILE-7524",
    "check_deleted_file_handles": "PROC-3602",
    "check_boot_loader_password": "BOOT-5122",
    "check_kernel_hardening": "KERN-5820",
    "check_file_integrity_tools": "FINT-4316",
    "check_package_manager_security": "PKGS-7388",
    "check_logging_and_auditing": "LOGG-2138",
    "check_selinux_apparmor": "MACF-6234",
    "check_security_tools": "TOOL-5002",
    "check_filesystem_mounts": "FILE-6310",
    "check_shell_security": "SHLL-6202",
    "check_compiler_presence": "HRDN-7220",
    "check_legacy_services": "INSE-8016",
    "check_usb_storage": "USB-1000",
    "check_web_server_security": "HTTP-6622",
    "check_database_security": "DBS-1804",
    "check_mail_server_security": "MAIL-8816",
    "check_php_security": "PHP-2320",
    "check_dns_configuration": "NAME-4016",
}


def add_test_ids_to_file(filepath: str = "linux_health/checks.py"):
    """Add test_id parameters to all _pass, _warn, _fail calls in checks.py"""

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Track which function we're in
    current_function = None
    lines = content.split("\n")
    modified_lines = []

    for i, line in enumerate(lines):
        # Detect function definition
        func_match = re.match(r"^def (check_\w+)\(", line)
        if func_match:
            current_function = func_match.group(1)

        # Check if this line contains _pass, _warn, or _fail
        if current_function and re.search(r"return _(?:pass|warn|fail)\(", line):
            # Check if test_id already present
            if "test_id=" not in line:
                # Find the test_id for this function
                test_id = TEST_ID_MAP.get(current_function, "")
                if test_id:
                    # Look ahead to find the closing paren
                    j = i
                    while j < len(lines) and ")" not in lines[j]:
                        modified_lines.append(lines[j])
                        j += 1

                    # Add test_id before the closing paren
                    if j < len(lines):
                        close_line = lines[j]
                        # Insert test_id parameter
                        close_line = close_line.replace(")", f', test_id="{test_id}")')
                        modified_lines.append(close_line)

                        # Skip the lines we already processed
                        for k in range(i, j):
                            lines[k] = None  # Mark as processed
                        lines[j] = None
                        continue

        if lines[i] is not None:
            modified_lines.append(line)

    # Write back
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(modified_lines))

    print(f"✓ Added test IDs to {filepath}")


if __name__ == "__main__":
    add_test_ids_to_file()
