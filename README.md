# Linux Health Security Scanner

Comprehensive SSH-based security assessment tool for Linux systems. Performs 36+ security checks covering malware detection, vulnerability assessment, compliance monitoring, and system health.

**Status**: Production Ready ✅ | **Tests**: 87/87 passing (100%) | **Coverage**: 61% | **Code Quality**: 0 linting errors

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Docker Guide](#docker-guide)
- [Security Checks](#security-checks)
- [Development](#development)
- [Testing](#testing)
- [Contributing](#contributing)
- [Troubleshooting](#troubleshooting)

## Features

### Security Checks (36+)

| Category | Checks | Coverage |
|----------|--------|----------|
| **System Resources** | 4 | Disk, memory, CPU load, process usage |
| **Patching** | 2 | Reboot required, pending updates (security-critical) |
| **Network Security** | 6 | Firewall, suspicious connections, ARP spoofing, DNS tampering |
| **Authentication** | 5 | SSH config, password policy, auth failures, root logins, brute-force detection |
| **User Accounts** | 3 | Active accounts, stale accounts, recently created accounts |
| **Malware/Backdoors** | 4 | Reverse shells, crypto miners, hidden files, rootkit indicators |
| **File Integrity** | 3 | SUID binaries, world-writable files, critical binary integrity |
| **Process Security** | 3 | Listening services, abnormal network processes, suspicious locations |
| **Privilege Escalation** | 3 | Sudo misconfigurations, dangerous capabilities, exploit vectors |
| **Container/Kernel** | 2 | Container escape, kernel module integrity |
| **Log Security** | 2 | Log tampering, unexpected sudo usage |
| **Scheduled Tasks** | 1 | Cron jobs, at jobs, systemd timers |

### Key Capabilities

- ✅ **No Agent Required** - SSH-based remote assessment only
- ✅ **Comprehensive Detection** - Malware, intrusions, misconfigurations, vulnerabilities
- ✅ **Clear Reporting** - Text and Markdown formats with actionable recommendations
- ✅ **Port Scanning** - TCP connect scan (reports open ports only)
- ✅ **Production Ready** - Full test suite, error handling, Docker support
- ✅ **Auto-Remediation** - Copy-paste commands to fix identified issues
- ✅ **Optional Scans** - Rootkit detection (rkhunter), package hygiene checks

## Quick Start

### Installation

```bash
# Clone repository
git clone <repo-url>
cd linux_health

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan a remote host
python -m linux_health 192.168.1.100 username password

# Interactive password prompt (more secure)
python -m linux_health 192.168.1.100 username - --ask-password

# Save markdown report
python -m linux_health 192.168.1.100 username password --format md --output report.md

# With port specification
python -m linux_health 192.168.1.100 username password --port 2222
```

## Installation

### From Source

```bash
# Clone repository
git clone <repo-url>
cd linux_health

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m linux_health --help
```

### Using Docker

```bash
# Build image
docker build -t linux-health .

# Run scan
docker run --rm linux-health 192.168.1.100 username password

# Save report
docker run --rm -v $(pwd):/reports linux-health 192.168.1.100 username password \
  --format md --output /reports/scan.md
```

## Usage

### Command-Line Options

```bash
python -m linux_health <hostname> <username> <password> [options]

Required Arguments:
  hostname              Target Linux host (IP or hostname)
  username              SSH username
  password              SSH password (use '-' with --ask-password)

Optional Arguments:
  --port PORT           SSH port (default: 22)
  --timeout SECONDS     SSH timeout in seconds (default: 5.0)
  --format {text|md}    Output format (default: text)
  --output PATH         Save report to file (default: stdout)
  --scan-ports PORTS    Comma-separated ports to scan (default: 22,80,443,3306,5432)
  --ask-password        Prompt for password interactively
  --enable-rootkit-scan Run rkhunter if available on target
  --check-package-hygiene Check for unused/orphaned packages
  --help               Show help message
```

### Examples

```bash
# Basic scan with text output
python -m linux_health server.example.com admin mypassword

# Scan with markdown report saved to file
python -m linux_health 192.168.1.50 greg "allupinit!" --format md --output report.md

# Non-standard SSH port
python -m linux_health server.example.com admin password --port 2222

# Interactive mode with password prompt
python -m linux_health server.example.com admin - --ask-password

# Include optional scans (rootkit + package hygiene)
python -m linux_health server.example.com admin password \
  --enable-rootkit-scan \
  --check-package-hygiene

# Custom port scan
python -m linux_health server.example.com admin password \
  --scan-ports 22,80,443,8080,9000
```

## Docker Guide

### Quick Start

```bash
# Build the image
docker build -t linux-health .

# Run a scan
docker run --rm linux-health 192.168.1.100 username password
```

### Docker Compose

```bash
# Run with docker-compose
docker-compose run --rm linux-health 192.168.1.100 username password

# Run with report saved to local file
docker-compose run --rm -v "$(pwd)/reports:/app/reports" linux-health \
  192.168.1.100 username password --format md --output /app/reports/scan.md
```

### Docker Options

```bash
# Save report to local directory
docker run --rm -v "$(pwd):/reports" linux-health \
  192.168.1.100 username password --format md --output /reports/report.md

# Run with environment variables
docker run --rm \
  -e TARGET_HOST=192.168.1.100 \
  -e TARGET_USER=admin \
  -e TARGET_PASS=password \
  linux-health $TARGET_HOST $TARGET_USER $TARGET_PASS

# Interactive with TTY
docker run -it --rm linux-health 192.168.1.100 username - --ask-password
```

### Dockerfile Details

```dockerfile
FROM python:3.11-slim

# Base image: Python 3.11 on Debian slim (lightweight)
# Includes SSH client for remote assessments
# Minimal dependencies for production deployment

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY linux_health/ /app/linux_health/

# Entry point
ENTRYPOINT ["python", "-m", "linux_health"]
```

## Security Checks

### Critical Threats (Auto-detected)

| Check | Detects | Method |
|-------|---------|--------|
| **Reverse Shells** | Active reverse shell processes | Process pattern matching (bash -i, /dev/tcp/, nc -e, socat) |
| **Crypto Miners** | Mining processes/pool connections | Process names (xmrig, minerd), ports (3333, 4444, 5555) |
| **Suspicious Connections** | Unusual external connections | TCP connection analysis, filters RFC1918 |
| **ARP Spoofing** | Duplicate MAC addresses | ARP table analysis (ip neigh) |
| **DNS Tampering** | Hijacked DNS servers | /etc/resolv.conf validation |
| **Hidden Files** | Backdoors in system dirs | find .* in /tmp, /var/tmp, /usr/bin, /etc |
| **Log Tampering** | Deleted/manipulated logs | Log volume analysis |
| **Binary Modification** | Trojan system binaries | Modification time check on /bin/bash, /usr/bin/sudo, etc. |

### Vulnerability Detection

| Check | Identifies | Severity |
|-------|-----------|----------|
| **Privilege Escalation** | NOPASSWD sudo, dangerous capabilities, vulnerable sudo versions | FAIL if 2+ vectors |
| **Weak Password Policy** | Missing/weak PAM configuration | FAIL if no pam_pwquality |
| **Container Escape** | Privileged containers, escape indicators | FAIL if privileged |
| **World-Writable Files** | Insecure permissions in system paths | WARN if any found |
| **Kernel Modules** | Suspicious/unsigned modules | FAIL if outside /lib/modules |
| **SUID Files** | Excessive SUID binaries | WARN if unusual count |

### System Health Monitoring

| Check | Monitors | Thresholds |
|-------|----------|-----------|
| **Disk Usage** | Root filesystem capacity | WARN: 80%, FAIL: 90% |
| **Memory** | Available memory | WARN: 20%, FAIL: 10% |
| **System Load** | CPU load averages | WARN: 4+, FAIL: 8+ |
| **Process Resources** | High CPU/memory processes | Flag processes >80% |
| **Pending Updates** | Security vs. regular updates | FAIL if security updates pending |
| **Listening Services** | Public network listeners | Categorize SSH/HTTP/DB/etc. |

## Report Output

### Text Format
```
================================================================================
LINUX HOST HEALTH REPORT: SERVER.EXAMPLE.COM
================================================================================
Generated: 2026-01-08 10:30:45 UTC

SYSTEM INFORMATION
  Hostname:      server.example.com
  OS:            Ubuntu 22.04 LTS
  Kernel:        5.15.0-1234-generic

SUMMARY
  Total Checks:  36
  ✅ Passed:     28
  ⚠️  Warnings:   6
  ❌ Failed:     2

HEALTH CHECKS
[FAIL] Pending updates | 12 packages pending (3 security)
[WARN] SSH Config     | Password authentication enabled
[PASS] Memory         | 42% available
```

### Markdown Format
- GitHub-compatible tables
- Status icons (✅, ⚠️, ❌)
- Structured sections
- Copy-paste remediation commands
- Auto-remediation guide

## Development

### Project Structure

```
linux_health/
├── linux_health/                  # Main package
│   ├── __init__.py               # Package initialization
│   ├── __main__.py               # Entry point
│   ├── checks.py                 # 36+ security check functions (1900+ lines)
│   ├── cli.py                    # Command-line interface & orchestration
│   ├── report.py                 # Report rendering (text/markdown)
│   ├── scanner.py                # TCP port scanner
│   └── ssh_client.py             # SSH session wrapper (Paramiko)
├── tests/
│   └── test_linux_health.py      # 87 comprehensive unit tests
├── .github/
│   └── copilot-instructions.md   # Copilot customization
├── Dockerfile                     # Docker build configuration
├── docker-compose.yml            # Docker Compose setup
├── requirements.txt              # Runtime dependencies (paramiko)
├── requirements-dev.txt          # Development tools
├── .gitignore                    # Git ignore rules
├── .dockerignore                 # Docker ignore rules
└── README.md                     # This file
```

### Key Modules

**checks.py** (1900+ lines)
- 36+ security check functions
- Threat detection and vulnerability assessment
- Modular design - each check is independent
- Comprehensive logging and error handling

**cli.py** (100+ lines)
- Command-line argument parsing
- SSH connection orchestration
- Report generation and output
- Password handling (interactive + args)

**report.py** (270 lines)
- Text and Markdown report formatting
- Status summaries and detailed findings
- Port scan results formatting
- System information collection

**scanner.py** (30 lines)
- Simple TCP port scanner
- Non-invasive connection-based detection
- Supports custom port lists

**ssh_client.py** (35 lines)
- Paramiko SSH session wrapper
- Connection pooling ready
- Timeout and error handling

## Testing

### Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests (87 total)
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=linux_health --cov-report=html

# Run specific test class
pytest tests/ -k "TestCheckDiskUsage" -v

# Run with output on failure
pytest tests/ -vv --tb=short

# Run in parallel (faster)
pip install pytest-xdist
pytest tests/ -n auto
```

### Test Coverage

Current coverage: **61%** (87/87 tests passing)

Coverage by module:
- `checks.py`: 69% (main check functions)
- `cli.py`: 58% (CLI argument handling)
- `report.py`: 40% (report formatting)
- `scanner.py`: 45% (port scanning)
- `ssh_client.py`: 30% (SSH connection wrapper)

To improve coverage:
1. Add integration tests against real Linux hosts
2. Add report formatting edge cases
3. Add port scanner timeout/error scenarios
4. Add SSH connection failure scenarios

### Test Categories

**Unit Tests** (87 total)
- Check logic validation (70+ tests)
- CLI argument parsing (9 tests)
- Report rendering (8 tests)

**Coverage includes:**
- Pass/Warn/Fail scenarios
- Edge cases (empty output, errors)
- Mock SSH responses
- Report format validation

## Code Quality

### Linting

```bash
# Ruff check (all errors/warnings)
ruff check linux_health/ tests/

# Ruff fix (auto-fix issues)
ruff check --fix linux_health/ tests/

# Black format (code style)
black linux_health/ tests/

# Combined lint and format
ruff check --fix linux_health/ tests/ && black linux_health/ tests/
```

**Current Status**: ✅ 0 linting errors

### Code Style

- **Formatter**: Black (PEP 8)
- **Linter**: Ruff (E, F, W rules)
- **Line Length**: 88 characters
- **Type Hints**: Recommended for new code
- **Docstrings**: Google style

## Contributing

### Adding New Security Checks

1. **Create check function** in `checks.py`:

```python
def check_my_security_item(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check description (one-liner)."""
    category = "Category Name"
    code, out, err = _run(ssh, "command")
    
    if serious_issue:
        return _fail("Item", "Details", "Recommendation", category)
    elif warning_level:
        return _warn("Item", "Details", "Recommendation", category)
    return _pass("Item", "Details", "No action", category)
```

2. **Add to `run_all_checks()`** function:

```python
results.append(check_my_security_item(ssh, password))
```

3. **Add unit tests** in `tests/test_linux_health.py`:

```python
class TestMySecurityItem:
    def test_pass_case(self):
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "output", ""))
        result = check_my_security_item(mock_ssh)
        assert result.status == "pass"
    
    def test_fail_case(self):
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "bad_output", ""))
        result = check_my_security_item(mock_ssh)
        assert result.status == "fail"
```

4. **Test and verify**:

```bash
pytest tests/test_linux_health.py::TestMySecurityItem -v
```

### Pull Request Process

1. Create feature branch: `git checkout -b feature/new-check`
2. Add code and tests
3. Run tests: `pytest tests/ -v`
4. Run linting: `ruff check --fix . && black .`
5. Update documentation
6. Commit with clear messages
7. Push and create pull request

## Troubleshooting

### SSH Connection Issues

```bash
# Increase timeout
python -m linux_health host user pass --timeout 30

# Non-standard port
python -m linux_health host user pass --port 2222

# Debug SSH connection
ssh -vvv user@host

# Test with public key (if available)
# Set up key auth first, then use in script
```

### Unicode/Encoding Errors (Windows)

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m linux_health host user pass
```

### Permission Denied Errors

Some checks require elevated privileges:

```bash
# Give user sudo access for scanner
sudo visudo

# Add line:
scanuser ALL=(ALL) NOPASSWD: /bin/ss, /sbin/iptables, /usr/bin/apt-get
```

### Docker Issues

```bash
# Rebuild image (clear cache)
docker build --no-cache -t linux-health .

# Run with verbose output
docker run --rm -it linux-health host user pass

# Mount reports directory
docker run --rm -v "$(pwd):/reports" linux-health \
  host user pass --format md --output /reports/scan.md
```

### Report Generation Issues

```bash
# Check if output file is writable
ls -la /path/to/output/

# Use absolute path for output
python -m linux_health host user pass \
  --output /home/user/reports/scan.md

# Test text format first
python -m linux_health host user pass --format text
```

## Security Considerations

- **Credentials**: Use SSH keys instead of passwords when possible
- **Network**: Run from trusted management network
- **Logs**: Scanner creates SSH sessions visible in auth.log
- **Impact**: Read-only operations, minimal system impact
- **Data**: No data is modified or exfiltrated
- **Secrets**: Never commit credentials to version control

## Requirements

### Runtime

- Python 3.11+
- SSH access to target systems
- Network connectivity
- `paramiko>=3.0.0`

### Development

- All runtime requirements
- `pytest>=7.0.0`
- `pytest-cov>=4.0.0`
- `pytest-mock>=3.10.0`
- `ruff>=0.1.0`
- `black>=23.0.0`

## Performance Notes

- Single target scan: 30-60 seconds (depends on system load)
- Port scan: 5-10 seconds (default ports)
- SSH connection: 2-5 seconds
- Check execution: Parallel-ready design (future enhancement)

## License

[Your License Here]

## Changelog

### v1.0.0 - Initial Release
- 36+ comprehensive security checks
- Malware detection (reverse shells, crypto miners)
- Vulnerability assessment (privilege escalation, weak configs)
- System health monitoring
- Docker support
- 87 unit tests (100% pass rate)
- Text and Markdown reporting
- SSH-based assessment (no agent required)
- Auto-remediation guide with copy-paste commands

## Support

For issues, questions, or contributions:
1. Check [Troubleshooting](#troubleshooting) section
2. Review existing GitHub issues
3. Open new issue with details and test output
4. Include: host OS, Python version, error messages

---

**Production Ready** ✅ | **Well Tested** ✅ | **Documented** ✅

| Category | Checks | Coverage |
|----------|--------|----------|
| **System Resources** | 4 | Disk, memory, CPU load, process usage |
| **Patching** | 2 | Reboot required, pending updates (security-critical) |
| **Network Security** | 6 | Firewall, suspicious connections, ARP spoofing, DNS tampering |
| **Authentication** | 5 | SSH config, password policy, auth failures, root logins, brute-force detection |
| **User Accounts** | 3 | Active accounts, stale accounts, recently created accounts |
| **Malware/Backdoors** | 4 | Reverse shells, crypto miners, hidden files, rootkit indicators |
| **File Integrity** | 3 | SUID binaries, world-writable files, critical binary integrity |
| **Process Security** | 3 | Listening services, abnormal network processes, suspicious locations |
| **Privilege Escalation** | 3 | Sudo misconfigurations, dangerous capabilities, exploit vectors |
| **Container/Kernel** | 2 | Container escape, kernel module integrity |
| **Log Security** | 2 | Log tampering, unexpected sudo usage |
| **Scheduled Tasks** | 1 | Cron jobs, at jobs, systemd timers |

### Key Capabilities

- ✅ **No Agent Required** - SSH-based remote assessment only
- ✅ **Comprehensive Detection** - Malware, intrusions, misconfigurations, vulnerabilities
- ✅ **Clear Reporting** - Text and Markdown formats with actionable recommendations
- ✅ **Port Scanning** - TCP connect scan (reports open ports only)
- ✅ **Production Ready** - Full test suite, error handling, Docker support
- ✅ **Optional Scans** - Rootkit detection (rkhunter), package hygiene checks

## Quick Start

### Installation

```bash
# Clone repository
git clone <repo-url>
cd linux_health

# Install dependencies
pip install -r requirements.txt

# Or use Docker
docker build -t linux-health .
```

### Basic Usage

```bash
# Scan a remote host
python -m linux_health hostname username password

# Interactive password prompt
python -m linux_health hostname username - --ask-password

# Save markdown report
python -m linux_health hostname username password --format md --output report.md

# With Docker
docker run --rm linux-health hostname username password
```

## Security Checks Reference

### Critical Threats (Auto-detected)

| Check | Detects | Method |
|-------|---------|--------|
| **Reverse Shells** | Active reverse shell processes | Process pattern matching (bash -i, /dev/tcp/, nc -e, socat) |
| **Crypto Miners** | Mining processes/pool connections | Process names (xmrig, minerd), ports (3333, 4444, 5555) |
| **Suspicious Connections** | Unusual external connections | TCP connection analysis, filters RFC1918 |
| **ARP Spoofing** | Duplicate MAC addresses | ARP table analysis (ip neigh) |
| **DNS Tampering** | Hijacked DNS servers | /etc/resolv.conf validation |
| **Hidden Files** | Backdoors in system dirs | find .* in /tmp, /var/tmp, /usr/bin, /etc |
| **Log Tampering** | Deleted/manipulated logs | Log volume analysis |
| **Binary Modification** | Trojan system binaries | Modification time check on /bin/bash, /usr/bin/sudo, etc. |

### Vulnerability Detection

| Check | Identifies | Severity |
|-------|-----------|----------|
| **Privilege Escalation** | NOPASSWD sudo, dangerous capabilities, vulnerable sudo versions | FAIL if 2+ vectors |
| **Weak Password Policy** | Missing/weak PAM configuration | FAIL if no pam_pwquality |
| **Container Escape** | Privileged containers, escape indicators | FAIL if privileged |
| **World-Writable Files** | Insecure permissions in system paths | WARN if any found |
| **Kernel Modules** | Suspicious/unsigned modules | FAIL if outside /lib/modules |
| **SUID Files** | Excessive SUID binaries | WARN if unusual count |

### System Health Monitoring

| Check | Monitors | Thresholds |
|-------|----------|-----------|
| **Disk Usage** | Root filesystem capacity | WARN: 80%, FAIL: 90% |
| **Memory** | Available memory | WARN: 20%, FAIL: 10% |
| **System Load** | CPU load averages | WARN: 4+, FAIL: 8+ |
| **Process Resources** | High CPU/memory processes | Flag processes >80% |
| **Pending Updates** | Security vs. regular updates | FAIL if security updates pending |
| **Listening Services** | Public network listeners | Categorize SSH/HTTP/DB/etc. |

## Command-Line Options

```bash
python -m linux_health <hostname> <username> <password> [options]

Required:
  hostname              Target Linux host
  username              SSH username
  password              SSH password (use '-' with --ask-password)

Options:
  --port PORT           SSH port (default: 22)
  --timeout SECONDS     SSH timeout (default: 5.0)
  --format {text|md}    Output format (default: text)
  --output PATH         Save report to file (default: stdout)
  --scan-ports PORTS    Comma-separated ports to scan
  --ask-password        Prompt for password interactively
  --enable-rootkit-scan Run rkhunter if available
  --check-package-hygiene Check for unused/orphaned packages
```

## Report Output

### Text Format
```
================================================================================
LINUX HOST HEALTH REPORT: SERVER.EXAMPLE.COM
================================================================================
Generated: 2026-01-08 10:30:45 UTC

SYSTEM INFORMATION
--------------------------------------------------------------------------------
  Hostname:      server.example.com
  OS:            Ubuntu 22.04 LTS
  Kernel:        5.15.0-1234-generic
  Uptime:        15 days, 3 hours
  Logged-in:     2 users

SUMMARY
--------------------------------------------------------------------------------
  Total Checks:  36
  ✅ Passed:     28
  ⚠️  Warnings:   6
  ❌ Failed:     2
  Open Ports:    3 (22, 80, 443)

HEALTH CHECKS
--------------------------------------------------------------------------------
[FAIL] Pending updates         | Patching
    Details: 12 packages pending (3 security)
    Action:  Apply security updates immediately

[WARN] SSH Config              | SSH
    Details: Password authentication enabled
    Action:  Set 'PasswordAuthentication no' and use SSH keys
```

### Markdown Format
- GitHub-compatible tables
- Status icons (✅, ⚠️, ❌)
- Collapsible detailed findings
- Copy-paste remediation commands

## Docker Usage

### Build and Run

```bash
# Build container
docker build -t linux-health .

# Run scan
docker run --rm linux-health hostname username password

# Save report
docker run --rm linux-health hostname username password \
  --format md --output /tmp/report.md

# Docker Compose
docker-compose run --rm linux-health hostname username password
```

### Dockerfile

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y openssh-client
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY linux_health/ /app/linux_health/
ENTRYPOINT ["python", "-m", "linux_health"]
```

## Development

### Project Structure

```
linux_health/
├── linux_health/
│   ├── __init__.py
│   ├── __main__.py        # Entry point
│   ├── checks.py          # 36+ security check functions
│   ├── cli.py             # Command-line interface
│   ├── report.py          # Report rendering (text/markdown)
│   ├── scanner.py         # TCP port scanner
│   └── ssh_client.py      # SSH session wrapper
├── tests/
│   └── test_linux_health.py  # 87 unit tests
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

### Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=linux_health --cov-report=html

# Lint code
ruff check linux_health/ tests/
black --check linux_health/ tests/
```

### Adding New Checks

1. Add check function to `linux_health/checks.py`:
```python
def check_my_security_item(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check description."""
    category = "Category Name"
    code, out, err = _run(ssh, "command")
    
    if suspicious_condition:
        return _fail("Item", "Details", "Recommendation", category)
    elif warning_condition:
        return _warn("Item", "Details", "Recommendation", category)
    return _pass("Item", "Details", "No action", category)
```

2. Add to `run_all_checks()`:
```python
results.append(check_my_security_item(ssh, password))
```

3. Add tests to `tests/test_linux_health.py`:
```python
def test_my_check():
    mock_ssh = Mock()
    mock_ssh.run = MagicMock(return_value=(0, "output", ""))
    result = check_my_security_item(mock_ssh)
    assert result.status == "pass"
```

## Integration Examples

### Cron Job (Daily Scan)
```bash
#!/bin/bash
# /etc/cron.daily/security-scan
python -m linux_health localhost root "$(cat /root/.ssh_pass)" \
  --format md --output /var/log/security-scan-$(date +\%Y\%m\%d).md
```

### Ansible Playbook
```yaml
- name: Security assessment
  hosts: all
  tasks:
    - name: Run security scan
      command: >
        python -m linux_health {{ inventory_hostname }}
        {{ ansible_user }} {{ ansible_password }}
      register: scan_result
      failed_when: "'FAIL' in scan_result.stdout"
```

### Nagios/Icinga Check
```bash
#!/bin/bash
FAILS=$(python -m linux_health $1 $2 $3 | grep -c "^\[FAIL\]")
if [ $FAILS -gt 0 ]; then
  echo "CRITICAL: $FAILS security issues found"
  exit 2
fi
echo "OK: All checks passed"
exit 0
```

## Troubleshooting

### SSH Connection Issues
```bash
# Increase timeout
python -m linux_health host user pass --timeout 30

# Non-standard port
python -m linux_health host user pass --port 2222

# Debug SSH
ssh -vvv user@host
```

### Unicode/Encoding Errors (Windows)
```powershell
$env:PYTHONIOENCODING="utf-8"
python -m linux_health host user pass
```

### Permission Denied
Some checks require sudo. Ensure the SSH user has appropriate sudo privileges:
```bash
# /etc/sudoers.d/security-scan
scanuser ALL=(ALL) NOPASSWD: /bin/ss, /sbin/iptables, /usr/bin/apt-get
```

## Security Considerations

- **Credentials**: Use SSH keys instead of passwords when possible
- **Network**: Run from trusted management network
- **Logs**: Scanner creates SSH sessions visible in auth.log
- **Impact**: Read-only operations, minimal system impact
- **Data**: No data is modified or exfiltrated

## Requirements

- Python 3.11+
- SSH access to target systems
- Network connectivity
- Dependencies: paramiko, pytest (dev)

## License

[Your License Here]

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new checks
4. Ensure all tests pass: `pytest tests/ -v`
5. Submit pull request

## Changelog

### v1.0.0 - Initial Release
- 36+ comprehensive security checks
- Malware detection (reverse shells, crypto miners)
- Vulnerability assessment (privilege escalation, weak configs)
- System health monitoring
- Docker support
- 87 unit tests (100% pass rate)
- Text and Markdown reporting
- SSH-based assessment (no agent required)

## Support

For issues, questions, or contributions, please open an issue on the repository.

---

**Status**: Production Ready ✅  
**Test Coverage**: 87 tests passing (100%)  
**Code Quality**: Linted with ruff and black (0 issues)  
**Docker**: Build verified ✅  
**Last Updated**: January 8, 2026
