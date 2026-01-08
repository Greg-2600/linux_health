# Linux Health

Python CLI for comprehensive health and security assessment of remote Linux systems via SSH. Generates text or Markdown reports with actionable findings.

## Features

- **Health/Security Checks**: 36+ comprehensive checks covering:
  - **System Resources**: Storage, memory, CPU load, process resource usage
  - **Patching**: Reboot required, pending updates (security vs. regular)
  - **Network Security**: Firewall status, suspicious connections, ARP spoofing, DNS tampering
  - **Authentication**: SSH config, password policy, auth failures, root logins, failed login spikes
  - **User Accounts**: Active accounts, stale accounts, recently created accounts
  - **Malware/Backdoors**: Reverse shell detection, crypto miners, hidden files, deleted file handles
  - **File Security**: SUID binaries, world-writable files, critical binary integrity
  - **Process Security**: Listening services, abnormal network processes, suspicious process locations
  - **Privilege Escalation**: Sudo misconfigurations, dangerous capabilities, privilege vectors
  - **Kernel Security**: Kernel module integrity, system binary modifications
  - **Container Security**: Container escape indicators, privileged container detection
  - **Log Security**: Log tampering detection, unexpected sudo usage
  - **Scheduled Tasks**: Cron jobs, at jobs, systemd timers
- **Port Scanning**: TCP connect scan; reports **open ports only** (summarizes when none open)
- **Security Audit Extras**: SSH login history, firewall status, SUID inventory, sudoers, critical file perms, failed systemd units (severity-ranked)
- **Optional Rootkit Scan**: rkhunter (when installed)
- **Process Monitoring**: Flags >80% CPU/MEM processes with names/usages
- **Updates**: Separates security vs. regular updates; security updates are elevated
- **Reporting**: Text/Markdown with concise checklist and detailed sections

## Requirements

- Python 3.11+
- SSH access to target Linux system
- Paramiko (installed via requirements.txt)

## Installation

### Local Installation

```bash
pip install -r requirements.txt
```

### Docker Installation

```bash
docker build -t linux-health .
# or using docker-compose
docker-compose build
```

## Usage

### Basic Usage

```bash
python -m linux_health <hostname> <username> <password>
```

### Examples

```bash
# Check remote host with interactive password prompt
python -m linux_health ubuntu.example.com admin - --ask-password

# Check on non-standard SSH port
python -m linux_health ubuntu.example.com admin password --port 2222

# Scan specific ports
python -m linux_health ubuntu.example.com admin password --scan-ports 22,80,443,3306

# Save report to file in markdown format
python -m linux_health ubuntu.example.com admin password --format md --output report.md

# Custom connection timeout
python -m linux_health ubuntu.example.com admin password --timeout 10.0

# Enable optional rootkit scan (if rkhunter is installed on target)
python -m linux_health ubuntu.example.com admin password --enable-rootkit-scan

# Check for unused and orphaned packages
python -m linux_health ubuntu.example.com admin password --check-package-hygiene

# Combine multiple optional checks
python -m linux_health ubuntu.example.com admin password --enable-rootkit-scan --check-package-hygiene
```

### Project Structure

This README is the single source of truth; other Markdown files are archival references only.

```
linux_health/
├── linux_health/
│   ├── __init__.py
│   ├── __main__.py
│   ├── checks.py          # Core health/security checks
│   ├── cli.py             # CLI parsing and orchestration
│   ├── report.py          # Text/Markdown report rendering (open-ports-only)
│   ├── scanner.py         # Lightweight TCP port scanner
│   └── ssh_client.py      # SSH session wrapper
├── tests/
│   └── test_linux_health.py
├── docker-compose.yml
├── Dockerfile
├── Dockerfile.multistage
├── requirements.txt
├── requirements-dev.txt
├── README.md              # Primary, consolidated docs (includes improvements & sample excerpt)
├── IMPROVEMENTS.md        # Archived copy (no longer primary)
├── report_final.md        # Archived sample report
└── health_report.txt      # Legacy sample output
```

### Development & Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Run full test suite
python -m pytest -v

# Run a single test file
python -m pytest tests/test_linux_health.py -v
```

Notes:
- Port scan output lists only open ports; when none are open, the report states all scanned ports were closed/filtered.
- Use `--format md` for Markdown output or omit for text output.

## Improvements (formerly IMPROVEMENTS.md)

Seven major changes driven by live report analysis (all in current code/tests):

1) SSH config readability: primary `sshd -T` with grep fallback; improved sudo handling and regex.
2) Rkhunter compatibility: removed `--skip-warnings`; keep `--skip-keypress`; capture warnings.
3) Listening services categorization: summarizes SSH/HTTP/HTTPS/DB/DNS/Other for public listeners.
4) Process resource monitoring: new check flags processes >80% CPU/MEM with names/usages.
5) Security vs regular updates: separates security updates (FAIL) from regular (WARN).
6) SSH security rating: scores PasswordAuthentication, PermitRootLogin, non-default port; emits overall rating.
7) Failed systemd units severity: CRITICAL/WARNING/INFO classification.

Quality and coverage: all tests passing; improved error handling and sudo fallbacks.

Potential future enhancements: DB/service probes, web checks, root-cause for failed units, CPU-core-aware load thresholds, threat intel hooks, role-based config profiles.

## Sample Report (excerpt from latest run)

Shows open-port-only scan section and improved checks:

```
## Summary
- Checks: 14 (✅ 5 / ⚠️ 8 / ❌ 1)
- Open ports (scanned): 3 -> 22, 80, 5432

## Port Scan (lightweight)
| Port | State | Notes |
| --- | --- | --- |
| 22 | open | Connected |
| 80 | open | Connected |
| 5432 | open | Connected |
```

For a full example, see report_final.md (retained as reference); key content is summarized above.

### Docker Usage

```bash
# Run with docker-compose
docker-compose run --rm linux-health <hostname> <username> - --ask-password

# Run with direct docker command
docker run --rm linux-health <hostname> <username> - --ask-password
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `hostname` | Target host to check (required) |
| `username` | SSH username (required) |
| `password` | SSH password or `-` to prompt (required) |
| `--port PORT` | SSH port (default: 22) |
| `--timeout SECONDS` | SSH connection timeout (default: 5.0) |
| `--format {text\|md}` | Output format (default: text) |
| `--output PATH` | Output file path (default: stdout) |
| `--scan-ports PORTS` | Comma-separated ports to scan (default: common ports) |
| `--ask-password` | Prompt for password interactively |
| `--enable-rootkit-scan` | Run rkhunter rootkit scan if available on target |
| `--check-package-hygiene` | Check for unused/orphaned packages and bloat |

## Report Output

The tool generates comprehensive health reports including:

### System Information
- Hostname, OS version, kernel version
- System uptime
- Logged-in users

### Comprehensive Security Checks

The scanner performs 36+ security checks across multiple categories:

#### System Resources
- **Disk Usage**: Root filesystem capacity monitoring
- **Memory**: Available memory percentage
- **CPU Load**: System load averages (1m, 5m, 15m)
- **Process Resource Usage**: Flags processes using >80% CPU/MEM

#### Patching & Updates
- **Reboot Required**: Checks for `/var/run/reboot-required`
- **Pending Updates**: Separates security updates (FAIL) from regular (WARN)

#### Network Security
- **Firewall Status**: UFW/iptables/firewalld configuration
- **Suspicious Network Connections**: Detects unusual external connections
- **ARP Spoofing Detection**: Checks for duplicate MAC addresses
- **DNS Tampering**: Verifies DNS resolver integrity
- **Listening Services**: Categorizes public listeners (SSH/HTTP/DB/etc.)
- **Abnormal Network Processes**: Detects processes with unusual network activity

#### Authentication & Access Control
- **SSH Configuration**: PasswordAuthentication, PermitRootLogin, port settings
- **Password Policy**: PAM password quality/complexity requirements
- **Auth Failures**: Recent failed authentication attempts
- **Root Logins**: Recent root login activity
- **Failed Login Spikes**: Detects brute-force attempts

#### User Account Security
- **Active Accounts**: Lists all user accounts
- **Stale Accounts**: Identifies unused accounts (no login in 90+ days)
- **Recently Created Accounts**: Detects new accounts (last 30 days)

#### Malware & Intrusion Detection
- **Reverse Shell Detection**: Scans for active reverse shell patterns
- **Crypto Miner Detection**: Identifies cryptocurrency mining processes/connections
- **Hidden Files**: Searches for hidden files in system directories
- **Deleted File Handles**: Detects processes with deleted file handles (rootkit indicator)
- **Optional Rootkit Scan**: rkhunter integration when available

#### File & System Integrity
- **SUID Binaries**: Lists SUID files and checks for anomalies
- **World-Writable System Files**: Finds insecure file permissions
- **Critical Binary Integrity**: Checks modification times on /bin/bash, /usr/bin/sudo, etc.
- **System Binary Modifications**: Detects changes to core system files

#### Privilege Escalation Detection
- **Privilege Escalation Vectors**: NOPASSWD sudo, dangerous capabilities, writable /etc/passwd
- **Unexpected Sudo Usage**: Recent sudo command history
- **Sudoers Configuration**: Syntax and permission checks

#### Kernel & Container Security
- **Kernel Module Integrity**: Checks for unsigned or suspicious kernel modules
- **Container Escape Indicators**: Detects privileged containers or escape attempts

#### Log & Audit Security
- **Log Tampering Detection**: Checks for gaps/deletions in system logs
- **Systemd Unit Failures**: Categorizes failed units by severity (CRITICAL/WARNING/INFO)

#### Scheduled Tasks
- **Cron & Timers**: Analyzes cron jobs, at jobs, and systemd timers for suspicious entries

### Summary Statistics
- Total checks performed
- Pass/warning/fail counts
- Open ports detected

### Detailed Checks
Health checks organized by category:
- **Password Policy**: Password aging, complexity requirements
- **SSH Security**: Root login restrictions, authentication methods
- **Firewall**: Rules configuration and status
- **File Permissions**: Critical system file permissions
- **Package Management**: Available updates and package integrity
- **System Services**: Failed systemd units detection
- **Process Security**: SUID binaries and sudoers configuration

## Development

### Running Tests

```bash
pip install pytest pytest-mock
pytest tests/ -v
```

### Project Structure

```
linux_health/
├── __init__.py          # Package initialization
├── __main__.py          # Entry point
├── cli.py              # Command-line interface
├── checks.py           # Health checks implementation
├── report.py           # Report rendering
├── scanner.py          # Port scanning
└── ssh_client.py       # SSH connection management

tests/
└── test_linux_health.py # Unit tests

Dockerfile              # Docker image definition
docker-compose.yml      # Docker Compose configuration
```

## Optional: Rkhunter Rootkit Detection

This tool can optionally integrate with `rkhunter` (Rootkit Hunter) to scan for rootkits on the target system.

### Setup on Target System

Install rkhunter on the target Linux system (requires root/sudo):

```bash
# Ubuntu/Debian
sudo apt-get install rkhunter
sudo rkhunter --update

# CentOS/RHEL
sudo yum install rkhunter
sudo rkhunter --update

# Arch Linux
sudo pacman -S rkhunter
sudo rkhunter --update
```

### Usage with linux_health

Enable the rootkit scan by adding `--enable-rootkit-scan` flag:

```bash
python -m linux_health ubuntu.example.com admin password --enable-rootkit-scan
```

**Notes:**
- rkhunter must be installed on the **target system**, not the scanning machine
- The scan may take several minutes depending on system size
- Results will be included in the detailed security findings section of the report
- If rkhunter is not installed on the target, the flag is silently ignored
- Some rkhunter checks may require elevated privileges (the tool will attempt with sudo if a password is provided)

### Interpreting Results

Look for:
- `[OK]` - Check passed, no issues detected
- `[WARNING]` - Potential issues or unusual configurations  
- `[ALERT]` or `[FAILED]` - Security concern detected

## Optional: Package Hygiene & Bloat Detection

This tool can optionally scan for unused packages, orphaned dependencies, and installation bloat.

### What It Checks

**Orphaned/Autoremovable Packages:**
- Packages installed as dependencies but no longer needed
- Detected via package manager (apt/yum)
- Safe to remove - just dependency cleanup

**Development Tools** (when found):
- `build-essential`, `gcc`, `g++`, `python3-dev`, `git`, etc.
- Not harmful, but can be removed if development is complete
- Saves disk space and reduces attack surface

**Known Bloat Packages** (when found):
- Legacy/insecure: `telnet`, `talk`, `rsh-client`, `nis`
- Unnecessary graphical: `xserver-xorg`, `cups` (on servers)
- Consider removing unless actively needed

### Usage

Enable package hygiene check:

```bash
python -m linux_health ubuntu.example.com admin password --check-package-hygiene
```

### Interpreting Results

```
=== Orphaned/Autoremovable Packages ===
Remov python3-dev python3-pip
  (Safe to remove - no longer needed by other packages)

=== Installed Development Tools ===
build-essential
gcc
  (Remove if development is not needed)

=== Potentially Unnecessary Packages ===
cups
  (Consider removing if not required)
```

### Recommendations

1. **Review before removing** - Always understand why a package was installed
2. **Test in non-prod first** - Verify applications still work after removal
3. **Use dry-run** - Most package managers support `--dry-run` before actual removal
4. **Export list** - Save hygiene report for audit/compliance purposes

## Security Considerations

⚠️ **Warning**: This tool requires SSH credentials. For production use:

1. **Use SSH keys** instead of passwords when possible
2. **Avoid hardcoding credentials** in scripts
3. **Use environment variables** or secure secret management
4. **Restrict file permissions** on output reports containing sensitive data
5. **Run in isolated networks** when accessing production systems
6. **Log all connections** for audit purposes

## Docker Best Practices

When using Docker:

1. **Run as non-root** in production (modify Dockerfile if needed)
2. **Use environment variables** for credentials via `.env` file
3. **Mount volumes** for report persistence
4. **Set resource limits** for container safety

Example with environment variables:
```bash
docker run --rm \
  -e SSH_HOST=ubuntu.example.com \
  -e SSH_USER=admin \
  -v $(pwd)/reports:/app/reports \
  linux-health $SSH_HOST $SSH_USER - --ask-password --output /app/reports/report.txt
```

## Troubleshooting

### SSH Connection Failures
- Verify hostname and port are correct
- Check network connectivity to target host
- Ensure credentials are valid
- Verify SSH service is running on target

### Permission Denied Errors
- Some checks require elevated privileges (use user with sudo access)
- Provide user with appropriate sudoers configuration

### Timeout Issues
- Increase `--timeout` value for slower connections
- Check network latency to target system

## License

This project is provided as-is for system administration and security auditing purposes.

## Contributing

Contributions welcome! Please ensure:
- All tests pass: `pytest tests/ -v`
- Code follows Python standards
- Documentation is updated accordingly
