# Linux Health Security Scanner - Comprehensive Checks Summary

## Overview

The Linux Health security scanner has been enhanced with 14 new comprehensive security checks, bringing the total to **36+ security assessments**. The tool now provides enterprise-grade threat detection, vulnerability assessment, and compliance monitoring capabilities.

## New Security Checks Added

### 1. Suspicious Network Connections
- **Category**: Network Security
- **Detects**: Unusual external connections, potential C&C communication, data exfiltration
- **Method**: Analyzes established TCP connections, filters local/RFC1918 addresses
- **Status Levels**: 
  - PASS: Few external connections
  - WARN: 20-50 external connections
  - FAIL: 50+ external connections

### 2. Hidden Files in System Directories
- **Category**: Malware/Backdoors
- **Detects**: Hidden files in /tmp, /var/tmp, /dev/shm, /usr/bin, /sbin, /etc
- **Method**: Recursive find for `.*` files
- **Status Levels**:
  - PASS: No hidden files
  - WARN: 1-5 hidden files
  - FAIL: 6+ hidden files

### 3. Kernel Module Integrity
- **Category**: Kernel Security
- **Detects**: Unsigned modules, suspicious kernel module locations, module count anomalies
- **Method**: `lsmod` analysis, `modinfo` verification
- **Status Levels**:
  - PASS: All modules in /lib/modules, normal count
  - WARN: 150+ modules loaded (bloat)
  - FAIL: Modules not in standard paths (rootkit indicator)

### 4. Active Reverse Shells
- **Category**: Malware/Backdoors
- **Detects**: Running reverse shell processes
- **Patterns Matched**:
  - `bash -i`
  - `sh -i`
  - `/dev/tcp/`, `/dev/udp/`
  - `nc -e`, `ncat -e`
  - `socat`, Python/Perl/Ruby socket patterns
- **Status**: FAIL if any pattern detected

### 5. Weak Password Policy
- **Category**: Authentication
- **Detects**: Missing or weak PAM password quality configuration
- **Checks**:
  - Presence of pam_pwquality or pam_cracklib
  - Minimum password length (should be 8+, warning if <8)
- **Status Levels**:
  - FAIL: No password quality module
  - WARN: minlen < 8
  - PASS: Proper configuration

### 6. Container Escape Indicators
- **Category**: Container Security
- **Detects**:
  - Running in privileged containers
  - Suspicious mount points
  - Container escape attempts
- **Status Levels**:
  - PASS: Not in container or properly restricted
  - WARN: Container with escape-prone configuration
  - FAIL: Privileged container

### 7. ARP Spoofing Detection
- **Category**: Network Security
- **Detects**: Duplicate MAC addresses (ARP spoofing attempt)
- **Method**: `ip neigh show` analysis
- **Status Levels**:
  - PASS: No duplicates, normal ARP table size
  - WARN: Large ARP table (100+, possible ARP scan)
  - FAIL: Duplicate MAC addresses detected

### 8. DNS Tampering
- **Category**: Network Security
- **Detects**: Suspicious DNS server configuration
- **Checks**:
  - Blacklisted DNS servers (0.0.0.0, 127.0.0.2)
  - Missing DNS configuration
  - Unusual DNS servers
- **Status Levels**:
  - PASS: Legitimate DNS servers
  - WARN: No DNS configured
  - FAIL: Suspicious/blacklisted DNS

### 9. Cryptocurrency Miner Detection
- **Category**: Malware/Backdoors
- **Detects**:
  - Mining process names: xmrig, minerd, cpuminer, ethminer, etc.
  - Connections to mining pools (ports 3333, 4444, 5555, 7777, 9999)
  - Abnormal CPU usage (>90%)
- **Status Levels**:
  - PASS: No mining activity
  - WARN: High CPU usage (90%+)
  - FAIL: Mining process or pool connection detected

### 10. Critical Binary Integrity
- **Category**: File Integrity
- **Monitors**:
  - `/bin/bash`
  - `/bin/sh`
  - `/usr/bin/sudo`
  - `/bin/su`
  - `/usr/bin/ssh`
  - `/sbin/init`
- **Detects**:
  - Recent modifications (7 days)
  - World-writable permissions
  - Trojan/rootkit installation
- **Status Levels**:
  - PASS: Unmodified, properly secured
  - FAIL: Recently modified or world-writable

### 11. Log Tampering Detection
- **Category**: Log Security
- **Detects**:
  - Empty authentication logs
  - Missing syslog/messages
  - Possible log deletion
- **Monitors**: /var/log/auth.log, /var/log/secure, /var/log/syslog, /var/log/messages
- **Status Levels**:
  - PASS: Normal log volume
  - WARN: Few log entries
  - FAIL: Empty or missing logs

### 12. Privilege Escalation Vectors
- **Category**: Privilege Escalation
- **Detects**:
  - NOPASSWD sudoers entries
  - Dangerous Linux capabilities (cap_setuid)
  - World-writable /etc/passwd
  - Vulnerable sudo versions (CVE-2021-3156)
- **Vulnerable Sudo Versions**: < 1.9.5p2
- **Status Levels**:
  - PASS: No escalation vectors
  - WARN: One vector found
  - FAIL: 2+ vectors or critical vulnerability

### 13. World-Writable System Files
- **Category**: File Permissions
- **Detects**: Insecurely configured files in system paths
- **Locations Checked**:
  - /bin
  - /sbin
  - /usr/bin
  - /usr/sbin
  - /etc
- **Status**: FAIL if any world-writable files found

### 14. Deleted File Handles
- **Category**: Malware/Backdoors
- **Detects**: Processes holding file handles to deleted files (rootkit indicator)
- **Method**: `lsof +L1`
- **Status Levels**:
  - PASS: No deleted handles
  - WARN: Deleted file handles found (investigate)

## Original Security Checks (Retained)

### System Resources (4 checks)
1. Disk Usage - Monitor root filesystem capacity
2. Memory Availability - Check available memory percentage
3. System Load - Monitor CPU load averages
4. Process Resource Usage - Flag processes >80% CPU/MEM

### Patching & Updates (2 checks)
1. Reboot Required - Check for `/var/run/reboot-required`
2. Pending Updates - Separate security vs. regular updates

### Network Security (2 checks)
1. Firewall Status - UFW/iptables/firewalld configuration
2. Listening Services - Categorize public network listeners

### Authentication (5 checks)
1. SSH Configuration - PasswordAuthentication, PermitRootLogin, port settings
2. Auth Failures - Recent failed authentication attempts
3. Root Logins - Monitor root login activity
4. Failed Login Spikes - Detect brute-force attempts
5. Unexpected Sudo Usage - Monitor sudo command history

### User Account Security (3 checks)
1. Active Accounts - List all user accounts
2. Stale Accounts - Identify unused accounts (90+ days)
3. Recently Created Accounts - Detect new accounts (30 days)

### File Security (2 checks)
1. SUID Binaries - List and audit SUID files
2. System Binary Modifications - Detect changes to core system files

### Process Security (2 checks)
1. Abnormal Network Processes - Detect suspicious network utilities
2. Suspicious Process Locations - Find processes in /tmp, /dev/shm

### Scheduled Tasks (1 check)
1. Cron & Timers - Analyze cron jobs, at jobs, systemd timers

### Optional Scans
1. Rootkit Detection - rkhunter integration (when installed)
2. Package Hygiene - Detect unused/orphaned packages

## Implementation Details

### Code Architecture
- **checks.py**: Core security check functions (1897 lines)
- **cli.py**: Command-line interface and orchestration
- **report.py**: Report rendering (text and markdown)
- **scanner.py**: TCP port scanning
- **ssh_client.py**: SSH session management

### Test Coverage
- **Total Tests**: 87 (all passing)
- **New Test Classes**: 14
- **Test Methods**: 28 new tests for new checks
- **Coverage**: Unit tests with comprehensive mocking

### Deployment
- **Docker**: Containerized for consistent deployment
- **Python Version**: 3.11+
- **Dependencies**: Paramiko for SSH
- **No Agent Required**: SSH-based remote assessment only

## Usage Examples

### Basic Usage
```bash
python -m linux_health <hostname> <username> <password>
```

### Advanced Usage
```bash
# Interactive password prompt
python -m linux_health ubuntu.example.com admin - --ask-password

# Non-standard SSH port
python -m linux_health ubuntu.example.com admin password --port 2222

# Save markdown report
python -m linux_health ubuntu.example.com admin password --format md --output report.md

# Enable optional checks
python -m linux_health ubuntu.example.com admin password --enable-rootkit-scan --check-package-hygiene

# Custom timeout
python -m linux_health ubuntu.example.com admin password --timeout 30
```

### Docker Usage
```bash
docker build -t linux-health .
docker run --rm linux-health 192.168.1.26 username password

docker-compose run --rm linux-health 192.168.1.26 username - --ask-password
```

## Output Format

### Text Report
- Clear hierarchical structure
- Status icons (✅, ⚠️, ❌)
- Detailed findings and recommendations
- Port scan results
- System information summary

### Markdown Report
- GitHub-compatible formatting
- Checklist with status indicators
- Detailed sections for each check
- Command suggestions for remediation

## Security Assessment Matrix

| Threat Type | Checks | Detection Method |
|---|---|---|
| **Malware/Backdoors** | 4 checks | Process patterns, hidden files, rootkit scan |
| **Network Attacks** | 6 checks | Connection analysis, ARP, DNS, anomalies |
| **Privilege Escalation** | 3 checks | Sudo audit, capabilities, file permissions |
| **Authentication Attacks** | 5 checks | Log analysis, failed attempts, login tracking |
| **Compliance/Hygiene** | 4 checks | Updates, packages, kernel modules, logs |
| **System Health** | 4 checks | Resources, load, disk, processes |

## Performance Characteristics

- **Execution Time**: 30-120 seconds (depending on system and network)
- **SSH Overhead**: Minimal; all commands are lightweight
- **Network Impact**: Low bandwidth usage
- **Security**: No data modification, read-only assessments only

## Future Enhancements

1. Database/service-specific checks
2. Web application security assessment
3. Threat intelligence integration
4. Historical trend analysis
5. Automated remediation recommendations
6. Role-based scanning profiles
7. Multi-host reporting
8. Real-time monitoring mode

## Conclusion

The enhanced Linux Health scanner provides a comprehensive, SSH-based security assessment platform suitable for:
- Security audits
- Vulnerability assessments
- Incident response investigations
- Compliance monitoring
- Infrastructure health checks
- Threat detection and hunting

All checks are non-intrusive, require no agent installation, and provide actionable security intelligence with clear remediation guidance.
