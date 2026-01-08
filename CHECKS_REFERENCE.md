# Complete Security Checks Reference

## Quick Reference Table

| # | Check Name | Category | Severity | Detection Method |
|---|---|---|---|---|
| 1 | Disk Usage | System | ⚠️ | df command |
| 2 | Memory | System | ⚠️ | free command |
| 3 | System Load | System | ⚠️ | /proc/loadavg |
| 4 | Process Resources | System | ⚠️ | top/ps |
| 5 | Reboot Required | Patching | ⚠️ | /var/run/reboot-required |
| 6 | Pending Updates | Patching | 🔴 | apt-get/dnf/yum |
| 7 | SSH Config | SSH | ⚠️ | sshd -T |
| 8 | Firewall | Network | ✅ | ufw/iptables |
| 9 | **Suspicious Connections** | Network | 🔴 | ss/netstat |
| 10 | **ARP Spoofing** | Network | 🔴 | ip neigh |
| 11 | **DNS Tampering** | Network | 🔴 | /etc/resolv.conf |
| 12 | Time Sync | System | ⚠️ | timedatectl |
| 13 | Accounts | User | ✅ | /etc/passwd |
| 14 | Stale Accounts | User | ⚠️ | last/lastlog |
| 15 | **Recent Accounts** | User | ⚠️ | stat /home |
| 16 | Auth Failures | Auth | ⚠️ | auth.log |
| 17 | **Failed Login Spike** | Auth | 🔴 | auth.log analysis |
| 18 | Root Logins | Auth | 🔴 | auth.log |
| 19 | **Weak Password Policy** | Auth | 🔴 | /etc/pam.d |
| 20 | Listening Services | Network | ✅ | ss -tnlp |
| 21 | **Abnormal Network Processes** | Malware | ⚠️ | netstat/lsof |
| 22 | **Suspicious Process Locations** | Malware | 🔴 | find /tmp |
| 23 | **Unexpected Sudo Usage** | Security | ⚠️ | sudoers + logs |
| 24 | **System Binary Modifications** | Integrity | 🔴 | find -mtime |
| 25 | **SUID Files** | Security | ⚠️ | find -perm |
| 26 | **Cron & Timers** | Tasks | ✅ | crontab/systemctl |
| 27 | **Reverse Shell Detection** | Malware | 🔴 | ps aux |
| 28 | **Hidden Files** | Malware | 🔴 | find .* |
| 29 | **Kernel Modules** | Kernel | ⚠️ | lsmod/modinfo |
| 30 | **Container Escape** | Container | 🔴 | mount/ps |
| 31 | **Crypto Miners** | Malware | 🔴 | ps/ss |
| 32 | **Critical Binary Integrity** | Integrity | 🔴 | stat/ls -la |
| 33 | **Log Tampering** | Audit | 🔴 | tail logs |
| 34 | **Privilege Escalation** | Exploit | 🔴 | sudo/getcap |
| 35 | **World-Writable Files** | Permissions | 🔴 | find -perm |
| 36 | **Deleted File Handles** | Malware | ⚠️ | lsof +L1 |

**Legend:** 🔴 = New Check, ⚠️ = Warning Priority, ✅ = Informational

## Check Severities

### CRITICAL/FAIL 🔴 Checks
These indicate security issues requiring immediate attention:
1. Suspicious network connections (50+)
2. Reverse shell detected
3. Crypto miner detected
4. Critical binary modification (last 7 days)
5. World-writable critical files
6. DNS tampering/suspicious DNS
7. ARP spoofing detected
8. Log tampering/empty logs
9. Container privilege escalation risk
10. Privilege escalation vectors (2+)
11. Pending security updates
12. Failed login spike
13. Root logins detected
14. Recent account creation
15. System binary modifications
16. Hidden files in system directories

### WARNING/WARN ⚠️ Checks
These indicate issues to monitor and address:
1. Disk usage 80-90%
2. Memory 10-20% available
3. System load 4-8
4. Password policy weak (minlen < 8)
5. SSH password authentication enabled
6. Auth failures (recent)
7. Weak password policy
8. Process >80% CPU/memory
9. Container with escape vectors
10. ARP table large (possible scan)
11. Deleted file handles present
12. Large number of modules (150+)
13. SSH config issues
14. Privilege escalation (1 vector)

### PASS/INFO ✅ Checks
System is functioning properly:
1. Disk usage <80%
2. Memory >20% available
3. System load normal
4. SSH key auth only
5. Root login disabled
6. No auth failures
7. No stale accounts
8. No suspicious processes
9. No hidden files
10. Clean ARP table
11. Normal log volume
12. No escalation vectors
13. All files have proper permissions
14. No miners/reverse shells
15. Clean kernel modules
16. Not in privileged container

## Assessment Workflow

### Pre-Scan
1. Verify SSH connectivity
2. Confirm credentials
3. Set appropriate timeout (default 5s)

### Scan Execution
1. Gather system information (hostname, OS, uptime)
2. Run 35+ security checks in sequence
3. Perform TCP port scan on common ports
4. Collect detailed security findings

### Post-Scan
1. Analyze results by severity
2. Generate text or markdown report
3. Provide actionable recommendations
4. Save report for documentation

## Check Recommendations by Category

### 🔴 CRITICAL - Address Immediately
```bash
# Check recent system changes
sudo journalctl -xe --since="1 day ago"

# Investigate suspicious processes
ps auxww | grep -E "xmrig|minerd|crypto"
lsof -p PID  # Check process file handles

# Review security logs
sudo tail -200 /var/log/auth.log | grep -E "FAIL|ERROR"

# Check for backdoors
find / -type f -name ".*" 2>/dev/null | head -20
sudo netstat -tulpn | grep -E ":3333|:4444|:9999"
```

### ⚠️ WARNING - Monitor and Plan
```bash
# Resource management
du -xhd1 / | sort -h  # Find disk space consumers
ps aux --sort=-%mem | head -20  # Check memory usage

# Hardening
sudo nano /etc/ssh/sshd_config  # Disable password auth
sudo visudo  # Review sudo configuration
sudo ufw enable  # Enable firewall
```

### ✅ GOOD - Continue Monitoring
```bash
# Regular checks
crontab -l  # Review scheduled tasks
sudo systemctl status sshd  # Monitor SSH
sudo journalctl -u sshd -f  # Real-time SSH log

# Automation
0 0 * * * /opt/linux-health/scan.sh  # Daily scan
```

## Integration Examples

### Nagios/Icinga
```bash
#!/bin/bash
python -m linux_health $HOST $USER $PASS --timeout 30 | \
  grep -E "FAIL|WARN" | wc -l
```

### Splunk
```bash
python -m linux_health $HOST $USER $PASS --format json | \
  curl -X POST -d @- http://splunk:8088/services/collector
```

### Ansible
```yaml
- name: Security scan
  command: python -m linux_health {{ inventory_hostname }} {{ user }} {{ pass }}
  register: scan_result
  failed_when: "'FAIL' in scan_result.stdout"
```

### Git/CI/CD
```bash
#!/bin/bash
python -m linux_health $HOST $USER $PASS \
  --format md --output "reports/$(date +%Y%m%d).md"
git add reports/
git commit -m "Security scan $(date)"
git push
```

## Troubleshooting

### SSH Connection Fails
```bash
python -m linux_health host user pass --timeout 30 --port 2222
```

### Unicode/Encoding Issues
```bash
export PYTHONIOENCODING=utf-8
python -m linux_health ...
```

### Timeout on Large Systems
```bash
python -m linux_health ... --timeout 60  # Increase to 60s
```

### Specific Port Scan
```bash
python -m linux_health ... --scan-ports 22,80,443,3306,5432
```

## Performance Tips

1. **Large systems:** Use `--timeout 30-60`
2. **Slow networks:** Increase SSH timeout
3. **Limited resources:** Disable optional checks
4. **Parallel scans:** Use different ports/threads
5. **Caching:** Store results locally when possible

## Maintenance

### Keep Updated
```bash
git pull  # Get latest checks
docker build -t linux-health .  # Rebuild container
```

### Review Baselines
- Establish security baselines for each system
- Compare scans over time
- Flag anomalies and changes

### Document Findings
- Keep historical scan reports
- Track remediation efforts
- Build audit trail

## Compliance Mapping

### CIS Benchmarks
- Check 1-4: System hardening
- Check 5-8: Network security
- Check 9-14: SSH hardening
- Check 15+: Advanced security

### NIST Cybersecurity Framework
- **Identify:** System inventory, vulnerabilities
- **Protect:** Hardening, access control
- **Detect:** Monitoring, anomalies
- **Respond:** Incident investigation
- **Recover:** Remediation tracking

### HIPAA/PCI-DSS
- Access control checks
- Audit logging
- Password policies
- System updates
- File integrity

---

Last Updated: January 8, 2026
Status: Complete and Production Ready ✅
