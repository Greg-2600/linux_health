# Linux System Compromise Indicators - Comprehensive Analysis

## 1. Process-Level Indicators of Attack/Compromise

### High-Risk Process Behaviors
- **Processes running from /tmp or /var/tmp** - Common for malware execution
- **Processes running from /dev/shm** - In-memory filesystem (RAM disk), avoids disk traces
- **Processes with parent process deleted** - Orphaned processes, common in backdoors
- **Processes with suspicious name obfuscation** - (hexadecimal names, spaces, dots)
- **Interpreters (bash, perl, python) listening on network** - Reverse shells
- **Known malware process names** - cryptominers, trojans, bots
- **Processes with high FD count** - Resource hoarding, exfiltration
- **Processes with unusual arguments** - Commands with `-c`, `-r`, eval patterns
- **Processes using LD_PRELOAD** - Library injection attacks
- **Zombie processes** - Sign of missing signal handlers

### Detectable Via:
- `/proc/[pid]/cwd` - Running directory
- `/proc/[pid]/cmdline` - Command arguments
- `/proc/[pid]/fd/` - File descriptors
- `ps -auxww` with environment inspection
- `lsof` for file descriptor enumeration

---

## 2. Account/Authentication Compromise

### High-Risk Account Behaviors
- **Unexpected sudo access** - Users added to sudoers without approval
- **Root account login attempts** - Should be rare/denied
- **Accounts created recently** - Backdoor accounts
- **Accounts with UID 0** - Privilege escalation backdoors
- **SSH keys modified recently** - Account takeover
- **Home directories changed permissions** - Hiding evidence
- **Weak or missing passwords** - Easy lateral movement
- **Accounts with login shell changed** - Disabled accounts being reactivated
- **Session hijacking patterns** - Multiple simultaneous SSH from different IPs
- **Password-less SSH keys** - Unauthorized access facilitation

### Detectable Via:
- `/etc/passwd` modifications (stat/timestamp)
- `/etc/sudoers` and `/etc/sudoers.d/`
- `~/.ssh/authorized_keys` timestamp checks
- `lastlog` for unexpected logins
- `/var/log/auth.log` for sudo usage

---

## 3. File System Anomalies

### High-Risk File Modifications
- **System binaries modified** - /bin, /sbin, /usr/bin compromised
- **Recently modified system config files** - /etc changes
- **Hidden files in /root or /home** - Backdoor configuration
- **Suspicious files in /tmp** - Malware staging ground
- **World-writable system files** - Permission escalation
- **SUID binaries modified** - Privilege escalation
- **Libraries in unusual locations** - Rootkit/LD_PRELOAD injection
- **.so files in home directories** - Malicious libraries
- **Scripts in cron/systemd directories** - Persistence mechanism
- **Modified system documentation files** - Covering tracks

### Detectable Via:
- Find modified files since date
- Check file permissions/ownership
- Verify system binaries against baseline (if available)
- Scan for SUID/SGID changes
- Check library load paths

---

## 4. Persistence Mechanisms

### High-Risk Persistence
- **Unusual cron jobs** - Especially root cron, system cron, user cron
- **Suspicious systemd timer units** - Modern persistence
- **Unusual startup services** - Custom systemd services
- **Init.d scripts modified** - Rc.d persistence
- **Boot scripts in /etc/rc.local** - Legacy persistence
- **SSH rc files modified** - ~/.bash_profile, ~/.bashrc, ~/.profile
- **Library preload files** - /etc/ld.so.preload
- **Unusual kernel modules** - Rootkits
- **Modified sudoers without sudo** - No-password backdoors
- **Git hooks** - Auto-persistence via version control

### Detectable Via:
- Crontab enumeration
- Systemd timer listing
- Service file inspection
- Init.d directory scan
- RC file timestamp checks

---

## 5. Network/Data Exfiltration

### High-Risk Network Behaviors
- **Unusual outbound connections** - Known bad IPs/domains
- **DNS queries to malicious domains** - C2 communication
- **Processes with many open connections** - Botnet, scanner
- **Listening ports > 10000** - Common for backdoors
- **High volume network traffic** - Data exfiltration
- **Reverse shell signatures** - /dev/tcp patterns
- **Port forwarding rules** - Tunnel establishment
- **Unusual UDP traffic** - DNS tunneling, covert channels
- **Connections from privileged processes to internet** - Unexpected

### Detectable Via:
- `ss -tulpn` for listening processes
- `netstat -an` for active connections
- Process network file descriptor inspection
- Network bandwidth monitoring (if available)

---

## 6. Log/Forensic Anomalies

### High-Risk Log Behaviors
- **Log files cleared or truncated** - Evidence destruction
- **Large gaps in timestamps** - Missing logs
- **Failed login attempts from unusual sources** - Brute force
- **Sudo logs show unusual commands** - Privilege abuse
- **System messages about failed modules** - Rootkit installation failure
- **Cron execution but no logs** - Log tampering
- **SELinux/AppArmor denials** - Breach containment indicators
- **Journal incomplete/corruption** - Tampered logs
- **Last command doesn't match shell history** - Forensic evidence hiding

### Detectable Via:
- Log file size changes
- Timestamp gaps
- Failed login count
- Sudo usage patterns
- Journal analysis

---

## 7. Resource Exhaustion/Performance Degradation

### High-Risk Resource Patterns
- **CPU usage over threshold** - Cryptomining, brute force
- **Memory exhaustion** - Memory-hogging malware
- **Disk I/O saturation** - Encrypting files, logging activity
- **Sudden drop in disk space** - Cryptolocker, logging
- **Zombie processes** - Resource leak exploitation
- **Hanging/zombie kernel threads** - Rootkit activity
- **Unusual network bandwidth** - Exfiltration

### Detectable Via:
- Process memory/CPU tracking
- Disk space monitoring
- Process list enumeration
- Network traffic analysis

---

## 8. Rootkit/Advanced Malware

### High-Risk Rootkit Indicators
- **Kernel module list discrepancies** - Rootkits hide modules
- **Modified system call tables** - Syscall hooks
- **Rootkit scanner signatures** - rkhunter, chkrootkit
- **LKM (Loadable Kernel Module) anomalies** - Hidden modules
- **Modified /lib/modules** - Rootkit installation
- **Suspicious /proc behavior** - Information hiding
- **LD_PRELOAD presence** - Library injection
- **Unexpected module dependencies** - Hidden malware

### Detectable Via:
- rkhunter scans
- lsmod vs /proc/modules
- Kernel module signature verification
- LD_PRELOAD file checks
- System call table verification (advanced)

---

## Priority Implementation Matrix

### Critical (Implement First)
| Indicator | Severity | Feasibility | Implementation |
|-----------|----------|-------------|---|
| Suspicious process locations (/tmp, /dev/shm) | CRITICAL | Easy | Process scanning |
| Unexpected sudo usage | CRITICAL | Easy | Sudo log inspection |
| Recently created accounts | CRITICAL | Easy | /etc/passwd checking |
| Modified system binaries | CRITICAL | Medium | Checksum/timestamp comparison |
| Unusual listening ports | HIGH | Easy | ss/netstat parsing |
| Suspicious cron jobs | HIGH | Easy | Crontab enumeration |
| Root logins | CRITICAL | Easy | Existing (have this) |
| Failed logins from unique IPs | HIGH | Medium | Auth log parsing |
| File permission anomalies | HIGH | Medium | Find with permission checks |
| Rootkit detection | CRITICAL | Medium | rkhunter integration (have this) |

### Medium Priority (Implement Second)
| Indicator | Severity | Feasibility | Implementation |
|-----------|----------|-------------|---|
| SSH key modifications | MEDIUM | Easy | ~/.ssh timestamp checks |
| Log file integrity | MEDIUM | Medium | Journal and syslog checks |
| Unusual process arguments | MEDIUM | Hard | Deep cmdline analysis |
| Zombie processes | MEDIUM | Easy | Process state checking |
| High process FD count | MEDIUM | Easy | FD enumeration |
| Suspicious library loads | MEDIUM | Medium | LD_PRELOAD and library scanning |
| Boot-time persistence | MEDIUM | Easy | Init.d and rc.local scanning |

### Lower Priority (Nice to Have)
| Indicator | Severity | Feasibility | Implementation |
|-----------|----------|-------------|---|
| Data exfiltration detection | MEDIUM | Hard | Network traffic analysis |
| Performance degradation | MEDIUM | Medium | Resource baseline comparison |
| DNS anomalies | MEDIUM | Hard | DNS query logging (not captured) |
| Kernel module anomalies | LOW | Hard | Advanced kernel inspection |

---

## Recommended Implementation Order for This Project

1. ✅ **Abnormal network processes** (DONE)
2. **Suspicious process locations** - /tmp, /dev/shm execution
3. **Unexpected sudo usage** - audit sudoers and sudo logs
4. **Recently created accounts** - detect backdoor accounts (90+ days old handled, now new ones)
5. **Modified system binaries** - check key binaries for recent changes
6. **Failed login spike detection** - multiple failed attempts in short time
7. **SSH key modifications** - unauthorized_keys timestamp checks
8. **Zombie process detection** - sign of exploitation
9. **File permission anomalies** - world-writable system files
10. **Suspicious cron/systemd** - unusual scheduled tasks
