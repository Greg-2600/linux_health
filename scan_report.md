# Linux Host Health Report: juanjou

Generated: 2026-01-08 17:36:27 UTC

## System
- Hostname: juanjou
- OS: Ubuntu 24.04.3 LTS (Noble Numbat)
- Kernel: 6.8.0-90-generic
- Uptime: up 3 weeks, 2 days, 15 minutes
- Logged-in users: # users=0

## Summary
- Checks: 39 (✅ 21 / ⚠️ 12 / ❌ 6)
- Open ports (scanned): 3 -> 22, 80, 5432

## Checklist
| Status | Item | Details | Recommendation | Category |
| --- | --- | --- | --- | --- |
| ❌ FAIL | Disk usage | Root filesystem at 94% | Prune logs, remove old kernels, or extend disk; run 'sudo du -xhd1 /' to find top consumers | Storage |
| ✅ PASS | Memory | 40% available (19745 MiB of 48254 MiB) | No action | Memory |
| ⚠️ WARN | System load | Elevated load averages: 1m=4.42, 5m=4.83, 15m=4.45 | Check running processes with 'ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head' | CPU/Load |
| ✅ PASS | Reboot needed | No reboot-required flag | No action | Patching |
| ❌ FAIL | Pending updates | 16 packages pending (15 security updates) | Apply security updates immediately: 'sudo apt-get update && sudo apt-get upgrade' (adjust for distro) | Patching |
| ⚠️ WARN | PasswordAuthentication | Password authentication enabled | Set 'PasswordAuthentication no' and use SSH keys | SSH |
| ⚠️ WARN | PermitRootLogin | Root login over SSH enabled | Set 'PermitRootLogin no' and use sudo from user accounts | SSH |
| ⚠️ WARN | SSH Port | Using default port 22 | Consider non-default port + fail2ban/ufw | SSH |
| ⚠️ WARN | SSH Security Rating | ❌ Poor (0/5) | Review each recommendation above | SSH |
| ⚠️ WARN | Firewall | Firewall inactive | Enable host firewall (ufw enable or firewall-cmd --permanent --add-service=ssh) | Network |
| ✅ PASS | Time sync | NTP synchronized | Keep chrony/systemd-timesyncd running | Time |
| ✅ PASS | Root accounts | Only root has UID 0 | No action | Accounts |
| ✅ PASS | Stale user accounts | No users inactive >90 days | Monitor login activity periodically | Accounts |
| ⚠️ WARN | Auth failures (24h) | Could not read logs: [sudo] password for greg: | Check journalctl /var/log/auth.log | Auth |
| ⚠️ WARN | Root logins | 1 recent root login entries | Prefer sudo from named users; audit 'last root' for legitimacy | Auth |
| ⚠️ WARN | Listening services | Many public listeners (47): SSH=2, HTTP=2, DB=2, DNS=4, Other=37 | Review 'ss -tulpn' for unexpected services; tighten firewall/hosts.allow | Network |
| ⚠️ WARN | Abnormal network processes | Found 5 suspicious listener(s): 0.0.0.0:* on port 40000: non-standard port; 0.0.0.0:* on port 40000: non-standard port; 0.0.0.0:* on port 11435: non-standard port; +2 more | Review listening processes: ss -tulpn; investigate unfamiliar services and ports | Network |
| ✅ PASS | Suspicious process locations | No processes running from /tmp, /var/tmp, or /dev/shm | Continue monitoring for suspicious execution patterns | Process Integrity |
| ✅ PASS | Unexpected sudo usage | No obvious sudo misconfigurations detected | Monitor sudo logs regularly for privilege escalation attempts | Privilege Escalation |
| ⚠️ WARN | Recently created accounts | Found 10 account(s) created in last 30 days: fwupd-refresh (0 days old); sys (0 days old); man (0 days old); +7 more | Review new accounts in /etc/passwd; verify they are legitimate; check home directories for backdoors | Account Integrity |
| ✅ PASS | System binary modifications | No system binaries modified in last 7 days | Periodically verify system binary integrity | File Integrity |
| ✅ PASS | Failed login spike | Failed login attempts in recent logs: 14 (normal range) | Continue monitoring auth logs for brute force attempts | Authentication |
| ✅ PASS | SUID files | SUID binaries: 13 | Periodically review SUID inventory | Filesystem |
| ✅ PASS | Cron/Timers | cron.d=4, daily=9, hourly=0, user crontab lines=0, timers=19 | Keep cron/timers minimal and documented | Persistence |
| ✅ PASS | Process monitoring | Processes OK | Monitor with 'top -o %CPU' | Process Health |
| ✅ PASS | Suspicious connections | 3 external connections (normal for web servers) | Monitor periodically | Network Security |
| ❌ FAIL | Hidden system files | 13+ hidden files in system directories. Examples: /etc/cron.daily/.placeholder
/etc/skel/.bash_logout
/etc/skel/.profile
/etc/skel/.bashrc
/etc/cron.d/.placeholder | Investigate each file - may be malware/backdoors | Malware/Backdoors |
| ✅ PASS | Kernel modules | 88 modules loaded, all in standard paths | No action | Kernel Security |
| ✅ PASS | Reverse shell detection | No obvious reverse shell patterns detected | No action | Malware/Backdoors |
| ❌ FAIL | Password policy | No password quality settings found | Configure pam_pwquality or pam_cracklib for password complexity | Authentication |
| ✅ PASS | Container security | No container security issues detected | No action | Container Security |
| ❌ FAIL | ARP spoofing | Duplicate MAC addresses in ARP table: 04:42:1a:5e:2d:88
08:12:a5:7a:74:7a
0c:ee:99:85:20:84
38:f7:3d:10:06:db
46:77:5d:09:9e:e2
60:67:20:c5:72:ec
78:8a:86:be:e6:08
94:e2:3c:84:bd:ef
a2:44:a6:fb:08:1c
a6:d0:e7:23:01:9e
b4:7c:9c:c1:79:b1
cc:9e:a2:79:a6:73
d4:91:0f:a0:a5:34
e0:09:bf:7c:cd:78
e0:09:bf:81:16:cf
ea:21:33:3e:b4:25
f0:db:f8:19:f4:03
f8:54:b8:c6:26:c7
fc:a1:83:90:65:81 | URGENT: Possible ARP spoofing attack - investigate network immediately | Network Security |
| ✅ PASS | DNS tampering | DNS configuration OK (1 nameservers) | No action | Network Security |
| ✅ PASS | Crypto mining | No cryptocurrency mining activity detected | No action | Malware/Backdoors |
| ❌ FAIL | Critical binary integrity | World-writable critical binaries detected | URGENT: Fix permissions immediately - severe security risk | File Integrity |
| ✅ PASS | Log tampering | Log files appear intact (1000 auth, 1000 syslog entries) | No action | Log Security |
| ⚠️ WARN | Privilege escalation | Escalation vector found: Dangerous capabilities: /usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner, | Review and mitigate privilege escalation risks | Privilege Escalation |
| ✅ PASS | World-writable files | No world-writable files in system directories | No action | File Permissions |
| ✅ PASS | Deleted file handles | No suspicious deleted file handles | No action | Malware/Backdoors |

## Port Scan (lightweight)
| Port | State | Notes |
| --- | --- | --- |
| 22 | open | Connected |
| 80 | open | Connected |
| 5432 | open | Connected |

## Detailed Security Findings

### Top Processes by CPU/Memory
```
PID CMD                         %CPU %MEM
2555759 ps -eo pid,cmd,%cpu,%mem --  400  0.0
4031848 /usr/bin/zmc -m 1           56.4 11.3
1253622 /usr/bin/zmc -m 2           54.9 11.7
4098827 /usr/bin/zmc -m 3           52.7 10.9
3997229 /usr/bin/zmc -m 4           51.0 17.8
1164253 /zoneminder/cgi-bin/nph-zms 16.4  0.1
1164244 /zoneminder/cgi-bin/nph-zms 15.9  0.1
1164242 /zoneminder/cgi-bin/nph-zms 15.4  0.1
1164251 /zoneminder/cgi-bin/nph-zms 14.3  0.1
   1882 python3 -m homeassistant -- 11.2  1.2
2488899 /zoneminder/cgi-bin/nph-zms  8.5  0.1
2488896 /zoneminder/cgi-bin/nph-zms  7.9  0.1
2488902 /zoneminder/cgi-bin/nph-zms  7.0  0.1
2488903 /zoneminder/cgi-bin/nph-zms  4.9  0.1
   1732 mariadbd                     4.7  0.4
   1269 /usr/bin/dockerd -H fd:// -  1.2  0.1
   2596 nginx: worker process        0.9  0.0
   2588 nginx: worker process        0.7  0.0
   2593 nginx: worker process        0.3  0.0
```

### Disk Usage by Directory
```
711G	/
609G	/home
75G	/var
17G	/usr
1.9G	/mnt
197M	/boot
52M	/PATH_TO_YOUR_CONFIG
45M	/root
9.1M	/etc
88K	/tmp
28K	/snap
16K	/opt
16K	/lost+found
4.0K	/srv
4.0K	/sbin.usr-is-merged
4.0K	/media
4.0K	/lib.usr-is-merged
4.0K	/bin.usr-is-merged
```

### Available Updates
16 packages available for update

### Firewall Rules/Status
```
Status: inactive
```

### SSH Daemon Configuration Check
```
passwordauthentication yes
permitrootlogin without-password
port 22
```

### Failed Systemd Units
```
=== CRITICAL UNITS ===
[CRITICAL] ● systemd-networkd-wait-online.service loaded failed failed Wait for Network to be Configured
=== WARNING UNITS ===
[WARNING] ● apache2.service                      loaded failed failed The Apache HTTP Server
```

### Sudoers Configuration
```
Sudoers syntax: OK
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults	use_pty
root	ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo	ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
```

### Critical File Permissions
```
-rw-r--r-- /etc/passwd
-rw-r----- /etc/shadow
-rw-r--r-- /etc/ssh/sshd_config
-r--r----- /etc/sudoers
```

### SUID Binaries (recent activity)
```
1757981282.0000000000 Mon 15 Sep 2025 07:08:02 PM CDT /usr/bin/umount
1757981282.0000000000 Mon 15 Sep 2025 07:08:02 PM CDT /usr/bin/su
1757981282.0000000000 Mon 15 Sep 2025 07:08:02 PM CDT /usr/bin/mount
1750855373.0000000000 Wed 25 Jun 2025 07:42:53 AM CDT /usr/bin/sudo
1733140792.0000000000 Mon 02 Dec 2024 05:59:52 AM CST /usr/bin/pkexec
1717080755.0000000000 Thu 30 May 2024 09:52:35 AM CDT /usr/bin/passwd
1717080755.0000000000 Thu 30 May 2024 09:52:35 AM CDT /usr/bin/newgrp
1717080755.0000000000 Thu 30 May 2024 09:52:35 AM CDT /usr/bin/gpasswd
1717080755.0000000000 Thu 30 May 2024 09:52:35 AM CDT /usr/bin/chsh
1717080755.0000000000 Thu 30 May 2024 09:52:35 AM CDT /usr/bin/chfn
1712591877.0000000000 Mon 08 Apr 2024 10:57:57 AM CDT /usr/bin/fusermount3
1711959752.0000000000 Mon 01 Apr 2024 03:22:32 AM CDT /usr/bin/tcptraceroute.mt
1711843702.0000000000 Sat 30 Mar 2024 07:08:22 PM CDT /usr/bin/inetutils-traceroute
```

### Recent Root Logins
```
No recent root logins found (or last not available)
```

### Recent Successful SSH Logins (last 7 days)
```
Jan 08 11:25:43 juanjou sshd[2547045]: Accepted password for greg from 192.168.1.107 port 53662 ssh2
Jan 08 11:30:22 juanjou sshd[2549390]: Accepted password for greg from 192.168.1.107 port 62675 ssh2
Jan 08 11:30:40 juanjou sshd[2550078]: Accepted password for greg from 192.168.1.107 port 56542 ssh2
Jan 08 11:31:24 juanjou sshd[2550706]: Accepted password for greg from 192.168.1.107 port 53870 ssh2
Jan 08 11:32:28 juanjou sshd[2551780]: Accepted password for greg from 192.168.1.107 port 51479 ssh2
Jan 08 11:33:31 juanjou sshd[2552831]: Accepted password for greg from 192.168.1.107 port 59957 ssh2
Jan 08 11:34:32 juanjou sshd[2553872]: Accepted password for greg from 192.168.1.107 port 55369 ssh2
Jan 08 11:35:34 juanjou sshd[2554909]: Accepted password for greg from 192.168.1.107 port 61475 ssh2
```

### Recent Failed SSH Login Attempts (last 7 days)
```
No failed SSH logins found (or logs not available)
```

## Suggested Next Commands
- Inspect top CPU/mem: `ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head`
- Disk usage by dir: `sudo du -xhd1 / | sort -h`
- Pending updates (Debian/Ubuntu): `sudo apt-get update && sudo apt-get upgrade`
- Firewall (ufw): `sudo ufw status verbose`
- SSH hardening: edit `/etc/ssh/sshd_config` then `sudo systemctl reload sshd`

Notes: Port scan is TCP connect scan on provided/common ports; results may be filtered by firewalls.

---

## Auto-Remediate

Copy and paste these commands to fix the identified issues. Review each command before execution.

### 1. Free up disk space (94% usage - CRITICAL)
```bash
# Find top 10 largest directories
sudo du -xhd1 / 2>/dev/null | sort -rh | head -10

# Clean package cache
sudo apt-get clean
sudo apt-get autoremove -y

# Remove old kernels (keep current + one previous)
sudo apt-get autoremove --purge -y

# Rotate and compress old logs
sudo journalctl --vacuum-time=7d

# Find and review large log files
find /var/log -type f -size +100M -exec ls -lh {} \;
```

### 2. Apply security updates (15 pending - CRITICAL)
```bash
# Update package list and apply all security updates
sudo apt-get update
sudo apt-get upgrade -y

# If reboot is required after updates
if [ -f /var/run/reboot-required ]; then
    echo "Reboot required - schedule maintenance window"
    cat /var/run/reboot-required.pkgs
fi
```

### 3. Harden SSH configuration
```bash
# Backup current SSH config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

# Disable password authentication (ensure SSH keys are set up first!)
sudo sed -i 's/^#*PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Disable root login
sudo sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

# Change SSH port (optional - update firewall rules accordingly)
# sudo sed -i 's/^#*Port 22/Port 2222/' /etc/ssh/sshd_config

# Test configuration before restarting
sudo sshd -t && sudo systemctl restart sshd
```

### 4. Enable and configure firewall
```bash
# Install UFW if not present
sudo apt-get install -y ufw

# Allow SSH (CRITICAL - do this first to avoid lockout!)
sudo ufw allow 22/tcp comment 'SSH'

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'

# Allow PostgreSQL (if needed)
sudo ufw allow 5432/tcp comment 'PostgreSQL'

# Enable firewall
sudo ufw --force enable

# Check status
sudo ufw status verbose
```

### 5. Configure password policy (PAM)
```bash
# Install password quality checking library
sudo apt-get install -y libpam-pwquality

# Configure minimum password requirements
sudo tee /etc/security/pwquality.conf > /dev/null <<EOF
# Minimum password length
minlen = 12

# Require at least one digit
dcredit = -1

# Require at least one uppercase letter
ucredit = -1

# Require at least one lowercase letter
lcredit = -1

# Require at least one special character
ocredit = -1

# Number of character classes required
minclass = 3
EOF
```

### 6. Investigate ARP spoofing (URGENT)
```bash
# View current ARP table
ip neigh show

# Clear ARP cache and rebuild
sudo ip neigh flush all

# Install arpwatch to monitor for ARP spoofing
sudo apt-get install -y arpwatch
sudo systemctl enable arpwatch
sudo systemctl start arpwatch

# Check for duplicate MACs (investigation required)
arp -a | awk '{print $4}' | sort | uniq -d
```

### 7. Fix world-writable critical binaries (URGENT)
```bash
# Find world-writable files in critical paths
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -type f -perm -002 -ls

# Remove world-write permission (review list first!)
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -type f -perm -002 -exec chmod o-w {} \;

# Verify correct permissions
ls -la /bin/bash /usr/bin/sudo /usr/bin/su
```

### 8. Review hidden files in system directories
```bash
# List all hidden files in system directories
find /etc /tmp /var/tmp /usr/bin -name ".*" -type f 2>/dev/null

# Remove placeholder files (usually safe)
sudo rm -f /etc/cron.daily/.placeholder /etc/cron.d/.placeholder

# Review other hidden files (may be legitimate config or malware)
# DO NOT blindly delete - investigate each file
```

### 9. Review recently created accounts
```bash
# List accounts created in last 30 days with details
awk -F: '{print $1, $3, $6}' /etc/passwd | while read user uid home; do
    if [ -d "$home" ]; then
        created=$(stat -c %W "$home" 2>/dev/null)
        if [ "$created" != "-" ] && [ "$created" != "0" ]; then
            age=$(( ($(date +%s) - $created) / 86400 ))
            if [ $age -lt 30 ]; then
                echo "User: $user (UID: $uid) - Age: $age days - Home: $home"
            fi
        fi
    fi
done

# Lock suspicious accounts (replace USERNAME)
# sudo usermod -L USERNAME
# sudo chage -E 0 USERNAME
```

### 10. Investigate abnormal network processes
```bash
# List all listening processes with details
sudo ss -tulpn | grep LISTEN

# Investigate processes on non-standard ports
sudo netstat -tulpn | grep -E ':(40000|11435) '

# Check process details
ps aux | grep -E 'PID_FROM_ABOVE'

# Stop suspicious service (if identified)
# sudo systemctl stop SERVICE_NAME
# sudo systemctl disable SERVICE_NAME
```

### 11. Review and minimize listening services
```bash
# List all systemd services
systemctl list-units --type=service --state=running

# Disable unnecessary services (review carefully!)
# sudo systemctl disable SERVICE_NAME
# sudo systemctl stop SERVICE_NAME

# Check what's listening on each port
sudo lsof -i -P -n | grep LISTEN
```

### 12. Fix failed systemd units
```bash
# Check status of failed units
systemctl status systemd-networkd-wait-online.service
systemctl status apache2.service

# If Apache is not needed, disable it
sudo systemctl disable apache2.service

# Fix networkd wait timeout (if not using networkd)
sudo systemctl disable systemd-networkd-wait-online.service
```

### 13. Monitor system load
```bash
# Check what's causing high load
top -o %CPU

# Review ZoneMinder processes (causing high CPU)
# Consider optimizing ZoneMinder configuration or reducing camera load

# Check I/O wait
iostat -x 2 5
```

### Post-Remediation Checklist
```bash
# Re-run security scan to verify fixes
python -m linux_health 192.168.1.84 greg PASSWORD --format md --output scan_report_after.md

# Compare before/after
# Review all FAIL and WARN items to ensure they're resolved

# Schedule regular scans
# Add to crontab: 0 2 * * * /path/to/scan.sh
```

**⚠️ WARNINGS:**
- Always backup configuration files before making changes
- Test SSH changes from a second session to avoid lockout
- Review firewall rules carefully to avoid blocking legitimate traffic  
- Investigate before deleting - some "suspicious" items may be legitimate
- Schedule a maintenance window for reboots if required after updates