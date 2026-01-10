# Linux Host Health Report: greg-air-linux

Generated: 2026-01-10 19:40:01 UTC

## System
- Hostname: greg-air-linux
- OS: Ubuntu 25.10 (Questing Quokka)
- Kernel: 6.17.0-8-generic
- Uptime: up 13 hours, 41 minutes
- Logged-in users: # users=0

## Summary
- Checks: 39 (✅ 25 / ⚠️ 11 / ❌ 3)
- Open ports (scanned): 1 -> 22

## Checklist
| Status | Item | Details | Recommendation | Category |
| --- | --- | --- | --- | --- |
| ❌ FAIL | Hidden system files | 20+ hidden files in system directories. Examples: /tmp/greg-code-zsh/.zcompdump
/tmp/greg-code-zsh/.zlogin
/tmp/greg-code-zsh/.zshenv
/tmp/greg-code-zsh/.zprofile
/tmp/greg-code-zsh/.zshrc | Investigate each file - may be malware/backdoors | Malware/Backdoors |
| ❌ FAIL | Reverse shell detection | Possible reverse shell detected: greg       32363  0.0  0.0  11004  3600 pts/3    Ss+  13:03   0:01 /usr/bin/zsh -i
greg       35860  0.0  0.0  10864  4596 pts/4    Ss+  13:09   0:00 /usr/bin/zsh -i
greg       37253  0.0  0.0  10964  5800 pts/5    Ss   13:11   0:00 /usr/bin/zsh -i | URGENT: Investigate immediately - possible active compromise | Malware/Backdoors |
| ❌ FAIL | Critical binary integrity | World-writable critical binaries detected | URGENT: Fix permissions immediately - severe security risk | File Integrity |
| ⚠️ WARN | PasswordAuthentication | Password authentication enabled | Set 'PasswordAuthentication no' and use SSH keys | SSH |
| ⚠️ WARN | PermitRootLogin | Root login over SSH enabled | Set 'PermitRootLogin no' and use sudo from user accounts | SSH |
| ⚠️ WARN | SSH Port | Using default port 22 | Consider non-default port + fail2ban/ufw | SSH |
| ⚠️ WARN | SSH Security Rating | ❌ Poor (0/5) | Review each recommendation above | SSH |
| ⚠️ WARN | Firewall | Firewall inactive | Enable host firewall (ufw enable or firewall-cmd --permanent --add-service=ssh) | Network |
| ⚠️ WARN | Auth failures (24h) | Could not read logs: 0 | Check journalctl /var/log/auth.log | Auth |
| ⚠️ WARN | Listening services | Many public listeners (44): SSH=2, DNS=4, Other=38 | Review 'ss -tulpn' for unexpected services; tighten firewall/hosts.allow | Network |
| ⚠️ WARN | Abnormal network processes | Found 1 suspicious listener(s): 0.0.0.0:* on port 11435: non-standard port | Review listening processes: ss -tulpn; investigate unfamiliar services and ports | Network |
| ⚠️ WARN | Recently created accounts | Found 10 account(s) created in last 30 days: greg (0 days old); man (0 days old); daemon (0 days old); +7 more | Review new accounts in /etc/passwd; verify they are legitimate; check home directories for backdoors | Account Integrity |
| ⚠️ WARN | Privilege escalation | Escalation vector found: Dangerous capabilities: /snap/core20/2686/usr/bin/ping cap_net_raw=ep
/snap/snapd/25935/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,c | Review and mitigate privilege escalation risks | Privilege Escalation |
| ⚠️ WARN | Deleted file handles | Processes with deleted file handles: pipewire   2916 greg  35u   REG    0,1     2312     0    3323 /memfd:pipewire-memfd:flags=0x0000000f,type=2,size=2312 (deleted)
pipewire   2916 greg  38u   REG    0,1     2312     0    3324 /memfd:pipewire-memfd:flags=0x0000000f,type=2,size=2312 (deleted)
pipewire   2916 greg  45u   REG    0,1     2 | May indicate rootkit or running malware - investigate processes | Malware/Backdoors |
| ✅ PASS | Disk usage | Root filesystem at 39% | Keep below 80% to avoid surprises | Storage |
| ✅ PASS | Memory | 41% available (3008 MiB of 7330 MiB) | No action | Memory |
| ✅ PASS | System load | Load averages OK: 1m=1.81, 5m=1.71, 15m=1.58 | No action | CPU/Load |
| ✅ PASS | Reboot needed | No reboot-required flag | No action | Patching |
| ✅ PASS | Pending updates | 0 packages pending | No action | Patching |
| ✅ PASS | Time sync | NTP synchronized | Keep chrony/systemd-timesyncd running | Time |
| ✅ PASS | Root accounts | Only root has UID 0 | No action | Accounts |
| ✅ PASS | Stale user accounts | Could not retrieve last login data | Run 'lastlog' manually to verify | Accounts |
| ✅ PASS | Root logins | No recent root logins in last output | Keep using sudo from users | Auth |
| ✅ PASS | Suspicious process locations | No processes running from /tmp, /var/tmp, or /dev/shm | Continue monitoring for suspicious execution patterns | Process Integrity |
| ✅ PASS | Unexpected sudo usage | No obvious sudo misconfigurations detected | Monitor sudo logs regularly for privilege escalation attempts | Privilege Escalation |
| ✅ PASS | System binary modifications | No system binaries modified in last 7 days | Periodically verify system binary integrity | File Integrity |
| ✅ PASS | Failed login spike | Failed login attempts in recent logs: 1 (normal range) | Continue monitoring auth logs for brute force attempts | Authentication |
| ✅ PASS | SUID files | SUID binaries: 14 | Periodically review SUID inventory | Filesystem |
| ✅ PASS | Cron/Timers | cron.d=3, daily=9, hourly=0, user crontab lines=0, timers=23 | Keep cron/timers minimal and documented | Persistence |
| ✅ PASS | Process monitoring | Processes OK | Monitor with 'top -o %CPU' | Process Health |
| ✅ PASS | Suspicious connections | 20 external connections (normal for web servers) | Monitor periodically | Network Security |
| ✅ PASS | Kernel modules | 144 modules loaded, all in standard paths | No action | Kernel Security |
| ✅ PASS | Password policy | Password quality module configured | Verify complexity requirements are adequate | Authentication |
| ✅ PASS | Container security | No container security issues detected | No action | Container Security |
| ✅ PASS | ARP spoofing | ARP table clean (6 entries) | No action | Network Security |
| ✅ PASS | DNS tampering | DNS configuration OK (1 nameservers) | No action | Network Security |
| ✅ PASS | Crypto mining | No cryptocurrency mining activity detected | No action | Malware/Backdoors |
| ✅ PASS | Log tampering | Log files appear intact (1000 auth, 1000 syslog entries) | No action | Log Security |
| ✅ PASS | World-writable files | No world-writable files in system directories | No action | File Permissions |

## Port Scan (lightweight)
| Port | State | Notes |
| --- | --- | --- |
| 22 | open | Connected |

## Detailed Security Findings

### Top Processes by CPU/Memory
```
PID CMD                         %CPU %MEM
  11164 bitcoin-qt                  77.4 31.1
  34156 /snap/code/218/usr/share/co  6.4  4.5
   3915 /snap/firefox/7559/usr/lib/  6.1  2.6
  31978 /proc/self/exe --type=gpu-p  5.6  1.7
  31822 htop                         5.3  0.0
   3127 /usr/bin/gnome-shell         2.9  1.5
  35606 /proc/self/exe --type=utili  2.9  3.9
  32031 /proc/self/exe --type=utili  1.9  1.6
  31957 /snap/code/218/usr/share/co  1.8  2.9
  56915 python -m linux_health loca  1.4  0.2
  31870 /snap/code/218/usr/share/co  1.0  1.7
  32045 /proc/self/exe --type=utili  1.0  1.5
  31723 /snap/firefox/7559/usr/lib/  0.9  1.1
   9117 /usr/libexec/gnome-terminal  0.8  0.4
  32018 /proc/self/exe --type=utili  0.6  1.1
  56095 /snap/code/218/usr/share/co  0.6  1.2
  36601 /snap/code/218/usr/share/co  0.4  1.8
  33204 /snap/code/218/usr/share/co  0.4  1.1
   4263 /snap/firefox/7559/usr/lib/  0.3  1.1
```

### Disk Usage by Directory
```
40G	/
17G	/home
13G	/var
5.8G	/usr
341M	/opt
215M	/boot
13M	/etc
4.5M	/root
72K	/snap
16K	/lost+found
4.0K	/srv
4.0K	/mnt
4.0K	/media
4.0K	/cdrom
```

### Available Updates
0 packages available for update

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
=== WARNING UNITS ===
[WARNING] ● snap.canonical-livepatch.canonical-livepatchd.service loaded failed failed Service for snap application canonical-livepatch.canonical-livepatchd
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
1765203939.0000000000 Mon 08 Dec 2025 08:25:39 AM CST /usr/bin/mullvad-exclude
1758804440.0000000000 Thu 25 Sep 2025 07:47:20 AM CDT /usr/bin/sudo.ws
1758552148.0000000000 Mon 22 Sep 2025 09:42:28 AM CDT /usr/bin/umount
1758552148.0000000000 Mon 22 Sep 2025 09:42:28 AM CDT /usr/bin/su
1758552148.0000000000 Mon 22 Sep 2025 09:42:28 AM CDT /usr/bin/newgrp
1758552148.0000000000 Mon 22 Sep 2025 09:42:28 AM CDT /usr/bin/mount
1757268521.0000000000 Sun 07 Sep 2025 01:08:41 PM CDT /usr/sbin/pppd
1757171794.0000000000 Sat 06 Sep 2025 10:16:34 AM CDT /usr/bin/passwd
1757171794.0000000000 Sat 06 Sep 2025 10:16:34 AM CDT /usr/bin/gpasswd
1757171794.0000000000 Sat 06 Sep 2025 10:16:34 AM CDT /usr/bin/chsh
1757171794.0000000000 Sat 06 Sep 2025 10:16:34 AM CDT /usr/bin/chfn
1755700582.0000000000 Wed 20 Aug 2025 09:36:22 AM CDT /usr/bin/fusermount3
1737142666.0000000000 Fri 17 Jan 2025 01:37:46 PM CST /usr/bin/pkexec
1728114348.0000000000 Sat 05 Oct 2024 02:45:48 AM CDT /usr/bin/ntfs-3g
```

### Recent Root Logins
```
No recent root logins found (or last not available)
```

### Recent Successful SSH Logins (last 7 days)
```
Jan 10 13:39:02 greg-air-linux sshd-session[56952]: Accepted password for greg from 127.0.0.1 port 40528 ssh2
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