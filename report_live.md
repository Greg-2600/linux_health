# Linux Host Health Report: debian

Generated: 2026-01-08 15:59:49 UTC

## System
- Hostname: debian
- OS: Debian GNU/Linux 12 (bookworm)
- Kernel: 6.1.0-18-amd64
- Uptime: up 1 year, 32 weeks, 1 day, 20 hours, 51 minutes
- Logged-in users: greg
# users=1

## Summary
- Checks: 20 (✅ 8 / ⚠️ 12 / ❌ 0)
- Open ports (scanned): 4 -> 21, 22, 53, 80

## Checklist
| Status | Item | Details | Recommendation | Category |
| --- | --- | --- | --- | --- |
| ✅ PASS | Disk usage | Root filesystem at 73% | Keep below 80% to avoid surprises | Storage |
| ✅ PASS | Memory | 46% available (44881 MiB of 96632 MiB) | No action | Memory |
| ⚠️ WARN | System load | Elevated load averages: 1m=6.21, 5m=6.04, 15m=5.91 | Check running processes with 'ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head' | CPU/Load |
| ⚠️ WARN | Reboot needed | /var/run/reboot-required present | Schedule a reboot during maintenance window | Patching |
| ⚠️ WARN | Pending updates | 45 packages pending (non-security) | Update soon: 'sudo apt-get update && sudo apt-get upgrade' (adjust for distro) | Patching |
| ⚠️ WARN | PasswordAuthentication | Password authentication enabled | Set 'PasswordAuthentication no' and use SSH keys | SSH |
| ⚠️ WARN | PermitRootLogin | Root login over SSH enabled | Set 'PermitRootLogin no' and use sudo from user accounts | SSH |
| ⚠️ WARN | SSH Port | Using default port 22 | Consider non-default port + fail2ban/ufw | SSH |
| ⚠️ WARN | SSH Security Rating | ❌ Poor (0/5) | Review each recommendation above | SSH |
| ⚠️ WARN | Firewall | Firewall inactive | Enable host firewall (ufw enable or firewall-cmd --permanent --add-service=ssh) | Network |
| ✅ PASS | Time sync | NTP synchronized | Keep chrony/systemd-timesyncd running | Time |
| ✅ PASS | Root accounts | Only root has UID 0 | No action | Accounts |
| ✅ PASS | Stale user accounts | No users inactive >90 days | Monitor login activity periodically | Accounts |
| ✅ PASS | Auth failures (24h) | 1 failed SSH logins | Keep monitoring and consider fail2ban | Auth |
| ⚠️ WARN | Root logins | 1 recent root login entries | Prefer sudo from named users; audit 'last root' for legitimacy | Auth |
| ⚠️ WARN | Listening services | Many public listeners (69): SSH=2, HTTP=1, DB=2, DNS=4, Other=60 | Review 'ss -tulpn' for unexpected services; tighten firewall/hosts.allow | Network |
| ⚠️ WARN | Abnormal network processes | Found 14 suspicious listener(s): 0.0.0.0:* on port 11434: non-standard port; 0.0.0.0:* on port 8888: non-standard port; python3: Python interpreter listening (potential reverse shell); +11 more | Review listening processes: ss -tulpn; investigate unfamiliar services and ports | Network |
| ✅ PASS | SUID files | SUID binaries: 19 | Periodically review SUID inventory | Filesystem |
| ⚠️ WARN | Cron/Timers | cron.d=7, daily=15, hourly=0, user crontab lines=24, timers=15 | Review cron entries and systemd timers for legitimacy; check /etc/cron.* and systemctl list-timers | Persistence |
| ✅ PASS | Process monitoring | Processes OK | Monitor with 'top -o %CPU' | Process Health |

## Port Scan (lightweight)
| Port | State | Notes |
| --- | --- | --- |
| 21 | open | Connected |
| 22 | open | Connected |
| 53 | open | Connected |
| 80 | open | Connected |

## Detailed Security Findings

### Top Processes by CPU/Memory
```
PID CMD                         %CPU %MEM
1154343 /opt/Tdarr/Tdarr_Node/Tdarr  125  0.0
1154336 /opt/Tdarr/Tdarr_Node/Tdarr  112  0.0
3427923 ./Tdarr_Server              67.5  1.6
2937752 /usr/bin/mullvad-daemon -v  49.4  0.1
2796968 /opt/bazarr/venv/bin/python 29.6  0.4
4121639 /opt/readarr_audio_new/Read 26.5  2.1
2938615 /usr/bin/jellyfin --webdir= 14.1  0.7
3975549 /usr/lib/firefox-esr/firefo 11.8  1.0
2675604 /opt/Radarr/Radarr -nobrows 11.8  0.7
2938605 /usr/bin/transmission-daemo  8.8  0.2
   9661 /usr/bin/gnome-software --g  7.9  0.7
2938665 /opt/Sonarr/Sonarr -nobrows  7.6  1.7
3050946 /usr/lib/virtualbox/VBoxHea  7.0  4.3
 640034 /usr/lib/firefox-esr/firefo  6.2  0.7
 639491 /usr/lib/firefox-esr/firefo  5.1  0.4
2594000 mono /opt/Lidarr/Lidarr.exe  4.4  1.9
1587366 ssh -x -a -oClearAllForward  3.9  0.0
3641810 sshd: greg@notty             3.6  0.0
1031516 /usr/bin/find / -ignore_rea  3.2  0.0
```

### Disk Usage by Directory
```
40M	/etc
```

### Available Updates
45 packages available for update

### Firewall Rules/Status
```
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain FORWARD (policy DROP 999 packets, 1068K bytes)
 pkts bytes target     prot opt in     out     source               destination         
 690K  385M DOCKER-USER  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
 690K  385M DOCKER-ISOLATION-STAGE-1  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
 396K  332M ACCEPT     0    --  *      docker0  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
 1275 98872 DOCKER     0    --  *      docker0  0.0.0.0/0            0.0.0.0/0           
 291K   52M ACCEPT     0    --  docker0 !docker0  0.0.0.0/0            0.0.0.0/0           
    0     0 ACCEPT     0    --  docker0 docker0  0.0.0.0/0            0.0.0.0/0           
    0     0 ACCEPT     0    --  *      br-7bf3a8e4f97a  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
    0     0 DOCKER     0    --  *      br-7bf3a8e4f97a  0.0.0.0/0            0.0.0.0/0           
    0     0 ACCEPT     0    --  br-7bf3a8e4f97a !br-7bf3a8e4f97a  0.0.0.0/0            0.0.0.0/0           
    0     0 ACCEPT     0    --  br-7bf3a8e4f97a br-7bf3a8e4f97a  0.0.0.0/0            0.0.0.0/0           

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain DOCKER (2 references)
 pkts bytes target     prot opt in     out     source               destination         
  218 13024 ACCEPT     6    --  !docker0 docker0  0.0.0.0/0            172.17.0.2           tcp dpt:8080

Chain DOCKER-ISOLATION-STAGE-1 (1 references)
 pkts bytes target     prot opt in     out     source               destination         
 291K   52M DOCKER-ISOLATION-STAGE-2  0    --  docker0 !docker0  0.0.0.0/0            0.0.0.0/0           
    0     0 DOCKER-ISOLATION-STAGE-2  0    --  br-7bf3a8e4f97a !br-7bf3a8e4f97a  0.0.0.0/0            0.0.0.0/0           
 690K  385M RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0           

Chain DOCKER-ISOLATION-STAGE-2 (2 references)
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
[CRITICAL] ● networking.service      loaded failed failed Raise network interfaces
=== WARNING UNITS ===
[WARNING] ● apache2.service         loaded failed failed The Apache HTTP Server
[WARNING] ● caddy.service           loaded failed failed Caddy
[WARNING] ● filtron.service         loaded failed failed filtron
[WARNING] ● lidarr.service          loaded failed failed Lidarr Daemon
[WARNING] ● lighttpd.service        loaded failed failed Lighttpd Daemon
[WARNING] ● mongod.service          loaded failed failed MongoDB Database Server
[WARNING] ● morty.service           loaded failed failed morty
[WARNING] ● plexmediaserver.service loaded failed failed Plex Media Server
[WARNING] ● radarr.service          loaded failed failed Radarr Daemon
[WARNING] ● sling.service           loaded failed failed SlingBox Server Service
[WARNING] ● tautulli.service        loaded failed failed Tautulli - Stats for Plex Media Server usage
```

### Sudoers Configuration
```
Sudoers syntax: OK
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root	ALL=(ALL:ALL) ALL
%sudo	ALL=(ALL:ALL) ALL
greg	ALL=(ALL:ALL) ALL
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
1765720801.0000000000 Sun 14 Dec 2025 08:00:01 AM CST /usr/bin/newgrp
1765203939.0000000000 Mon 08 Dec 2025 08:25:39 AM CST /usr/bin/mullvad-exclude
1750750190.0000000000 Tue 24 Jun 2025 02:29:50 AM CDT /usr/bin/sudo
1742639114.0000000000 Sat 22 Mar 2025 05:25:14 AM CDT /usr/sbin/exim4
1732219314.0000000000 Thu 21 Nov 2024 02:01:54 PM CST /usr/bin/umount
1732219314.0000000000 Thu 21 Nov 2024 02:01:54 PM CST /usr/bin/su
1732219314.0000000000 Thu 21 Nov 2024 02:01:54 PM CST /usr/bin/mount
1730038570.0000000000 Sun 27 Oct 2024 09:16:10 AM CDT /usr/bin/ntfs-3g
1692784899.0000000000 Wed 23 Aug 2023 05:01:39 AM CDT /usr/bin/inetutils-traceroute
1681852035.0000000000 Tue 18 Apr 2023 04:07:15 PM CDT /usr/bin/fusermount3
1675202724.0000000000 Tue 31 Jan 2023 04:05:24 PM CST /usr/bin/pkexec
1665850822.0000000000 Sat 15 Oct 2022 11:20:22 AM CDT /usr/bin/at
1661522805.0000000000 Fri 26 Aug 2022 09:06:45 AM CDT /usr/sbin/mount.cifs
1652500224.0000000000 Fri 13 May 2022 10:50:24 PM CDT /usr/sbin/pppd
1581087254.0000000000 Fri 07 Feb 2020 08:54:14 AM CST /usr/bin/passwd
1581087254.0000000000 Fri 07 Feb 2020 08:54:14 AM CST /usr/bin/gpasswd
1581087254.0000000000 Fri 07 Feb 2020 08:54:14 AM CST /usr/bin/chsh
1581087254.0000000000 Fri 07 Feb 2020 08:54:14 AM CST /usr/bin/chfn
1563821009.0000000000 Mon 22 Jul 2019 01:43:29 PM CDT /usr/bin/tcptraceroute.mt
```

### Recent Root Logins
```
No recent root logins found (or last not available)
```

### Recent Successful SSH Logins (last 7 days)
```
Jan 07 15:35:42 debian sshd[656665]: Accepted password for greg from 192.168.1.107 port 60971 ssh2
Jan 07 15:50:44 debian sshd[663583]: Accepted password for greg from 192.168.1.107 port 63633 ssh2
Jan 07 15:51:39 debian sshd[664075]: Accepted password for greg from 192.168.1.107 port 64410 ssh2
Jan 07 16:26:20 debian sshd[674580]: Accepted password for greg from 192.168.1.107 port 51681 ssh2
Jan 07 16:29:29 debian sshd[675748]: Accepted password for greg from 192.168.1.107 port 53150 ssh2
Jan 07 16:30:21 debian sshd[676255]: Accepted password for greg from 192.168.1.107 port 56549 ssh2
Jan 07 22:06:47 debian sshd[760935]: Accepted password for greg from 192.168.1.107 port 57920 ssh2
Jan 07 22:07:53 debian sshd[761336]: Accepted password for greg from 192.168.1.107 port 56558 ssh2
Jan 07 23:51:34 debian sshd[785342]: Accepted password for greg from 192.168.1.107 port 54598 ssh2
Jan 08 09:59:04 debian sshd[1153374]: Accepted password for greg from 192.168.1.107 port 53263 ssh2
```

### Recent Failed SSH Login Attempts (last 7 days)
```
Jan 07 16:35:25 debian sshd[678187]: Failed password for greg from 192.168.1.107 port 63622 ssh2
```

## Suggested Next Commands
- Inspect top CPU/mem: `ps -eo pid,cmd,%cpu,%mem --sort=-%cpu | head`
- Disk usage by dir: `sudo du -xhd1 / | sort -h`
- Pending updates (Debian/Ubuntu): `sudo apt-get update && sudo apt-get upgrade`
- Firewall (ufw): `sudo ufw status verbose`
- SSH hardening: edit `/etc/ssh/sshd_config` then `sudo systemctl reload sshd`

Notes: Port scan is TCP connect scan on provided/common ports; results may be filtered by firewalls.