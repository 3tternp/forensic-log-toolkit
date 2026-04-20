# 🔍 Forensic Log Collection Toolkit

> **Full-spectrum log acquisition and parsing for Linux and Windows installation date to present**

| | |
|---|---|
| **Author** | Prem Basnet (Astra) |
| **Version** | 2.0 |
| **License** | Internal / Forensic Use |
| **Platforms** | Linux (Bash) · Windows (PowerShell 5.1+) |

---

## Table of Contents

- [Overview](#overview)
- [Files in this Toolkit](#files-in-this-toolkit)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Output Structure](#output-structure)
- [Log Coverage Linux](#log-coverage--linux)
- [Log Coverage Windows](#log-coverage--windows)
- [CSV Output Reference](#csv-output-reference)
- [Chain of Custody](#chain-of-custody)
- [Operational Notes](#operational-notes)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## Overview

This toolkit provides two forensic log collection scripts one for Linux (Bash) and one for Windows (PowerShell) designed to acquire, parse, and structure all available system logs from the date of OS installation through to the moment of collection. Raw logs are never dumped directly; every log source is normalized into structured, analysis-ready output.

The primary use cases are:

- **Incident Response**  rapid acquisition of all relevant evidence from a potentially compromised host
- **Forensic Investigation**  building a complete timeline of system activity from first boot
- **Threat Hunting** structured CSV outputs suitable for ingestion into SIEM platforms (Trident, Splunk, ELK, Sentinel)
- **Compliance Auditing** documented evidence collection with chain-of-custody hashing

Both scripts are designed to be run without any external dependencies beyond what ships with the OS. No third-party tools, no Python packages, no pip installs required.

---

## Files in this Toolkit

```
forensic-log-toolkit/
├── forensic_linux_log_collector.sh      # Bash script for Linux
├── forensic_windows_log_collector.ps1   # PowerShell script for Windows
└── README.md                            # This file
```

---

## Prerequisites

### Linux

| Requirement | Notes |
|---|---|
| Bash 4.0+ | Available on all modern Linux distributions |
| Root / sudo | Required for auth logs, audit logs, btmp, /proc access |
| `awk`, `grep`, `find`, `stat`, `ss` | Standard on all distributions |
| `journalctl` | Required for systemd journal (optional — falls back gracefully) |
| `last`, `lastb` | Required for login history (`util-linux` package) |
| `ausearch` | Optional  used as fallback if auditd is installed |

> Running without root will still collect a significant amount of data but will skip `/var/log/auth.log`, `/var/log/audit/audit.log`, `btmp` (failed login history), and some `/proc` entries.

### Windows

| Requirement | Notes |
|---|---|
| PowerShell 5.1+ | Included in Windows 8.1 / Server 2012 R2 and later |
| Administrator privileges | Required for Security event log, audit logs, WMI |
| Windows Event Log service | Must be running (default) |
| Execution Policy | Set to `Bypass` or `RemoteSigned` for the session |

> PowerShell 7+ (Core) is also fully supported.

---

## Quick Start

### Linux

```bash
# Clone or copy the script to the target system
chmod +x forensic_linux_log_collector.sh

# Run with root for complete coverage
sudo ./forensic_linux_log_collector.sh

# Output will be in the current directory:
# ./forensic_logs_<hostname>_<timestamp>/
```

### Windows

Open PowerShell **as Administrator**, then:

```powershell
# Allow script execution for this session only
Set-ExecutionPolicy Bypass -Scope Process -Force

# Run the collector
.\forensic_windows_log_collector.ps1

# Optional: specify a custom output path
.\forensic_windows_log_collector.ps1 -OutputPath "C:\Evidence\Case001"

# Optional: limit events per log source (default 5000)
.\forensic_windows_log_collector.ps1 -MaxEventsPerLog 10000
```

#### Windows Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | String | `Desktop\ForensicLogs_<host>_<ts>` | Directory for all output files |
| `-MaxEventsPerLog` | Int | `5000` | Max events to pull per event log source |
| `-SkipLargeScans` | Switch | `false` | Skip time-intensive registry scans |

---

## Output Structure

### Linux Output

```
forensic_logs_<hostname>_<timestamp>/
├── FORENSIC_REPORT_<hostname>_<timestamp>.txt   # Human-readable full report
├── SUMMARY.txt                                  # Collection summary & statistics
├── csv/
│   ├── system_users.csv
│   ├── auth_successful_logins.csv
│   ├── auth_failed_logins.csv
│   ├── ssh_logins.csv
│   ├── sudo_usage.csv
│   ├── kernel_events.csv
│   ├── service_events.csv
│   ├── suid_sgid_files.csv
│   ├── world_writable.csv
│   ├── cron_jobs.csv
│   ├── firewall_blocks.csv
│   ├── web_access.csv
│   ├── package_installs.csv
│   ├── active_connections.csv
│   ├── audit_events.csv
│   ├── recently_modified.csv
│   ├── processes.csv
│   └── login_history_wtmp.csv
└── raw/                                         # Reserved for future raw captures
```

### Windows Output

```
ForensicLogs_<hostname>_<timestamp>/
├── FORENSIC_REPORT_<hostname>_<timestamp>.txt   # Human-readable full report
├── FORENSIC_REPORT_<hostname>_<timestamp>.html  # HTML report (reserved)
├── SUMMARY_<hostname>_<timestamp>.txt           # Collection summary
├── CSV/
│   ├── 00_system_info.csv
│   ├── 02a_logon_success.csv
│   ├── 02b_logon_failed.csv
│   ├── 02c_logoff.csv
│   ├── 02d_account_management.csv
│   ├── 02e_privilege_use.csv
│   ├── 02f_object_access.csv
│   ├── 02g_process_creation.csv
│   ├── 02h_audit_policy_change.csv
│   ├── 03a_system_errors.csv
│   ├── 03b_service_events.csv
│   ├── 03c_startupshutdown.csv
│   ├── 03d_disk_driver_errors.csv
│   ├── 04a_application_errors.csv
│   ├── 04b_app_crashes.csv
│   ├── 05a_ps_scriptblock.csv
│   ├── 05b_ps_engine.csv
│   ├── 06a_scheduled_tasks.csv
│   ├── 06b_scheduled_tasks_current.csv
│   ├── 07a_network_connections.csv
│   ├── 07b_dns_cache.csv
│   ├── 07c_network_adapters.csv
│   ├── 07d_ip_config.csv
│   ├── 07e_arp_cache.csv
│   ├── 07f_firewall_events.csv
│   ├── 08a_rdp_sessions.csv
│   ├── 08b_rdp_auth.csv
│   ├── 09a_defender_events.csv
│   ├── 10a_wmi_events.csv
│   ├── 10b_applocker_events.csv
│   ├── 11a_usb_events.csv
│   ├── 11b_usb_registry.csv
│   ├── 12a_local_users.csv
│   ├── 12b_local_groups.csv
│   ├── 12c_autoruns.csv
│   ├── 13a_processes.csv
│   ├── 13b_services.csv
│   └── 14_installed_software.csv
└── RAW/
```

---

## Log Coverage Linux

### Section 1: System Installation Date
Detects the OS installation timestamp using multiple methods in priority order: filesystem root inode birth time, dpkg log first entry, oldest RPM transaction timestamp, `/lost+found` ctime, and oldest entry in `/var/log`. Also collects OS version, kernel version, architecture, and current uptime.

### Section 2: Authentication & Login Logs
Sources: `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL/CentOS)

Parses and structures:
- All successful interactive and network logons (via `last -F`)
- All failed login attempts with username, source IP, and failure type
- SSH accepted and rejected connections with key method and source IP
- Every `sudo` command invocation with user, target user, TTY, and full command

### Section 3: System / Kernel Logs
Sources: `dmesg`, `journalctl`

Captures kernel ring buffer events filtered for errors, warnings, OOM kills, hardware faults, segfaults, and call traces. SystemD journal is queried for error-and-above severity events across all units. Service start/stop/fail events are extracted and tagged.

### Section 4: Security Logs
Sources: filesystem (`find`), `/var/log/ufw.log`, `/var/log/audit/audit.log`, crontab files

Enumerates all SUID/SGID binaries system-wide, all world-writable files (excluding `/proc`, `/sys`, `/dev`, `/run`), all cron jobs across system and user crontabs, and all UFW/iptables block events parsed into structured fields (protocol, source IP/port, destination IP/port, interface). AppArmor and SELinux denial events are extracted separately.

### Section 5: Application Logs
Sources: Apache/Nginx access and error logs, MySQL/PostgreSQL logs, dpkg/rpm history

Web access logs are parsed into IP, method, URI, status code, and user agent fields. Suspicious patterns (path traversal, SQL injection attempts, XSS) are flagged inline. Package installation history is normalized to timestamp, action, package name, and version.

### Section 6: Network & Access Logs
Sources: `ss`, `ip`, `arp`, `/etc/resolv.conf`, `/etc/hosts`, syslog

Captures all active TCP/UDP connections with process name and PID, all listening ports, the ARP neighbor cache, DNS resolver configuration, and the hosts file. Network-related syslog events (DHCP, DNS, NetworkManager) are also extracted.

### Section 7: Audit Logs (auditd)
Sources: `/var/log/audit/audit.log`, `ausearch`

Parses SYSCALL, PATH, and EXECVE audit records into structured fields (timestamp, UID, PID, executable, key, result). USER_LOGIN, USER_LOGOUT, and USER_AUTH events are extracted separately for logon timeline reconstruction.

### Section 8: File Integrity & Suspicious Activity
Sources: filesystem (`find`, `stat`), `/etc/passwd`, `/etc/shadow`, `~/.bash_history`

Identifies files modified in the last 7 days within key directories (`/etc`, `/bin`, `/sbin`, `/usr/bin`, `/tmp`), hidden files in sensitive locations, executables in world-writable temp directories, all accounts with UID 0, accounts with empty passwords, and command history for all user accounts.

### Section 9: Running Processes & Scheduled Tasks
Sources: `ps`, `systemctl`, `atq`

Full process tree with parent/child relationships, CPU/memory stats, and start times. All active systemd timers and AT job queue entries are captured.

### Section 10: Login Records (wtmp/btmp/utmp)
Sources: `last -F -w`, `lastb -F`, `w`, `last reboot`, `last shutdown`

Complete login history from wtmp (all historical sessions), failed login history from btmp, currently logged-in users from utmp, and full reboot/shutdown history.

---

## Log Coverage: Windows

### Security Event Log

| Event ID | Description | Forensic Value |
|---|---|---|
| 4624 | Successful logon | Logon type, source IP, auth package, logon GUID |
| 4625 | Failed logon | Failure reason, sub-status, source IP |
| 4634 / 4647 | Logoff / User-initiated logoff | Session duration calculation |
| 4720 | Account created | New account creation tracking |
| 4725 / 4726 | Account disabled / deleted | Account lifecycle |
| 4738 | Account changed | Attribute modification |
| 4740 | Account locked out | Brute-force indicators |
| 4756 / 4757 | Group membership added/removed | Privilege escalation tracking |
| 4672 | Special privileges assigned | Admin-level logon detection |
| 4673 / 4674 | Privileged service/operation | Sensitive operation auditing |
| 4663 | Object access attempt | File and registry access |
| 4688 | Process creation | Full command line, parent process |
| 4719 | Audit policy changed | Tampering detection |

### System Event Log

| Event ID | Description |
|---|---|
| 6005 / 6006 | Event log service started / stopped |
| 6008 | Unexpected shutdown (crash indicator) |
| 7034 | Service crashed unexpectedly |
| 7036 | Service state changed |
| 7045 | New service installed |
| 1074 | System shutdown initiated |
| 51 / 11 | Disk I/O errors |

### Specialized Logs

| Log Source | Event IDs | Coverage |
|---|---|---|
| PowerShell/Operational | 4104 | Script block logging with IOC flagging |
| Windows PowerShell | 400, 403, 600 | Engine lifecycle |
| TaskScheduler/Operational | 106, 141, 200, 201, 202 | Task registration, execution, deletion |
| TerminalServices-LocalSessionManager | 21–25, 39–40 | RDP session lifecycle |
| RemoteDesktopServices-RdpCoreTS | 131, 98 | RDP connection requests |
| Windows Defender/Operational | 1006–1119 | Threat detection and response |
| WMI-Activity/Operational | 5857–5861 | WMI persistence mechanisms |
| AppLocker/EXE and DLL | 8003–8007 | Application execution control |
| DriverFrameworks-UserMode | 2003–2101 | USB device connect/disconnect |
| Security (Firewall) | 5156–5159 | Network connection allow/block |

---

## CSV Output Reference

All CSV files use UTF-8 encoding with headers in the first row. They are designed to be imported directly into Excel, pandas, or any SIEM platform.

### Key CSV Fields Linux

**`auth_failed_logins.csv`**
```
timestamp, username, source_ip, method, pid
```

**`ssh_logins.csv`**
```
timestamp, event, username, source_ip, port, key_fingerprint
```

**`firewall_blocks.csv`**
```
timestamp, action, protocol, src_ip, src_port, dst_ip, dst_port, iface
```

**`audit_events.csv`**
```
timestamp, type, syscall, uid, pid, exe, key, result
```

**`web_access.csv`**
```
timestamp, client_ip, method, uri, status_code, bytes, user_agent
```

### Key CSV Fields — Windows

**`02a_logon_success.csv`**
```
TimeCreated, EventId, SubjectUser, TargetUser, LogonType, LogonTypeName,
WorkstationName, IPAddress, IPPort, ProcessName, AuthPackage, LogonGuid
```

**`02g_process_creation.csv`**
```
TimeCreated, SubjectUser, NewProcess, ParentProcess, CommandLine,
TokenType, Suspicious
```
> The `Suspicious` field is automatically populated when the command line matches known offensive patterns (encoded PowerShell, LOLBIN usage, credential tools).

**`05a_ps_scriptblock.csv`**
```
TimeCreated, EventId, ScriptBlock, Suspicious
```

**`07a_network_connections.csv`**
```
LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
OwningProcess, ProcessName, CreationTime
```

---

## Chain of Custody

Both scripts print chain-of-custody commands at the end of every successful run. These should be executed immediately after collection before the output is moved or transferred.

### Linux

```bash
# Create a compressed archive
tar -czf forensic_<hostname>_<timestamp>.tar.gz ./forensic_logs_<hostname>_<timestamp>/

# Generate SHA-256 hash
sha256sum forensic_<hostname>_<timestamp>.tar.gz > forensic_<hostname>_<timestamp>.sha256

# Verify
sha256sum -c forensic_<hostname>_<timestamp>.sha256
```

### Windows

```powershell
# Hash all output files individually
Get-FileHash "C:\Evidence\ForensicLogs_*\*" -Algorithm SHA256 |
    Export-Csv "C:\Evidence\HASHES_$(hostname)_$(Get-Date -f yyyyMMdd).csv" -NoTypeInformation

# Compress the evidence directory
Compress-Archive -Path "C:\Evidence\ForensicLogs_*" `
    -DestinationPath "C:\Evidence\Forensic_$(hostname)_$(Get-Date -f yyyyMMdd_HHmmss).zip"

# Hash the archive itself
Get-FileHash "C:\Evidence\Forensic_*.zip" -Algorithm SHA256
```

Always record:
- Examiner name and badge/employee ID
- Date and time of collection (UTC)
- SHA-256 hash of the output archive
- System hostname, IP address, and OS version
- Whether the collection was run with elevated privileges

---

## Operational Notes

### Running on Live Systems vs. Images

Both scripts are designed for **live system collection**. They query running processes, active connections, and in-memory state in addition to log files. For forensic imaging scenarios, the Linux script can be pointed at mounted partitions by adjusting log paths; the Windows script requires a live session.

### Log Retention Limits

Windows Event Log retention is controlled by the log's `MaxSize` policy. If logs have been rotated or cleared (which is itself a forensic indicator — see Event ID 1102), historical events prior to the retention window will not be available. The Linux script handles compressed rotated logs (`.gz` files) transparently via `zcat` where applicable.

### SIEM Integration

All CSV outputs use consistent timestamp formats (`yyyy-MM-dd HH:mm:ss` for Windows, ISO-8601 for Linux) suitable for direct ingestion into:

- **Trident SIEM** — ingest via the CSV import pipeline or watch-folder connector
- **Splunk** — use `inputs.conf` with `sourcetype = csv` or the `| inputcsv` command
- **Elastic/ELK** — use Filebeat with the CSV input module
- **Microsoft Sentinel** — ingest via Logic App or the Custom Logs API

### Performance Impact

The Linux script uses `-xdev` with `find` to restrict searches to a single filesystem, avoiding NFS/CIFS mount traversal. The most time-intensive sections are the SUID scan and the world-writable file scan. On systems with large filesystems, these may take several minutes. Pass `-SkipLargeScans` on Windows to skip the registry enumeration passes if time is critical.

### Suspicious Pattern Detection

The following patterns are auto-flagged in both scripts:

**Linux (web access logs):**
- Path traversal: `../`
- SQL injection markers: `union select`
- XSS: `<script`, `javascript:`
- Null bytes: `\x00`

**Windows (process creation / PowerShell):**
- Encoded commands: `-enc`, `-EncodedCommand`
- AMSI bypass patterns
- `DownloadString`, `IEX`, `Invoke-Expression`
- Execution policy bypass: `-nop`, `-w hidden`, `bypass`
- Known credential tools: `mimikatz`, `invoke-web`
- LOLBIN abuse: `mshta`, `regsvr32`, `wscript`, `cscript`

---

## Troubleshooting

### Linux

**`Permission denied` on `/var/log/auth.log`**
Run the script with `sudo`. The auth log requires root on most distributions.

**`lastb: /var/log/btmp: No such file or directory`**
The btmp file is created on the first failed login attempt. If the system has never had a failed login, this is normal.

**`journalctl: command not found`**
The system uses SysV init rather than systemd. The script falls back to syslog parsing automatically.

**Script exits immediately with `unbound variable`**
This happens if the script is run with `sh` instead of `bash`. Always invoke with `bash ./forensic_linux_log_collector.sh` or ensure the shebang resolves to Bash 4+.

**auditd section shows no data**
Install and start auditd: `apt install auditd && systemctl enable --now auditd`. Existing logs will be empty until audit rules are configured.

### Windows

**`Get-WinEvent: The user does not have permission`**
The Security event log requires Administrator. Right-click PowerShell → Run as Administrator.

**`Get-LocalUser: The term 'Get-LocalUser' is not recognized`**
This cmdlet requires PowerShell 5.1 or later. Check your version with `$PSVersionTable.PSVersion`.

**PowerShell script block logging (4104) shows no events**
Script block logging must be enabled via Group Policy or registry before events are generated. Enable it with:
```powershell
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1
```

**`The execution of scripts is disabled on this system`**
Run this first (session-scoped, does not persist):
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

**Large output / slow collection**
Reduce the event cap: `.\forensic_windows_log_collector.ps1 -MaxEventsPerLog 1000`

---

## Disclaimer

This toolkit is intended for use by authorized security personnel conducting legitimate forensic investigations, incident response activities, or security audits on systems for which they have explicit written authorization. Unauthorized use of these scripts against systems you do not own or have permission to analyze may violate computer fraud and cybercrime laws in your jurisdiction, including Nepal's Cyber Security Act 2082, the Computer Fraud and Abuse Act (CFAA), and equivalent statutes.

All evidence collected using these scripts should be handled in accordance with your organization's evidence handling procedures and applicable legal requirements. The chain-of-custody steps documented above are a minimum baseline — consult your legal and compliance team for jurisdiction-specific requirements.

---

*Maintained by: 3tternp (Astra) | GitHub: [3tternp](https://github.com/3tternp)*
