#!/usr/bin/env bash
# =============================================================================
# forensic_linux_log_collector.sh
# Forensic Log Collection & Parsing Script — Linux
# Author : Prem Basnet (Astra) | Vairav Technology Security Pvt. Ltd.
# Version: 2.0
# Purpose: Collect and parse ALL system logs from installation date to present
#          Output: Structured CSV + human-readable TXT report for forensic use
# =============================================================================

set -euo pipefail

# ─── CONFIGURATION ──────────────────────────────────────────────────────────
SCRIPT_VERSION="2.0"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME_VAL=$(hostname)
OUTPUT_DIR="./forensic_logs_${HOSTNAME_VAL}_${TIMESTAMP}"
REPORT_FILE="${OUTPUT_DIR}/FORENSIC_REPORT_${HOSTNAME_VAL}_${TIMESTAMP}.txt"
CSV_DIR="${OUTPUT_DIR}/csv"
RAW_DIR="${OUTPUT_DIR}/raw"
SUMMARY_FILE="${OUTPUT_DIR}/SUMMARY.txt"

# Colors
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ─── HELPERS ────────────────────────────────────────────────────────────────
log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_section() { echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════════════════${NC}"; \
                echo -e "${CYAN}${BOLD}  $*${NC}"; \
                echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${NC}"; }

banner() {
cat << 'EOF'
 ╔═══════════════════════════════════════════════════════════╗
 ║   FORENSIC LINUX LOG COLLECTOR v2.0                       ║
 ║   Vairav Technology Security Pvt. Ltd.                    ║
 ║   Full-spectrum log acquisition — install date to now     ║
 ╚═══════════════════════════════════════════════════════════╝
EOF
}

write_report_header() {
    cat >> "$REPORT_FILE" << EOF
================================================================================
  FORENSIC LOG COLLECTION REPORT
  Host         : ${HOSTNAME_VAL}
  Collected By : forensic_linux_log_collector.sh v${SCRIPT_VERSION}
  Collection   : $(date -u "+%Y-%m-%d %H:%M:%S UTC")
  Analyst      : ${USER:-unknown}
  OS           : $(uname -a)
================================================================================

EOF
}

section_header() {
    local title="$1"
    echo "" >> "$REPORT_FILE"
    echo "################################################################################" >> "$REPORT_FILE"
    echo "## ${title}" >> "$REPORT_FILE"
    echo "## Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT_FILE"
    echo "################################################################################" >> "$REPORT_FILE"
}

csv_header() {
    local file="$1"; shift
    echo "$@" > "${CSV_DIR}/${file}"
}

safe_run() {
    # Run a command; suppress errors silently
    eval "$1" 2>/dev/null || true
}

# ─── SETUP ──────────────────────────────────────────────────────────────────
setup() {
    mkdir -p "${OUTPUT_DIR}" "${CSV_DIR}" "${RAW_DIR}"
    touch "$REPORT_FILE" "$SUMMARY_FILE"
    banner
    write_report_header
    log_info "Output directory: ${OUTPUT_DIR}"
}

# ─── SYSTEM INSTALLATION DATE ───────────────────────────────────────────────
get_install_date() {
    log_section "Detecting System Installation Date"
    local install_date=""

    # Method 1: filesystem root inode creation
    if stat / &>/dev/null; then
        install_date=$(stat / 2>/dev/null | grep -i "birth\|create" | awk '{print $2, $3}' | head -1)
    fi

    # Method 2: dpkg log (Debian/Ubuntu)
    if [[ -z "$install_date" ]] && [[ -f /var/log/dpkg.log ]]; then
        install_date=$(head -1 /var/log/dpkg.log | awk '{print $1, $2}')
    fi

    # Method 3: oldest rpm transaction (RHEL/CentOS)
    if [[ -z "$install_date" ]] && command -v rpm &>/dev/null; then
        install_date=$(rpm -qi bash 2>/dev/null | grep "Install Date" | awk -F: '{print $2}' | xargs)
    fi

    # Method 4: /lost+found ctime
    if [[ -z "$install_date" ]]; then
        install_date=$(stat /lost+found 2>/dev/null | grep Change | awk '{print $2, $3}' | head -1)
    fi

    # Method 5: oldest entry in /var/log
    if [[ -z "$install_date" ]]; then
        install_date=$(ls -lt /var/log/ 2>/dev/null | tail -1 | awk '{print $6, $7, $8}')
    fi

    INSTALL_DATE="${install_date:-Unknown}"
    log_info "Estimated install date: ${INSTALL_DATE}"

    section_header "SYSTEM INSTALLATION DATE"
    {
        echo "Hostname           : ${HOSTNAME_VAL}"
        echo "Estimated Install  : ${INSTALL_DATE}"
        echo "Current Date/Time  : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "Uptime             : $(uptime -p 2>/dev/null || uptime)"
        echo "Kernel             : $(uname -r)"
        echo "OS Release         : $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
        echo "Architecture       : $(uname -m)"
    } >> "$REPORT_FILE"
}

# ─── 1. SYSTEM INFORMATION ──────────────────────────────────────────────────
collect_system_info() {
    log_section "1. System Information"
    section_header "1. SYSTEM INFORMATION"

    {
        echo "[Hardware]"
        echo "CPU      : $(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)"
        echo "CPU Cores: $(nproc 2>/dev/null)"
        echo "RAM      : $(free -h 2>/dev/null | awk '/^Mem/{print $2}')"
        echo "Swap     : $(free -h 2>/dev/null | awk '/^Swap/{print $2}')"
        echo ""
        echo "[Disk Layout]"
        lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null || df -h 2>/dev/null
        echo ""
        echo "[Network Interfaces]"
        ip addr show 2>/dev/null | grep -E "^[0-9]+:|inet " | awk '{print $1,$2}' || ifconfig 2>/dev/null
        echo ""
        echo "[Routing Table]"
        ip route show 2>/dev/null || netstat -rn 2>/dev/null
    } >> "$REPORT_FILE"

    # CSV
    csv_header "system_users.csv" "username,uid,gid,home,shell,last_login"
    while IFS=: read -r user pass uid gid gecos home shell; do
        last_login=$(last "$user" 2>/dev/null | head -1 | awk '{print $4,$5,$6,$7}' || echo "never")
        echo "\"${user}\",\"${uid}\",\"${gid}\",\"${home}\",\"${shell}\",\"${last_login}\"" >> "${CSV_DIR}/system_users.csv"
    done < /etc/passwd
}

# ─── 2. AUTHENTICATION & LOGIN LOGS ────────────────────────────────────────
collect_auth_logs() {
    log_section "2. Authentication & Login Logs"
    section_header "2. AUTHENTICATION & LOGIN LOGS"

    # Successful logins
    csv_header "auth_successful_logins.csv" "timestamp,username,source_ip,terminal,pid,status"
    {
        echo "[Successful Logins — last 10000 entries]"
        last -F 2>/dev/null | head -200 | awk '{
            printf "%-20s %-15s %-20s %-15s %s\n", $1, $3, $4" "$5" "$6" "$7, $2, $8
        }' | tee >(awk 'NF{print "\""$1"\",\""$2"\",\""$3"\",\""$4"\",\"\",\"success\""}' >> "${CSV_DIR}/auth_successful_logins.csv")
    } >> "$REPORT_FILE"

    # Failed logins
    csv_header "auth_failed_logins.csv" "timestamp,username,source_ip,method,pid"
    {
        echo ""
        echo "[Failed Login Attempts]"
        for logfile in /var/log/auth.log /var/log/secure /var/log/messages; do
            if [[ -f "$logfile" ]]; then
                grep -i "failed\|invalid\|authentication failure\|FAILED" "$logfile" 2>/dev/null | \
                awk '{
                    ts=$1" "$2" "$3; user="unknown"; ip="unknown"
                    for(i=1;i<=NF;i++){
                        if($i ~ /user=/) {split($i,a,"="); user=a[2]}
                        if($i ~ /from/) ip=$(i+1)
                    }
                    printf "[%s] User=%-20s IP=%-18s MSG=%s\n", ts, user, ip, $0
                }' | head -500 | tee >(awk '{print "\""$2"\",\""$3"\",\""$5"\",\"password\",\"\""}' >> "${CSV_DIR}/auth_failed_logins.csv")
                break
            fi
        done
    } >> "$REPORT_FILE"

    # SSH logins
    csv_header "ssh_logins.csv" "timestamp,event,username,source_ip,port,key_fingerprint"
    {
        echo ""
        echo "[SSH Login Activity]"
        for logfile in /var/log/auth.log /var/log/secure; do
            if [[ -f "$logfile" ]]; then
                grep -i "sshd\|ssh2" "$logfile" 2>/dev/null | grep -i "accepted\|failed\|disconnect\|invalid" | \
                awk '{
                    ts=$1" "$2" "$3; event="unknown"; user="unknown"; ip="unknown"
                    if($0 ~ /Accepted/) event="ACCEPTED"
                    if($0 ~ /Failed/)   event="FAILED"
                    if($0 ~ /Invalid/)  event="INVALID"
                    if($0 ~ /Disconnect/) event="DISCONNECT"
                    for(i=1;i<=NF;i++){
                        if($i=="for"||$i=="user") user=$(i+1)
                        if($i=="from") ip=$(i+1)
                    }
                    printf "[%s] %-12s User=%-20s IP=%s\n", ts, event, user, ip
                }' | head -500 | tee >(awk '{print "\""$1" "$2" "$3"\",\""$4"\",\""$5"\",\""$6"\",\"\",\"\""}' >> "${CSV_DIR}/ssh_logins.csv")
                break
            fi
        done
    } >> "$REPORT_FILE"

    # Sudo usage
    csv_header "sudo_usage.csv" "timestamp,user,run_as,command,tty,status"
    {
        echo ""
        echo "[Sudo Command Usage]"
        for logfile in /var/log/auth.log /var/log/secure; do
            if [[ -f "$logfile" ]]; then
                grep "sudo:" "$logfile" 2>/dev/null | \
                awk '{
                    ts=$1" "$2" "$3; user="?"; cmd="?"
                    for(i=1;i<=NF;i++){
                        if($i ~ /^TTY=/) tty=$i
                        if($i == "COMMAND=") cmd=substr($0, index($0,"COMMAND="))
                    }
                    print "["ts"]", $0
                }' | head -300 | tee >(awk '{print "\""$1" "$2" "$3"\",\""$5"\",\"\",\""substr($0, index($0,"COMMAND")+8)"\",\"\",\"\""}' >> "${CSV_DIR}/sudo_usage.csv")
                break
            fi
        done
    } >> "$REPORT_FILE"
}

# ─── 3. SYSTEM/KERNEL LOGS ──────────────────────────────────────────────────
collect_system_logs() {
    log_section "3. System / Kernel Logs"
    section_header "3. SYSTEM / KERNEL LOGS"

    csv_header "kernel_events.csv" "timestamp,log_level,subsystem,message"

    {
        echo "[Kernel Ring Buffer — Notable Events]"
        dmesg --time-format iso 2>/dev/null | grep -E -i "error|warn|fail|oops|panic|killed|oom|hardware|usb|eth|nvme|sda|segfault|call trace" | \
        awk '{
            ts=$1; level="INFO"
            if($0 ~ /error|Error/) level="ERROR"
            if($0 ~ /warn|Warn/)   level="WARN"
            if($0 ~ /fail|Fail/)   level="FAIL"
            if($0 ~ /panic|Panic/) level="CRITICAL"
            printf "[%s] [%-8s] %s\n", ts, level, substr($0, index($0,$3))
        }' | head -500 | tee >(awk -F'\t' '{print "\""$1"\",\""$2"\",\"\",\""$3"\""}' >> "${CSV_DIR}/kernel_events.csv")

        echo ""
        echo "[SystemD Journal — Critical/Error (last 1000 entries)]"
        if command -v journalctl &>/dev/null; then
            journalctl -p err..emerg --no-pager --output=short-iso 2>/dev/null | head -500 | \
            awk '{
                ts=$1; host=$2; unit=$3
                msg=substr($0, index($0,$4))
                printf "[%s] HOST=%-15s UNIT=%-25s MSG=%s\n", ts, host, unit, msg
            }'
        fi
    } >> "$REPORT_FILE"

    # OOM events
    {
        echo ""
        echo "[OOM Killer Events]"
        dmesg 2>/dev/null | grep -i "out of memory\|oom_kill\|Killed process" | \
        awk '{print "[OOM]", $0}' | head -100
    } >> "$REPORT_FILE"

    # Service start/stop (journald)
    csv_header "service_events.csv" "timestamp,unit,event,pid,exit_code"
    {
        echo ""
        echo "[Service Start/Stop Events (journald)]"
        if command -v journalctl &>/dev/null; then
            journalctl --no-pager -o short-iso 2>/dev/null | \
            grep -E "Started|Stopped|Failed|Starting|Stopping|systemd\[1\]" | head -500 | \
            awk '{
                ts=$1; unit="unknown"; event="unknown"
                if($0 ~ /Started/)  event="STARTED"
                if($0 ~ /Stopped/)  event="STOPPED"
                if($0 ~ /Failed/)   event="FAILED"
                if($0 ~ /Starting/) event="STARTING"
                print "["ts"]", event, substr($0, index($0,$4))
            }' | tee >(awk '{print "\""$1"\",\""$3"\",\""$2"\",\"\",\"\""}' >> "${CSV_DIR}/service_events.csv")
        fi
    } >> "$REPORT_FILE"
}

# ─── 4. SECURITY LOGS ───────────────────────────────────────────────────────
collect_security_logs() {
    log_section "4. Security Logs"
    section_header "4. SECURITY LOGS"

    # SUID/SGID files
    csv_header "suid_sgid_files.csv" "permissions,owner,group,path,last_modified"
    {
        echo "[SUID/SGID Binaries]"
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | \
        while read -r f; do
            stat_out=$(stat -c "%A %U %G %y" "$f" 2>/dev/null)
            perms=$(echo "$stat_out" | awk '{print $1}')
            owner=$(echo "$stat_out" | awk '{print $2}')
            group=$(echo "$stat_out" | awk '{print $3}')
            mtime=$(echo "$stat_out" | awk '{print $4,$5}')
            printf "%-15s %-10s %-10s %-60s %s\n" "$perms" "$owner" "$group" "$f" "$mtime"
            echo "\"${perms}\",\"${owner}\",\"${group}\",\"${f}\",\"${mtime}\"" >> "${CSV_DIR}/suid_sgid_files.csv"
        done | head -200
    } >> "$REPORT_FILE"

    # World-writable files
    csv_header "world_writable.csv" "permissions,owner,path"
    {
        echo ""
        echo "[World-Writable Files (excl. /proc /sys /dev /run)]"
        find / -xdev -not \( -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune \) \
            -perm -o+w -type f 2>/dev/null | head -100 | \
        while read -r f; do
            perms=$(stat -c "%A" "$f" 2>/dev/null)
            owner=$(stat -c "%U" "$f" 2>/dev/null)
            printf "%-15s %-15s %s\n" "$perms" "$owner" "$f"
            echo "\"${perms}\",\"${owner}\",\"${f}\"" >> "${CSV_DIR}/world_writable.csv"
        done
    } >> "$REPORT_FILE"

    # Crontab activity
    csv_header "cron_jobs.csv" "user,schedule,command,source_file"
    {
        echo ""
        echo "[Cron Jobs — All Users]"
        # System crontabs
        for cfile in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
            if [[ -f "$cfile" ]]; then
                echo "  [FILE: $cfile]"
                grep -v "^#\|^$" "$cfile" 2>/dev/null | while IFS= read -r line; do
                    echo "  $line"
                    echo "\"$(basename "$cfile")\",\"\",\"${line}\",\"${cfile}\"" >> "${CSV_DIR}/cron_jobs.csv"
                done
            fi
        done
        # Cron log
        for logfile in /var/log/cron /var/log/cron.log /var/log/syslog; do
            if [[ -f "$logfile" ]]; then
                echo "  [Cron Execution Log — last 200]"
                grep -i "cron\|CMD" "$logfile" 2>/dev/null | tail -200 | \
                awk '{print "  ["$1,$2,$3"]", substr($0,index($0,$5))}'
                break
            fi
        done
    } >> "$REPORT_FILE"

    # Firewall logs (iptables/ufw/firewalld)
    csv_header "firewall_blocks.csv" "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port,iface"
    {
        echo ""
        echo "[Firewall Block Events]"
        for logfile in /var/log/ufw.log /var/log/firewalld /var/log/messages /var/log/syslog; do
            if [[ -f "$logfile" ]]; then
                grep -E "UFW BLOCK|REJECT|DROP|DENY" "$logfile" 2>/dev/null | head -300 | \
                awk '{
                    ts=$1" "$2" "$3; action="BLOCK"; proto="?"; src="?"; dst="?"; sport="?"; dport="?"; iface="?"
                    for(i=1;i<=NF;i++){
                        if($i ~ /^PROTO=/) {split($i,a,"="); proto=a[2]}
                        if($i ~ /^SRC=/)   {split($i,a,"="); src=a[2]}
                        if($i ~ /^DST=/)   {split($i,a,"="); dst=a[2]}
                        if($i ~ /^SPT=/)   {split($i,a,"="); sport=a[2]}
                        if($i ~ /^DPT=/)   {split($i,a,"="); dport=a[2]}
                        if($i ~ /^IN=/)    {split($i,a,"="); iface=a[2]}
                    }
                    printf "[%s] %-6s PROTO=%-5s SRC=%-18s:%-6s DST=%-18s:%-6s IFACE=%s\n", ts, action, proto, src, sport, dst, dport, iface
                    printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", ts, action, proto, src, sport, dst, dport, iface >> "/dev/fd/3"
                }' 3>> "${CSV_DIR}/firewall_blocks.csv"
                break
            fi
        done
    } >> "$REPORT_FILE"

    # AppArmor / SELinux denials
    {
        echo ""
        echo "[AppArmor / SELinux Denial Events]"
        for logfile in /var/log/audit/audit.log /var/log/kern.log /var/log/syslog; do
            if [[ -f "$logfile" ]]; then
                grep -E "apparmor=\"DENIED\"|avc:.*denied|selinux.*denied" "$logfile" 2>/dev/null | \
                awk '{print "["$1,$2,$3"]", $0}' | head -200
                break
            fi
        done
    } >> "$REPORT_FILE"
}

# ─── 5. APPLICATION LOGS ────────────────────────────────────────────────────
collect_application_logs() {
    log_section "5. Application Logs"
    section_header "5. APPLICATION LOGS"

    # Apache/Nginx access & error
    csv_header "web_access.csv" "timestamp,client_ip,method,uri,status_code,bytes,user_agent"
    {
        echo "[Web Server Access Logs]"
        local found=false
        for logfile in /var/log/apache2/access.log /var/log/httpd/access_log /var/log/nginx/access.log; do
            if [[ -f "$logfile" ]]; then
                found=true
                echo "  [Source: $logfile]"
                awk '{
                    ip=$1; ts=substr($4,2); method=$6; uri=$7; status=$9; bytes=$10
                    ua="unknown"
                    # Combined log format user-agent
                    if(NF>=12){ua=substr($0,index($0,$12))}
                    # Flag suspicious
                    flag=""
                    if(status ~ /^4/) flag=" [CLIENT_ERR]"
                    if(status ~ /^5/) flag=" [SERVER_ERR]"
                    if(uri ~ /\.\.\/|union.*select|script.*>|<.*>|\x00/) flag=" [!SUSPICIOUS!]"
                    printf "  [%s] %-18s %-8s %-50s %s%s\n", ts, ip, method, uri, status, flag
                }' "$logfile" | head -500 | \
                tee >(awk '{print "\""$2"\",\""$3"\",\""$4"\",\""$5"\",\""$6"\",\"\",\""substr($0,index($0,$7))"\""}' >> "${CSV_DIR}/web_access.csv")
            fi
        done
        $found || echo "  No web server logs found."

        echo ""
        echo "[Web Server Error Logs]"
        for logfile in /var/log/apache2/error.log /var/log/httpd/error_log /var/log/nginx/error.log; do
            if [[ -f "$logfile" ]]; then
                echo "  [Source: $logfile]"
                awk '{
                    level="INFO"
                    if($0 ~ /\[error\]/)  level="ERROR"
                    if($0 ~ /\[crit\]/)   level="CRITICAL"
                    if($0 ~ /\[alert\]/)  level="ALERT"
                    if($0 ~ /\[emerg\]/)  level="EMERGENCY"
                    printf "  [%-10s] %s\n", level, $0
                }' "$logfile" | head -200
            fi
        done
    } >> "$REPORT_FILE"

    # MySQL/PostgreSQL logs
    {
        echo ""
        echo "[Database Logs]"
        for logfile in /var/log/mysql/error.log /var/log/mysql.log /var/lib/pgsql/data/pg_log/*.log \
                       /var/log/postgresql/postgresql-*.log; do
            if [[ -f "$logfile" ]]; then
                echo "  [Source: $logfile]"
                grep -E "ERROR|WARN|FATAL|connect|disconnect|denied|fail" "$logfile" 2>/dev/null | \
                awk '{print "  "$0}' | head -200
            fi
        done
    } >> "$REPORT_FILE"

    # Application package install history
    csv_header "package_installs.csv" "timestamp,action,package,version"
    {
        echo ""
        echo "[Package Installation History]"
        if [[ -f /var/log/dpkg.log ]]; then
            echo "  [dpkg — Debian/Ubuntu]"
            grep " install \| upgrade \| remove " /var/log/dpkg.log 2>/dev/null | \
            awk '{printf "  [%s %s] %-10s %-40s %s\n", $1, $2, $3, $4, $5}' | \
            tee >(awk '{print "\""$1" "$2"\",\""$3"\",\""$4"\",\""$5"\""}' >> "${CSV_DIR}/package_installs.csv")
        fi
        if command -v rpm &>/dev/null; then
            echo "  [RPM — RHEL/CentOS]"
            rpm -qa --queryformat "%{INSTALLTIME:date} | %-40{NAME} | %{VERSION}\n" 2>/dev/null | sort | \
            tee >(awk -F'|' '{print "\""$1"\",\"install\",\""$2"\",\""$3"\""}' >> "${CSV_DIR}/package_installs.csv")
        fi
    } >> "$REPORT_FILE"
}

# ─── 6. NETWORK & ACCESS LOGS ───────────────────────────────────────────────
collect_network_logs() {
    log_section "6. Network & Access Logs"
    section_header "6. NETWORK & ACCESS LOGS"

    csv_header "active_connections.csv" "protocol,local_addr,local_port,remote_addr,remote_port,state,pid,process"
    {
        echo "[Active Network Connections]"
        if command -v ss &>/dev/null; then
            ss -tulpn 2>/dev/null | awk '
            NR>1 {
                proto=$1; state=$2; local=$5; remote=$6; proc=$7
                split(local,la,":"); split(remote,ra,":")
                printf "  %-6s %-20s:%-8s %-20s:%-8s %-15s %s\n", proto, la[1], la[length(la)], ra[1], ra[length(ra)], state, proc
            }' | tee >(awk '{print "\""$1"\",\""$2"\",\""$3"\",\""$4"\",\""$5"\",\""$6"\",\"\",\""$7"\""}' >> "${CSV_DIR}/active_connections.csv")
        else
            netstat -tulpn 2>/dev/null | awk 'NR>2{print "  "$0}'
        fi

        echo ""
        echo "[Listening Ports]"
        ss -lntp 2>/dev/null | awk 'NR>1{printf "  %-8s %-30s %s\n", $1, $5, $7}'

        echo ""
        echo "[ARP Cache]"
        arp -n 2>/dev/null | awk 'NR>1{printf "  IP=%-18s MAC=%-20s IFACE=%s\n", $1, $3, $5}'

        echo ""
        echo "[DNS Resolver Config]"
        cat /etc/resolv.conf 2>/dev/null | grep -v "^#\|^$" | awk '{print "  "$0}'

        echo ""
        echo "[Hosts File]"
        cat /etc/hosts 2>/dev/null | grep -v "^#\|^$" | awk '{print "  "$0}'
    } >> "$REPORT_FILE"

    # Network traffic from logs (netstat historical)
    {
        echo ""
        echo "[Network-Related Syslog Events]"
        for logfile in /var/log/syslog /var/log/messages; do
            if [[ -f "$logfile" ]]; then
                grep -E "dhcp|dns|connect|refused|timeout|reset|NetworkManager|network" "$logfile" 2>/dev/null | \
                awk '{ts=$1" "$2" "$3; print "  ["ts"]", substr($0,index($0,$5))}' | head -200
                break
            fi
        done
    } >> "$REPORT_FILE"
}

# ─── 7. AUDIT LOGS (auditd) ─────────────────────────────────────────────────
collect_audit_logs() {
    log_section "7. Audit Logs (auditd)"
    section_header "7. AUDIT LOGS (auditd)"

    csv_header "audit_events.csv" "timestamp,type,syscall,uid,pid,exe,key,result"

    if [[ -f /var/log/audit/audit.log ]]; then
        {
            echo "[Auditd — File Access Events]"
            grep "type=SYSCALL\|type=PATH\|type=EXECVE" /var/log/audit/audit.log 2>/dev/null | \
            awk '{
                ts="?"; type="?"; uid="?"; pid="?"; exe="?"; key="?"; result="?"
                for(i=1;i<=NF;i++){
                    if($i ~ /^msg=audit\(/) {
                        split($i,a,"[(:]"); ts=a[2]
                    }
                    if($i ~ /^type=/)    {split($i,a,"="); type=a[2]}
                    if($i ~ /^uid=/)     {split($i,a,"="); uid=a[2]}
                    if($i ~ /^pid=/)     {split($i,a,"="); pid=a[2]}
                    if($i ~ /^exe=/)     {split($i,a,"="); exe=a[2]}
                    if($i ~ /^key=/)     {split($i,a,"="); key=a[2]}
                    if($i ~ /^success=/) {split($i,a,"="); result=a[2]}
                }
                printf "[%s] TYPE=%-15s UID=%-5s PID=%-7s EXE=%-30s KEY=%s RESULT=%s\n", ts, type, uid, pid, exe, key, result
                printf "\"%s\",\"%s\",\"\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", ts, type, uid, pid, exe, key, result >> "/dev/fd/3"
            }' 3>> "${CSV_DIR}/audit_events.csv" | head -500

            echo ""
            echo "[Auditd — Login/Logout Events]"
            grep "type=USER_LOGIN\|type=USER_LOGOUT\|type=USER_AUTH" /var/log/audit/audit.log 2>/dev/null | \
            awk '{
                ts="?"; result="?"; user="?"
                for(i=1;i<=NF;i++){
                    if($i ~ /^msg=/) {split($i,a,"[(:]"); ts=a[2]}
                    if($i ~ /^acct=/) {split($i,a,"="); user=a[2]}
                    if($i ~ /^res=/)  {split($i,a,"="); result=a[2]}
                }
                printf "[%s] %-20s USER=%s RESULT=%s\n", ts, $3, user, result
            }' | head -200
        } >> "$REPORT_FILE"
    else
        echo "  auditd not installed or /var/log/audit/audit.log not found." >> "$REPORT_FILE"
        if command -v ausearch &>/dev/null; then
            {
                echo "  [ausearch fallback — login events]"
                ausearch -m USER_LOGIN --interpret 2>/dev/null | head -200 | awk '{print "  "$0}'
            } >> "$REPORT_FILE"
        fi
    fi
}

# ─── 8. FILE INTEGRITY & SUSPICIOUS ACTIVITY ────────────────────────────────
collect_integrity_logs() {
    log_section "8. File Integrity & Suspicious Activity"
    section_header "8. FILE INTEGRITY & SUSPICIOUS ACTIVITY"

    csv_header "recently_modified.csv" "modified_time,permissions,owner,path"
    {
        echo "[Files Modified in Last 7 Days (key dirs)]"
        find /etc /bin /sbin /usr/bin /usr/sbin /tmp /var/tmp /dev/shm \
             -xdev -type f -newer /tmp -mtime -7 2>/dev/null | \
        while read -r f; do
            info=$(stat -c "%y %A %U" "$f" 2>/dev/null)
            mtime=$(echo "$info" | awk '{print $1, $2}')
            perms=$(echo "$info" | awk '{print $3}')
            owner=$(echo "$info" | awk '{print $4}')
            printf "  %-25s %-12s %-12s %s\n" "$mtime" "$perms" "$owner" "$f"
            echo "\"${mtime}\",\"${perms}\",\"${owner}\",\"${f}\"" >> "${CSV_DIR}/recently_modified.csv"
        done | head -300

        echo ""
        echo "[Hidden Files/Directories in Sensitive Paths]"
        find /tmp /var/tmp /dev/shm /root /home -name ".*" -type f 2>/dev/null | \
        while read -r f; do
            printf "  [HIDDEN] %s\n" "$f"
        done | head -100

        echo ""
        echo "[Executable Files in /tmp /var/tmp /dev/shm]"
        find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | \
        while read -r f; do
            printf "  [EXEC IN TEMP] %s  [%s]\n" "$f" "$(file "$f" 2>/dev/null | cut -d: -f2 | xargs)"
        done | head -100

        echo ""
        echo "[/etc/passwd and /etc/shadow Modifications]"
        stat -c "  /etc/passwd  — Last change: %y | Mode: %A | Owner: %U" /etc/passwd 2>/dev/null
        stat -c "  /etc/shadow  — Last change: %y | Mode: %A | Owner: %U" /etc/shadow 2>/dev/null

        echo ""
        echo "[Accounts with UID 0 (root-equivalent)]"
        awk -F: '$3==0{print "  [UID=0] User:", $1, "Shell:", $7}' /etc/passwd

        echo ""
        echo "[Accounts with Empty Passwords]"
        awk -F: '($2=="" || $2=="*" || $2=="!" ) && $3>=1000{print "  [NOPW]", $1}' /etc/shadow 2>/dev/null || \
        awk -F: '$2==""{print "  [NOPW]", $1}' /etc/passwd

        echo ""
        echo "[Bash History — All Users]"
        for home_dir in /root /home/*; do
            hist_file="${home_dir}/.bash_history"
            if [[ -f "$hist_file" ]]; then
                echo "  [User: $(basename "$home_dir")]"
                tail -50 "$hist_file" 2>/dev/null | awk '{print "    "$0}'
            fi
        done
    } >> "$REPORT_FILE"
}

# ─── 9. PROCESS & SCHEDULED TASK SNAPSHOT ───────────────────────────────────
collect_process_logs() {
    log_section "9. Running Processes & Scheduled Tasks"
    section_header "9. RUNNING PROCESSES & SCHEDULED TASKS"

    csv_header "processes.csv" "pid,ppid,user,cpu,mem,start_time,command"
    {
        echo "[All Running Processes]"
        ps auxf 2>/dev/null | \
        awk '
        NR==1{print "  "sprintf("%-8s %-8s %-15s %-6s %-6s %-20s %s", "PID","PPID","USER","%CPU","%MEM","STARTED","COMMAND"); next}
        {printf "  %-8s %-8s %-15s %-6s %-6s %-20s %s\n", $2, $3, $1, $3, $4, $9, substr($0,index($0,$11))}
        ' | head -200 | \
        tee >(awk 'NR>1{print "\""$1"\",\""$2"\",\""$3"\",\""$4"\",\""$5"\",\""$6"\",\""substr($0,index($0,$7))"\""}' >> "${CSV_DIR}/processes.csv")

        echo ""
        echo "[Systemd Timers]"
        systemctl list-timers --all --no-pager 2>/dev/null | awk '{print "  "$0}' | head -50

        echo ""
        echo "[AT Jobs]"
        atq 2>/dev/null | awk '{print "  "$0}' || echo "  No at jobs / atq not available."
    } >> "$REPORT_FILE"
}

# ─── 10. WTMP / BTMP / UTMP ANALYSIS ────────────────────────────────────────
collect_wtmp_logs() {
    log_section "10. Login Records (wtmp/btmp/utmp)"
    section_header "10. LOGIN RECORDS (wtmp / btmp / utmp)"

    csv_header "login_history_wtmp.csv" "user,terminal,source,login_time,logout_time,duration"
    {
        echo "[Full Login History — wtmp (all time)]"
        last -F -w 2>/dev/null | head -1000 | \
        awk '{
            user=$1; term=$2; src=$3
            if(NF>=10) login=$4" "$5" "$6" "$7
            printf "  %-15s %-12s %-20s %-30s\n", user, term, src, login
        }' | tee >(awk '{print "\""$1"\",\""$2"\",\""$3"\",\""$4" "$5"\",\"\",\"\""}' >> "${CSV_DIR}/login_history_wtmp.csv")

        echo ""
        echo "[Failed Login Attempts — btmp (all time)]"
        lastb -F 2>/dev/null | head -500 | \
        awk '{printf "  %-15s %-12s %-20s %-30s\n", $1, $2, $3, $4" "$5" "$6" "$7}' || \
        echo "  No btmp data (run as root for access)."

        echo ""
        echo "[Currently Logged-In Users — utmp]"
        w 2>/dev/null | awk '{print "  "$0}'

        echo ""
        echo "[Last Reboot / Shutdown History]"
        last reboot 2>/dev/null | awk '{print "  [REBOOT] "$0}' | head -20
        last shutdown 2>/dev/null | awk '{print "  [SHUTDOWN] "$0}' | head -20
    } >> "$REPORT_FILE"
}

# ─── SUMMARY GENERATION ─────────────────────────────────────────────────────
generate_summary() {
    log_section "Generating Summary"
    {
        cat << EOF
================================================================================
  FORENSIC COLLECTION SUMMARY
  Host     : ${HOSTNAME_VAL}
  Date     : $(date -u '+%Y-%m-%d %H:%M:%S UTC')
  Install  : ${INSTALL_DATE}
================================================================================

FILES GENERATED:
$(ls -lh "${OUTPUT_DIR}" 2>/dev/null)

CSV REPORTS:
$(ls -lh "${CSV_DIR}" 2>/dev/null)

KEY STATISTICS:
  - Total Users       : $(wc -l < /etc/passwd)
  - Root-equiv UIDs   : $(awk -F: '$3==0' /etc/passwd | wc -l)
  - SUID Binaries     : $(find / -xdev -perm -4000 -type f 2>/dev/null | wc -l)
  - World-Writable    : $(find / -xdev -not \( -path /proc -prune -o -path /sys -prune \) -perm -o+w -type f 2>/dev/null | wc -l)
  - Cron Jobs         : $(find /etc/cron* /var/spool/cron 2>/dev/null -type f | wc -l)
  - Listening Ports   : $(ss -lntp 2>/dev/null | grep -c LISTEN || echo 0)
  - Running Procs     : $(ps aux 2>/dev/null | wc -l)

EOF
    } > "$SUMMARY_FILE"
    cat "$SUMMARY_FILE"
}

# ─── MAIN ───────────────────────────────────────────────────────────────────
main() {
    # Check root
    if [[ $EUID -ne 0 ]]; then
        log_warn "Not running as root — some logs may be inaccessible. Re-run with sudo for full coverage."
    fi

    setup
    get_install_date
    collect_system_info
    collect_auth_logs
    collect_system_logs
    collect_security_logs
    collect_application_logs
    collect_network_logs
    collect_audit_logs
    collect_integrity_logs
    collect_process_logs
    collect_wtmp_logs
    generate_summary

    echo ""
    log_info "Collection complete."
    log_info "Report  : ${REPORT_FILE}"
    log_info "CSVs    : ${CSV_DIR}/"
    log_info "Summary : ${SUMMARY_FILE}"
    echo ""
    echo -e "${YELLOW}[!] Compress and hash the output for chain of custody:${NC}"
    echo "    tar -czf forensic_${HOSTNAME_VAL}_${TIMESTAMP}.tar.gz ${OUTPUT_DIR}/"
    echo "    sha256sum forensic_${HOSTNAME_VAL}_${TIMESTAMP}.tar.gz > forensic_${HOSTNAME_VAL}_${TIMESTAMP}.sha256"
}

main "$@"
