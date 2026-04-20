#Requires -Version 5.1
<#
.SYNOPSIS
    Forensic Log Collection & Parsing Script - Windows
.DESCRIPTION
    Collects and parses ALL Windows logs from system installation date to present.
    Covers: System, Security, Application, PowerShell, RDP, Task Scheduler,
            Network, WMI, Defender, Firewall, USB, and more.
    Output: Structured CSV + HTML report + TXT summary for forensic analysis.
.AUTHOR
    Prem Basnet (Astra) | Vairav Technology Security Pvt. Ltd.
.VERSION
    2.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath    = "$env:USERPROFILE\Desktop\ForensicLogs_$(hostname)_$(Get-Date -f 'yyyyMMdd_HHmmss')",
    [int]   $MaxEventsPerLog = 5000,
    [switch]$SkipLargeScans
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

# --- SETUP ------------------------------------------------------------------
$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$HostName    = $env:COMPUTERNAME
$CsvDir      = Join-Path $OutputPath "CSV"
$RawDir      = Join-Path $OutputPath "RAW"
$ReportFile  = Join-Path $OutputPath "FORENSIC_REPORT_${HostName}_${Timestamp}.txt"
$HtmlReport  = Join-Path $OutputPath "FORENSIC_REPORT_${HostName}_${Timestamp}.html"
$SummaryFile = Join-Path $OutputPath "SUMMARY_${HostName}_${Timestamp}.txt"

foreach ($dir in @($OutputPath, $CsvDir, $RawDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# --- HELPERS ----------------------------------------------------------------
function Write-Banner {
    Write-Host ""
    Write-Host " +===========================================================+" -ForegroundColor Cyan
    Write-Host " |   FORENSIC WINDOWS LOG COLLECTOR v2.0                     |" -ForegroundColor Cyan
    Write-Host " |   Vairav Technology Security Pvt. Ltd.                    |" -ForegroundColor Cyan
    Write-Host " |   Full-spectrum log acquisition - install date to now     |" -ForegroundColor Cyan
    Write-Host " +===========================================================+" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n======================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host "======================================================" -ForegroundColor Cyan
    Add-Content -Path $ReportFile -Value "`n################################################################################"
    Add-Content -Path $ReportFile -Value "## $Title"
    Add-Content -Path $ReportFile -Value "## $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
    Add-Content -Path $ReportFile -Value "################################################################################"
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $colors = @{ "INFO" = "Green"; "WARN" = "Yellow"; "ERROR" = "Red"; "DEBUG" = "Gray" }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

function Export-Events {
    param(
        [string]$LogName,
        [int[]]$EventIds,
        [string]$CsvFileName,
        [string]$SectionTitle,
        [scriptblock]$ParseBlock,
        [string]$FilterXml = $null
    )
    Write-Log "Collecting: $SectionTitle"
    Add-Content -Path $ReportFile -Value "`n[$SectionTitle]"

    try {
        $splat = @{ LogName = $LogName; MaxEvents = $MaxEventsPerLog; ErrorAction = "SilentlyContinue" }
        if ($EventIds) { $splat['Id'] = $EventIds }

        $events = if ($FilterXml) {
            Get-WinEvent -FilterXml $FilterXml -MaxEvents $MaxEventsPerLog -ErrorAction SilentlyContinue
        } else {
            Get-WinEvent @splat
        }

        if (-not $events) {
            Add-Content -Path $ReportFile -Value "  [No events found or access denied]"
            return
        }

        $parsed = $events | ForEach-Object { & $ParseBlock $_ } | Where-Object { $_ -ne $null }

        if ($parsed) {
            $parsed | Export-Csv -Path (Join-Path $CsvDir $CsvFileName) -NoTypeInformation -Encoding UTF8
            $parsed | ForEach-Object {
                $line = ($_.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join " | "
                Add-Content -Path $ReportFile -Value "  $line"
            }
            Write-Log "  -> $($parsed.Count) events parsed -> $CsvFileName"
        }
    }
    catch {
        Add-Content -Path $ReportFile -Value "  [Error: $($_.Exception.Message)]"
    }
}

function Format-EventXml {
    param($Event)
    try { [xml]$Event.ToXml() } catch { $null }
}

# --- 1. SYSTEM INSTALLATION DATE --------------------------------------------
function Get-InstallDate {
    Write-Section "1. SYSTEM INSTALLATION DATE"
    Write-Log "Detecting install date"

    $installDate = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallDate
    if ($installDate) {
        $installDateTime = [System.DateTimeOffset]::FromUnixTimeSeconds($installDate).DateTime
    } else {
        $installDateTime = (Get-CimInstance Win32_OperatingSystem).InstallDate
    }

    $osInfo = Get-CimInstance Win32_OperatingSystem
    $csInfo = Get-CimInstance Win32_ComputerSystem
    $biosInfo = Get-CimInstance Win32_BIOS

    $data = [ordered]@{
        Hostname          = $HostName
        "Install Date"    = $installDateTime
        "Collection Date" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "OS Name"         = $osInfo.Caption
        "OS Version"      = $osInfo.Version
        "OS Build"        = $osInfo.BuildNumber
        "OS Architecture" = $osInfo.OSArchitecture
        "Last Boot"       = $osInfo.LastBootUpTime
        "Uptime"          = (New-TimeSpan -Start $osInfo.LastBootUpTime -End (Get-Date)).ToString()
        "Domain"          = $csInfo.Domain
        "Total RAM"       = "$([math]::Round($csInfo.TotalPhysicalMemory/1GB, 2)) GB"
        "BIOS Version"    = $biosInfo.SMBIOSBIOSVersion
        "Serial Number"   = $biosInfo.SerialNumber
    }

    $script:InstallDate = $installDateTime
    $data.GetEnumerator() | ForEach-Object {
        Add-Content -Path $ReportFile -Value ("  {0,-25}: {1}" -f $_.Key, $_.Value)
    }
    $data | ForEach-Object { [PSCustomObject]$_ } | Export-Csv (Join-Path $CsvDir "00_system_info.csv") -NoTypeInformation -Encoding UTF8

    Write-Log "Install date detected: $installDateTime"
}

# --- 2. SECURITY LOGS -------------------------------------------------------
function Get-SecurityLogs {
    Write-Section "2. SECURITY EVENT LOGS"

    # Successful Logons (4624)
    Export-Events -LogName "Security" -EventIds @(4624) -CsvFileName "02a_logon_success.csv" `
        -SectionTitle "Successful Logon Events (4624)" -ParseBlock {
        param($e)
        $xml = Format-EventXml $e
        if (-not $xml) { return }
        $d = $xml.Event.EventData.Data
        [PSCustomObject]@{
            TimeCreated    = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId        = $e.Id
            SubjectUser    = ($d | Where-Object Name -eq "SubjectUserName").'#text'
            TargetUser     = ($d | Where-Object Name -eq "TargetUserName").'#text'
            LogonType      = ($d | Where-Object Name -eq "LogonType").'#text'
            LogonTypeName  = switch(($d | Where-Object Name -eq "LogonType").'#text'){
                               "2" {"Interactive"} "3" {"Network"} "4" {"Batch"} "5" {"Service"}
                               "7" {"Unlock"}      "8" {"NetworkCleartext"} "10" {"RemoteInteractive"}
                               "11" {"CachedInteractive"} default {"Unknown"} }
            WorkstationName= ($d | Where-Object Name -eq "WorkstationName").'#text'
            IPAddress      = ($d | Where-Object Name -eq "IpAddress").'#text'
            IPPort         = ($d | Where-Object Name -eq "IpPort").'#text'
            ProcessName    = ($d | Where-Object Name -eq "ProcessName").'#text'
            AuthPackage    = ($d | Where-Object Name -eq "AuthenticationPackageName").'#text'
            LogonGuid      = ($d | Where-Object Name -eq "LogonGuid").'#text'
        }
    }

    # Failed Logons (4625)
    Export-Events -LogName "Security" -EventIds @(4625) -CsvFileName "02b_logon_failed.csv" `
        -SectionTitle "Failed Logon Events (4625)" -ParseBlock {
        param($e)
        $xml = Format-EventXml $e
        if (-not $xml) { return }
        $d = $xml.Event.EventData.Data
        [PSCustomObject]@{
            TimeCreated    = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId        = $e.Id
            TargetUser     = ($d | Where-Object Name -eq "TargetUserName").'#text'
            TargetDomain   = ($d | Where-Object Name -eq "TargetDomainName").'#text'
            LogonType      = ($d | Where-Object Name -eq "LogonType").'#text'
            FailureReason  = ($d | Where-Object Name -eq "FailureReason").'#text'
            Status         = ($d | Where-Object Name -eq "Status").'#text'
            SubStatus      = ($d | Where-Object Name -eq "SubStatus").'#text'
            WorkstationName= ($d | Where-Object Name -eq "WorkstationName").'#text'
            IPAddress      = ($d | Where-Object Name -eq "IpAddress").'#text'
            IPPort         = ($d | Where-Object Name -eq "IpPort").'#text'
        }
    }

    # Logoffs (4634, 4647)
    Export-Events -LogName "Security" -EventIds @(4634, 4647) -CsvFileName "02c_logoff.csv" `
        -SectionTitle "Logoff Events (4634, 4647)" -ParseBlock {
        param($e)
        $xml = Format-EventXml $e
        if (-not $xml) { return }
        $d = $xml.Event.EventData.Data
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId     = $e.Id
            User        = ($d | Where-Object Name -eq "TargetUserName").'#text'
            Domain      = ($d | Where-Object Name -eq "TargetDomainName").'#text'
            LogonType   = ($d | Where-Object Name -eq "LogonType").'#text'
            LogonId     = ($d | Where-Object Name -eq "TargetLogonId").'#text'
        }
    }

    # Account Management (4720, 4722, 4725, 4726, 4738, 4740, 4756)
    Export-Events -LogName "Security" -EventIds @(4720,4722,4725,4726,4738,4740,4756,4757,4767) `
        -CsvFileName "02d_account_management.csv" -SectionTitle "Account Management Events" -ParseBlock {
        param($e)
        $xml = Format-EventXml $e
        if (-not $xml) { return }
        $d = $xml.Event.EventData.Data
        $eventDesc = switch($e.Id){
            4720 {"Account Created"}   4722 {"Account Enabled"}   4725 {"Account Disabled"}
            4726 {"Account Deleted"}   4738 {"Account Changed"}   4740 {"Account Locked Out"}
            4756 {"Member Added to Group"} 4757 {"Member Removed from Group"} 4767 {"Account Unlocked"}
            default {"Account Event"} }
        [PSCustomObject]@{
            TimeCreated   = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId       = $e.Id
            EventDesc     = $eventDesc
            TargetUser    = ($d | Where-Object Name -eq "TargetUserName").'#text'
            TargetDomain  = ($d | Where-Object Name -eq "TargetDomainName").'#text'
            SubjectUser   = ($d | Where-Object Name -eq "SubjectUserName").'#text'
            SubjectDomain = ($d | Where-Object Name -eq "SubjectDomainName").'#text'
        }
    }

    # Privilege Use (4672, 4673, 4674)
    Export-Events -LogName "Security" -EventIds @(4672,4673,4674) -CsvFileName "02e_privilege_use.csv" `
        -SectionTitle "Privilege Use Events (4672,4673,4674)" -ParseBlock {
        param($e)
        $xml = Format-EventXml $e
        if (-not $xml) { return }
        $d = $xml.Event.EventData.Data
        [PSCustomObject]@{
            TimeCreated  = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId      = $e.Id
            SubjectUser  = ($d | Where-Object Name -eq "SubjectUserName").'#text'
            SubjectDomain= ($d | Where-Object Name -eq "SubjectDomainName").'#text'
            PrivilegeList= ($d | Where-Object Name -eq "PrivilegeList").'#text'
            ProcessName  = ($d | Where-Object Name -eq "ProcessName").'#text'
        }
    }

    # Object Access (4663 - file, reg access)
    Export-Events -LogName "Security" -EventIds @(4663) -CsvFileName "02f_object_access.csv" `
        -SectionTitle "Object Access Events (4663)" -ParseBlock {
        param($e)
        $xml = Format-EventXml $e
        if (-not $xml) { return }
        $d = $xml.Event.EventData.Data
        [PSCustomObject]@{
            TimeCreated   = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            SubjectUser   = ($d | Where-Object Name -eq "SubjectUserName").'#text'
            ObjectType    = ($d | Where-Object Name -eq "ObjectType").'#text'
            ObjectName    = ($d | Where-Object Name -eq "ObjectName").'#text'
            AccessMask    = ($d | Where-Object Name -eq "AccessMask").'#text'
            ProcessName   = ($d | Where-Object Name -eq "ProcessName").'#text'
        }
    }

    # Process Creation (4688)
    Export-Events -LogName "Security" -EventIds @(4688) -CsvFileName "02g_process_creation.csv" `
        -SectionTitle "Process Creation Events (4688)" -ParseBlock {
        param($e)
        $xml = Format-EventXml $e
        if (-not $xml) { return }
        $d = $xml.Event.EventData.Data
        $cmdLine = ($d | Where-Object Name -eq "CommandLine").'#text'
        $suspicious = ""
        if ($cmdLine -match "powershell.*-enc|-nop|-w hidden|bypass|downloadstring|iex|invoke-expression|mimikatz|whoami|net user|reg add|schtasks|mshta|wscript|cscript|regsvr32") {
            $suspicious = "!SUSPICIOUS!"
        }
        [PSCustomObject]@{
            TimeCreated   = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            SubjectUser   = ($d | Where-Object Name -eq "SubjectUserName").'#text'
            NewProcess    = ($d | Where-Object Name -eq "NewProcessName").'#text'
            ParentProcess = ($d | Where-Object Name -eq "ParentProcessName").'#text'
            CommandLine   = $cmdLine
            TokenType     = ($d | Where-Object Name -eq "TokenElevationType").'#text'
            Suspicious    = $suspicious
        }
    }

    # Audit Policy Changes (4719)
    Export-Events -LogName "Security" -EventIds @(4719) -CsvFileName "02h_audit_policy_change.csv" `
        -SectionTitle "Audit Policy Change (4719)" -ParseBlock {
        param($e)
        $xml = Format-EventXml $e
        if (-not $xml) { return }
        $d = $xml.Event.EventData.Data
        [PSCustomObject]@{
            TimeCreated    = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            SubjectUser    = ($d | Where-Object Name -eq "SubjectUserName").'#text'
            Category       = ($d | Where-Object Name -eq "CategoryId").'#text'
            SubCategory    = ($d | Where-Object Name -eq "SubcategoryId").'#text'
            AuditPolicyChange= ($d | Where-Object Name -eq "AuditPolicyChanges").'#text'
        }
    }
}

# --- 3. SYSTEM LOGS ---------------------------------------------------------
function Get-SystemLogs {
    Write-Section "3. SYSTEM EVENT LOGS"

    # System errors and warnings
    Export-Events -LogName "System" -EventIds $null -CsvFileName "03a_system_errors.csv" `
        -SectionTitle "System Errors and Warnings" -ParseBlock {
        param($e)
        if ($e.Level -gt 3) { return }
        [PSCustomObject]@{
            TimeCreated  = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId      = $e.Id
            Level        = switch($e.Level){ 1{"Critical"} 2{"Error"} 3{"Warning"} default{"Info"} }
            Source       = $e.ProviderName
            Message      = ($e.Message -replace "`n"," " -replace "`r"," ").Substring(0, [Math]::Min(300, $e.Message.Length))
            Computer     = $e.MachineName
        }
    }

    # Service control events
    Export-Events -LogName "System" -EventIds @(7034,7035,7036,7040,7045) `
        -CsvFileName "03b_service_events.csv" -SectionTitle "Service Control Events (7034-7045)" -ParseBlock {
        param($e)
        $desc = switch($e.Id){
            7034 {"Service Crashed"}      7035 {"Service Control Sent"}
            7036 {"Service State Changed"} 7040 {"Service Start Type Changed"}
            7045 {"New Service Installed"} default {"Service Event"} }
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId     = $e.Id
            EventDesc   = $desc
            ServiceName = if($e.Message -match "service name is ([^.`n]+)") { $Matches[1] } else { $e.Properties[0].Value }
            Message     = ($e.Message -replace "`n"," ").Substring(0, [Math]::Min(200, $e.Message.Length))
        }
    }

    # System startup/shutdown
    Export-Events -LogName "System" -EventIds @(1074,1076,6005,6006,6008,6009) `
        -CsvFileName "03c_startupshutdown.csv" -SectionTitle "Startup/Shutdown Events" -ParseBlock {
        param($e)
        $desc = switch($e.Id){
            1074 {"System Shutdown Initiated"} 1076 {"Shutdown Reason"}
            6005 {"Event Log Started"}         6006 {"Event Log Stopped"}
            6008 {"Unexpected Shutdown"}       6009 {"System Version Info"}
            default {"Startup/Shutdown"} }
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId     = $e.Id
            EventDesc   = $desc
            User        = if($e.UserId) { $e.UserId.Value } else { "SYSTEM" }
            Message     = ($e.Message -replace "`n"," ").Substring(0, [Math]::Min(250, $e.Message.Length))
        }
    }

    # Driver/Hardware errors
    Export-Events -LogName "System" -EventIds @(51,52,11,15,55) `
        -CsvFileName "03d_disk_driver_errors.csv" -SectionTitle "Disk/Driver Errors" -ParseBlock {
        param($e)
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId     = $e.Id
            Source      = $e.ProviderName
            Message     = ($e.Message -replace "`n"," ").Substring(0, [Math]::Min(300, $e.Message.Length))
        }
    }
}

# --- 4. APPLICATION LOGS ----------------------------------------------------
function Get-ApplicationLogs {
    Write-Section "4. APPLICATION EVENT LOGS"

    Export-Events -LogName "Application" -EventIds $null -CsvFileName "04a_application_errors.csv" `
        -SectionTitle "Application Errors and Warnings" -ParseBlock {
        param($e)
        if ($e.Level -gt 3) { return }
        [PSCustomObject]@{
            TimeCreated  = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId      = $e.Id
            Level        = switch($e.Level){ 1{"Critical"} 2{"Error"} 3{"Warning"} default{"Info"} }
            Source       = $e.ProviderName
            Message      = ($e.Message -replace "`n"," " -replace "`r","").Substring(0, [Math]::Min(400, $e.Message.Length))
        }
    }

    # Application crashes (WER - 1000, 1001)
    Export-Events -LogName "Application" -EventIds @(1000, 1001, 1002) `
        -CsvFileName "04b_app_crashes.csv" -SectionTitle "Application Crashes (WER)" -ParseBlock {
        param($e)
        [PSCustomObject]@{
            TimeCreated   = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId       = $e.Id
            EventDesc     = if($e.Id -eq 1000){"App Crash"}elseif($e.Id -eq 1001){"Crash Report Queued"}else{"Hang"}
            Application   = if($e.Properties.Count -gt 0) { $e.Properties[0].Value } else { "Unknown" }
            Version       = if($e.Properties.Count -gt 1) { $e.Properties[1].Value } else { "Unknown" }
            FaultModule   = if($e.Properties.Count -gt 3) { $e.Properties[3].Value } else { "Unknown" }
        }
    }
}

# --- 5. POWERSHELL & SCRIPT LOGS --------------------------------------------
function Get-PowerShellLogs {
    Write-Section "5. POWERSHELL EXECUTION LOGS"

    # PS Script Block Logging (4104)
    Export-Events -LogName "Microsoft-Windows-PowerShell/Operational" -EventIds @(4104) `
        -CsvFileName "05a_ps_scriptblock.csv" -SectionTitle "PowerShell Script Block (4104)" -ParseBlock {
        param($e)
        $msg = $e.Message
        $suspicious = ""
        if ($msg -match "-enc|downloadstring|iex|invoke-expression|bypass|hidden|mimikatz|amsi|base64|frombase64|shellcode|invoke-web") {
            $suspicious = "!SUSPICIOUS!"
        }
        [PSCustomObject]@{
            TimeCreated  = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId      = $e.Id
            ScriptBlock  = $msg.Substring(0, [Math]::Min(500, $msg.Length)) -replace "`n"," "
            Suspicious   = $suspicious
        }
    }

    # PS Engine start/stop (400, 403)
    Export-Events -LogName "Windows PowerShell" -EventIds @(400, 403, 600) `
        -CsvFileName "05b_ps_engine.csv" -SectionTitle "PowerShell Engine Events" -ParseBlock {
        param($e)
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId     = $e.Id
            EventDesc   = if($e.Id -eq 400){"PS Engine Started"}elseif($e.Id -eq 403){"PS Engine Stopped"}else{"Provider Loaded"}
            Message     = ($e.Message -replace "`n"," ").Substring(0, [Math]::Min(300, $e.Message.Length))
        }
    }
}

# --- 6. TASK SCHEDULER LOGS -------------------------------------------------
function Get-TaskSchedulerLogs {
    Write-Section "6. TASK SCHEDULER LOGS"

    Export-Events -LogName "Microsoft-Windows-TaskScheduler/Operational" `
        -EventIds @(106, 107, 140, 141, 200, 201, 202, 325, 326, 327) `
        -CsvFileName "06a_scheduled_tasks.csv" -SectionTitle "Task Scheduler Events" -ParseBlock {
        param($e)
        $desc = switch($e.Id){
            106 {"Task Registered"}   107 {"Task Triggered"}    140 {"Task Updated"}
            141 {"Task Deleted"}      200 {"Task Action Started"} 201 {"Task Action Completed"}
            202 {"Task Action Failed"} 325 {"Task Engine Started"} 326 {"Task Engine Stopped"}
            327 {"Task Engine Idle"}  default {"Task Event"} }
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId     = $e.Id
            EventDesc   = $desc
            TaskName    = if($e.Properties.Count -gt 0) { $e.Properties[0].Value } else { "Unknown" }
            User        = if($e.Properties.Count -gt 1) { $e.Properties[1].Value } else { "System" }
            Message     = ($e.Message -replace "`n"," ").Substring(0, [Math]::Min(250, $e.Message.Length))
        }
    }

    # Enumerate all scheduled tasks (current state)
    Write-Section "6b. REGISTERED SCHEDULED TASKS (CURRENT)"
    Write-Log "Enumerating all scheduled tasks"
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object TaskName, TaskPath, State,
        @{N="Author";E={$_.Principal.UserId}},
        @{N="Actions";E={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "}},
        @{N="Triggers";E={($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join "; "}}
    if ($tasks) {
        $tasks | Export-Csv (Join-Path $CsvDir "06b_scheduled_tasks_current.csv") -NoTypeInformation -Encoding UTF8
        $tasks | ForEach-Object {
            $taskLine = "  [$($_.State)] $($_.TaskPath)$($_.TaskName) -- $($_.Actions)"
            Add-Content -Path $ReportFile -Value $taskLine
        }
    }
}

# --- 7. NETWORK LOGS --------------------------------------------------------
function Get-NetworkLogs {
    Write-Section "7. NETWORK LOGS"

    # Current connections
    Write-Log "Collecting network connections"
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
        $proc = try { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } catch { "Unknown" }
        $stateDesc = switch($_.State){ "Established"{"ESTABLISHED"} "Listen"{"LISTEN"} "TimeWait"{"TIME_WAIT"} "CloseWait"{"CLOSE_WAIT"} default{$_.State} }
        [PSCustomObject]@{
            LocalAddress   = $_.LocalAddress
            LocalPort      = $_.LocalPort
            RemoteAddress  = $_.RemoteAddress
            RemotePort     = $_.RemotePort
            State          = $stateDesc
            OwningProcess  = $_.OwningProcess
            ProcessName    = $proc
            CreationTime   = $_.CreationTime
        }
    }
    if ($connections) {
        $connections | Export-Csv (Join-Path $CsvDir "07a_network_connections.csv") -NoTypeInformation -Encoding UTF8
        $connections | ForEach-Object {
            Add-Content -Path $ReportFile -Value ("  [$($_.State)] {0}:{1} -> {2}:{3} PID={4} [{5}]" -f $_.LocalAddress,$_.LocalPort,$_.RemoteAddress,$_.RemotePort,$_.OwningProcess,$_.ProcessName)
        }
    }

    # DNS cache
    Write-Log "Collecting DNS cache"
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, Name, Type, Status, TimeToLive, DataLength, Data
    if ($dnsCache) {
        $dnsCache | Export-Csv (Join-Path $CsvDir "07b_dns_cache.csv") -NoTypeInformation -Encoding UTF8
        Add-Content -Path $ReportFile -Value "`n[DNS Cache]"
        $dnsCache | ForEach-Object { Add-Content -Path $ReportFile -Value ("  {0,-50} TTL={1,-8} Type={2,-8} Data={3}" -f $_.Entry, $_.TimeToLive, $_.Type, $_.Data) }
    }

    # Network adapters
    $adapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress, Status, LinkSpeed, MediaType
    $adapters | Export-Csv (Join-Path $CsvDir "07c_network_adapters.csv") -NoTypeInformation -Encoding UTF8
    Add-Content -Path $ReportFile -Value "`n[Network Adapters]"
    $adapters | ForEach-Object {
        $adapterLine = "  [$($_.Status)] $($_.Name) -- MAC=$($_.MacAddress) -- $($_.InterfaceDescription)"
        Add-Content -Path $ReportFile -Value $adapterLine
    }

    # IP config
    $ipconfig = Get-NetIPAddress | Where-Object { $_.AddressFamily -in @("IPv4","IPv6") } | `
        Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength, AddressState
    $ipconfig | Export-Csv (Join-Path $CsvDir "07d_ip_config.csv") -NoTypeInformation -Encoding UTF8

    # ARP
    $arp = Get-NetNeighbor | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State
    $arp | Export-Csv (Join-Path $CsvDir "07e_arp_cache.csv") -NoTypeInformation -Encoding UTF8

    # Firewall log events
    Export-Events -LogName "Security" -EventIds @(5156, 5157, 5158, 5159) `
        -CsvFileName "07f_firewall_events.csv" -SectionTitle "Windows Firewall Connection Events" -ParseBlock {
        param($e)
        $xml = Format-EventXml $e
        if (-not $xml) { return }
        $d = $xml.Event.EventData.Data
        $desc = switch($e.Id){ 5156{"Permitted"} 5157{"Blocked"} 5158{"Bind Permitted"} 5159{"Bind Blocked"} default{"?"} }
        [PSCustomObject]@{
            TimeCreated  = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId      = $e.Id
            Action       = $desc
            ProcessName  = ($d | Where-Object Name -eq "Application").'#text'
            Protocol     = ($d | Where-Object Name -eq "Protocol").'#text'
            SourceIP     = ($d | Where-Object Name -eq "SourceAddress").'#text'
            SourcePort   = ($d | Where-Object Name -eq "SourcePort").'#text'
            DestIP       = ($d | Where-Object Name -eq "DestAddress").'#text'
            DestPort     = ($d | Where-Object Name -eq "DestPort").'#text'
            Direction    = ($d | Where-Object Name -eq "Direction").'#text'
        }
    }
}

# --- 8. RDP / REMOTE ACCESS LOGS --------------------------------------------
function Get-RDPLogs {
    Write-Section "8. RDP & REMOTE ACCESS LOGS"

    Export-Events -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" `
        -EventIds @(21, 22, 23, 24, 25, 39, 40) -CsvFileName "08a_rdp_sessions.csv" `
        -SectionTitle "RDP Session Events" -ParseBlock {
        param($e)
        $desc = switch($e.Id){
            21 {"Session Logon"}    22 {"Shell Start"}      23 {"Session Logoff"}
            24 {"Session Disconnect"} 25 {"Session Reconnect"} 39 {"Session Disconnect (different session)"}
            40 {"Session Requested Disconnect"} default {"RDP Event"} }
        [PSCustomObject]@{
            TimeCreated  = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId      = $e.Id
            EventDesc    = $desc
            User         = if($e.Properties.Count -gt 0) { $e.Properties[0].Value } else { "Unknown" }
            SessionId    = if($e.Properties.Count -gt 1) { $e.Properties[1].Value } else { "Unknown" }
            SourceIP     = if($e.Properties.Count -gt 2) { $e.Properties[2].Value } else { "Unknown" }
        }
    }

    # RDP Authentication
    Export-Events -LogName "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" `
        -EventIds @(131, 98) -CsvFileName "08b_rdp_auth.csv" `
        -SectionTitle "RDP Core Auth Events (131, 98)" -ParseBlock {
        param($e)
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId     = $e.Id
            EventDesc   = if($e.Id -eq 131){"RDP Connection Request"}else{"Connection Closed"}
            ClientIP    = if($e.Properties.Count -gt 0) { $e.Properties[0].Value } else { "Unknown" }
            Message     = ($e.Message -replace "`n"," ").Substring(0, [Math]::Min(200, $e.Message.Length))
        }
    }
}

# --- 9. WINDOWS DEFENDER / AV LOGS ------------------------------------------
function Get-DefenderLogs {
    Write-Section "9. WINDOWS DEFENDER / ANTIMALWARE LOGS"

    Export-Events -LogName "Microsoft-Windows-Windows Defender/Operational" `
        -EventIds @(1006, 1007, 1008, 1009, 1010, 1011, 1012, 1116, 1117, 1118, 1119) `
        -CsvFileName "09a_defender_events.csv" -SectionTitle "Windows Defender Threat Events" -ParseBlock {
        param($e)
        $desc = switch($e.Id){
            1006 {"Malware Detected"}   1007 {"Malware Action Taken"} 1008 {"Malware Action Failed"}
            1009 {"Quarantine Restored"} 1010 {"Quarantine Restore Failed"} 1011 {"History Delete"}
            1012 {"History Delete Failed"} 1116 {"Platform Warning (Malware)"} 1117 {"Malware Action Platform"}
            1118 {"Antimalware Expired"} 1119 {"Critical Error"} default {"Defender Event"} }
        [PSCustomObject]@{
            TimeCreated  = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId      = $e.Id
            EventDesc    = $desc
            ThreatName   = if($e.Properties.Count -gt 7) { $e.Properties[7].Value } else { "Unknown" }
            SeverityName = if($e.Properties.Count -gt 9) { $e.Properties[9].Value } else { "Unknown" }
            ActionName   = if($e.Properties.Count -gt 14) { $e.Properties[14].Value } else { "Unknown" }
            Path         = if($e.Properties.Count -gt 21) { $e.Properties[21].Value } else { "Unknown" }
            User         = if($e.Properties.Count -gt 24) { $e.Properties[24].Value } else { "Unknown" }
        }
    }
}

# --- 10. WMI & AppLocker/SRP ------------------------------------------------
function Get-WMIAndAppLockerLogs {
    Write-Section "10. WMI ACTIVITY & APPLOCKER LOGS"

    Export-Events -LogName "Microsoft-Windows-WMI-Activity/Operational" `
        -EventIds @(5857, 5858, 5859, 5860, 5861) -CsvFileName "10a_wmi_events.csv" `
        -SectionTitle "WMI Activity Events" -ParseBlock {
        param($e)
        $desc = switch($e.Id){
            5857 {"Provider Host Started"} 5858 {"Provider Query Error"}
            5859 {"Event Subscription Created"} 5860 {"Event Consumer Created"} 5861 {"Filter-Consumer Binding"}
            default {"WMI Event"} }
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId     = $e.Id
            EventDesc   = $desc
            Message     = ($e.Message -replace "`n"," ").Substring(0, [Math]::Min(400, $e.Message.Length))
        }
    }

    Export-Events -LogName "Microsoft-Windows-AppLocker/EXE and DLL" `
        -EventIds @(8003, 8004, 8006, 8007) -CsvFileName "10b_applocker_events.csv" `
        -SectionTitle "AppLocker Execution Events" -ParseBlock {
        param($e)
        $desc = switch($e.Id){ 8003{"Allowed(Audit)"}  8004{"Blocked(Audit)"} 8006{"Script Allowed"} 8007{"Script Blocked"} default{"AppLocker"} }
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId     = $e.Id
            EventDesc   = $desc
            User        = if($e.UserId) { $e.UserId.Value } else { "Unknown" }
            FilePath    = if($e.Properties.Count -gt 1) { $e.Properties[1].Value } else { "Unknown" }
            Publisher   = if($e.Properties.Count -gt 3) { $e.Properties[3].Value } else { "Unknown" }
        }
    }
}

# --- 11. USB & DEVICE LOGS --------------------------------------------------
function Get-USBLogs {
    Write-Section "11. USB & REMOVABLE DEVICE LOGS"

    Export-Events -LogName "Microsoft-Windows-DriverFrameworks-UserMode/Operational" `
        -EventIds @(2003, 2004, 2100, 2101) -CsvFileName "11a_usb_events.csv" `
        -SectionTitle "USB Connection Events" -ParseBlock {
        param($e)
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId     = $e.Id
            EventDesc   = if($e.Id -in @(2003,2004)){"Device Connected"}else{"Device Disconnected"}
            DeviceId    = if($e.Properties.Count -gt 0) { $e.Properties[0].Value } else { "Unknown" }
        }
    }

    # USB from registry (historical device list)
    Write-Log "Reading USB device history from registry"
    Add-Content -Path $ReportFile -Value "`n[Historical USB Devices - Registry]"
    try {
        $usbKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        if (Test-Path $usbKey) {
            $usbDevices = Get-ChildItem $usbKey -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    DeviceKey    = $_.Name
                    FriendlyName = $props.FriendlyName
                    Mfg          = $props.Mfg
                    Class        = $props.Class
                }
            }
            $usbDevices | Export-Csv (Join-Path $CsvDir "11b_usb_registry.csv") -NoTypeInformation -Encoding UTF8
            $usbDevices | ForEach-Object {
                $usbLine = "  [$($_.Class)] $($_.FriendlyName) -- $($_.DeviceKey)"
                Add-Content -Path $ReportFile -Value $usbLine
            }
        }
    } catch {
        Add-Content -Path $ReportFile -Value "  [Access denied or key not found]"
    }
}

# --- 12. USER & LOCAL ACCOUNTS ----------------------------------------------
function Get-UserAccountInfo {
    Write-Section "12. LOCAL USERS, GROUPS & ACCOUNT POLICY"

    Write-Log "Collecting local user accounts"
    $users = Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, Enabled, FullName, Description,
        PasswordRequired, PasswordLastSet, PasswordNeverExpires, LastLogon, AccountExpires,
        @{N="SID";E={$_.SID.Value}}
    if ($users) {
        $users | Export-Csv (Join-Path $CsvDir "12a_local_users.csv") -NoTypeInformation -Encoding UTF8
        Add-Content -Path $ReportFile -Value "`n[Local User Accounts]"
        $users | ForEach-Object {
            Add-Content -Path $ReportFile -Value ("  [{0}] {1,-20} Enabled={2,-5} LastLogon={3,-25} PwdLastSet={4}" -f
                $_.SID, $_.Name, $_.Enabled, $_.LastLogon, $_.PasswordLastSet)
        }
    }

    Write-Log "Collecting local groups"
    $groups = Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
        $groupName = $_.Name
        $members = try {
            (Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join "; "
        } catch { "" }
        [PSCustomObject]@{
            GroupName   = $groupName
            Description = $_.Description
            Members     = $members
        }
    }
    if ($groups) {
        $groups | Export-Csv (Join-Path $CsvDir "12b_local_groups.csv") -NoTypeInformation -Encoding UTF8
        Add-Content -Path $ReportFile -Value "`n[Local Groups]"
        $groups | ForEach-Object { Add-Content -Path $ReportFile -Value "  [$($_.GroupName)] Members: $($_.Members)" }
    }

    # Autorun entries
    Write-Log "Collecting autorun / startup entries"
    $autoruns = @()
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $autoruns += [PSCustomObject]@{ RegistryPath = $path; Name = $_.Name; Value = $_.Value }
            }
        }
    }
    if ($autoruns) {
        $autoruns | Export-Csv (Join-Path $CsvDir "12c_autoruns.csv") -NoTypeInformation -Encoding UTF8
        Add-Content -Path $ReportFile -Value "`n[Autorun Entries]"
        $autoruns | ForEach-Object { Add-Content -Path $ReportFile -Value "  [$($_.Name)] $($_.Value)  [Registry: $($_.RegistryPath)]" }
    }
}

# --- 13. PROCESS & SERVICE SNAPSHOT -----------------------------------------
function Get-ProcessServiceSnapshot {
    Write-Section "13. RUNNING PROCESSES & SERVICES"

    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $owner = try { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue).User } catch { "Unknown" }
        [PSCustomObject]@{
            PID           = $_.ProcessId
            PPID          = $_.ParentProcessId
            Name          = $_.Name
            ExecutablePath= $_.ExecutablePath
            CommandLine   = $_.CommandLine
            Owner         = $owner
            CreationDate  = $_.CreationDate
            WorkingSetMB  = [math]::Round($_.WorkingSetSize/1MB, 2)
        }
    }
    if ($processes) {
        $processes | Export-Csv (Join-Path $CsvDir "13a_processes.csv") -NoTypeInformation -Encoding UTF8
        Add-Content -Path $ReportFile -Value "`n[Running Processes]"
        $processes | Sort-Object PID | ForEach-Object {
            Add-Content -Path $ReportFile -Value ("  PID={0,-7} PPID={1,-7} {2,-30} User={3,-20} CMD={4}" -f $_.PID,$_.PPID,$_.Name,$_.Owner,($_.CommandLine -replace "`n"," ").Substring(0,[Math]::Min(100,$_.CommandLine.Length)))
        }
    }

    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName,
        State, StartMode, PathName, StartName, Description
    if ($services) {
        $services | Export-Csv (Join-Path $CsvDir "13b_services.csv") -NoTypeInformation -Encoding UTF8
        Add-Content -Path $ReportFile -Value "`n[Windows Services]"
        $services | Where-Object { $_.State -eq "Running" } | ForEach-Object {
            Add-Content -Path $ReportFile -Value ("  [RUNNING] {0,-40} Mode={1,-10} User={2,-20} Path={3}" -f $_.DisplayName, $_.StartMode, $_.StartName, $_.PathName)
        }
    }
}

# --- 14. INSTALLED SOFTWARE -------------------------------------------------
function Get-InstalledSoftware {
    Write-Section "14. INSTALLED SOFTWARE"

    $software = @()
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($path in $regPaths) {
        $software += Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation,
                @{N="RegistryPath";E={$path}}
    }
    if ($software) {
        $software | Sort-Object DisplayName | Export-Csv (Join-Path $CsvDir "14_installed_software.csv") -NoTypeInformation -Encoding UTF8
        Add-Content -Path $ReportFile -Value "`n[Installed Software]"
        $software | Sort-Object InstallDate -Descending | ForEach-Object {
            Add-Content -Path $ReportFile -Value ("  [{0,-12}] {1,-50} v{2,-15} Publisher={3}" -f $_.InstallDate, $_.DisplayName, $_.DisplayVersion, $_.Publisher)
        }
    }
}

# --- SUMMARY REPORT ---------------------------------------------------------
function Write-Summary {
    Write-Section "COLLECTION SUMMARY"

    $csvFiles = Get-ChildItem $CsvDir -Filter "*.csv" -ErrorAction SilentlyContinue
    $totalEvents = 0
    $csvFiles | ForEach-Object {
        $count = (Import-Csv $_.FullName -ErrorAction SilentlyContinue | Measure-Object).Count
        $totalEvents += $count
    }

    $summary = @"
================================================================================
  FORENSIC COLLECTION SUMMARY
  Host         : $HostName
  Install Date : $($script:InstallDate)
  Collected    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
  Analyst      : $env:USERNAME
================================================================================

OUTPUT FILES:
  Report  : $ReportFile
  CSVs    : $CsvDir  ($($csvFiles.Count) files)
  Summary : $SummaryFile

STATISTICS:
  Total Parsed Events      : $totalEvents
  Local Users              : $((Get-LocalUser -EA SilentlyContinue | Measure-Object).Count)
  Running Processes        : $((Get-Process -EA SilentlyContinue | Measure-Object).Count)
  Running Services         : $((Get-Service -EA SilentlyContinue | Where-Object {$_.Status -eq "Running"} | Measure-Object).Count)
  Listening Ports          : $((Get-NetTCPConnection -State Listen -EA SilentlyContinue | Measure-Object).Count)
  Scheduled Tasks          : $((Get-ScheduledTask -EA SilentlyContinue | Measure-Object).Count)
  Installed Software       : $((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue | Where-Object {$_.DisplayName} | Measure-Object).Count)

CSV FILES GENERATED:
$($csvFiles | ForEach-Object { "  $($_.Name) ($($_.Length / 1KB -as [int]) KB)" } | Out-String)
================================================================================
"@

    Set-Content -Path $SummaryFile -Value $summary
    Write-Host $summary -ForegroundColor Green
    Add-Content -Path $ReportFile -Value $summary
}

# --- DISCLAIMER -------------------------------------------------------------
function Show-Disclaimer {
    $border = "=" * 76
    Write-Host ""
    Write-Host $border -ForegroundColor Red
    Write-Host "  (!)  LEGAL DISCLAIMER - READ BEFORE PROCEEDING  (!)" -ForegroundColor Red
    Write-Host $border -ForegroundColor Red
    Write-Host ""
    Write-Host "  This tool is intended EXCLUSIVELY for:" -ForegroundColor Yellow
    Write-Host "    ? Authorized forensic investigations" -ForegroundColor White
    Write-Host "    ? Incident response on systems you OWN or have WRITTEN authorization" -ForegroundColor White
    Write-Host "      to analyze" -ForegroundColor White
    Write-Host "    ? Security audits with documented written authorization" -ForegroundColor White
    Write-Host ""
    Write-Host "  UNAUTHORIZED USE is a criminal offense under:" -ForegroundColor Yellow
    Write-Host "    ? Nepal Cyber Security Act 2082 (B.S.)" -ForegroundColor White
    Write-Host "    ? Electronic Transactions Act 2063 (Nepal)" -ForegroundColor White
    Write-Host "    ? Computer Fraud and Abuse Act - CFAA (United States)" -ForegroundColor White
    Write-Host "    ? Computer Misuse Act 1990 (United Kingdom)" -ForegroundColor White
    Write-Host "    ? Equivalent cybercrime statutes in your jurisdiction" -ForegroundColor White
    Write-Host ""
    Write-Host "  By proceeding, you CONFIRM that:" -ForegroundColor Yellow
    Write-Host "    [1] You have explicit WRITTEN authorization to collect logs from this system" -ForegroundColor White
    Write-Host "    [2] Collected evidence will be handled per your organization's procedures" -ForegroundColor White
    Write-Host "    [3] You accept FULL legal responsibility for this collection activity" -ForegroundColor White
    Write-Host ""
    Write-Host "  Vairav Technology Security Pvt. Ltd. accepts NO liability for" -ForegroundColor DarkGray
    Write-Host "  unauthorized or improper use of this tool." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host $border -ForegroundColor Red
    Write-Host ""
    Write-Host ("  Target Host : {0} ({1})" -f $env:COMPUTERNAME,
        ((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -notmatch "^127\." } | Select-Object -First 1).IPAddress)) -ForegroundColor Cyan
    Write-Host ("  Run By      : {0}\{1} at {2} UTC" -f $env:USERDOMAIN, $env:USERNAME,
        (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) -ForegroundColor Cyan
    Write-Host ""

    $confirm = Read-Host "  Do you have written authorization to collect logs from this system? [yes/NO]"
    if ($confirm.Trim().ToLower() -ne "yes") {
        Write-Host ""
        Write-Host "[ABORTED] Authorization not confirmed. No data collected. Exiting." -ForegroundColor Red
        Write-Host ""
        exit 1
    }

    Write-Host ""
    Write-Host "[[OK]] Authorization confirmed. Recording analyst acceptance..." -ForegroundColor Green
    Write-Host ""

    # Return acceptance record object - written to disk after output dir is created
    return [PSCustomObject]@{
        AcceptedBy   = "$env:USERDOMAIN\$env:USERNAME"
        AcceptedAt   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
        Host         = $env:COMPUTERNAME
        HostIP       = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object { $_.IPAddress -notmatch "^127\." } | Select-Object -First 1).IPAddress
        Script       = "forensic_windows_log_collector.ps1 v2.0"
        Purpose      = "Forensic log collection - authorized use only"
    }
}

# --- MAIN -------------------------------------------------------------------
Write-Banner
$DisclaimerRecord = Show-Disclaimer

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "WARNING: Not running as Administrator. Many security/auth logs will be inaccessible." "WARN"
    Write-Log "Re-run: Start-Process PowerShell -Verb RunAs" "WARN"
}

# Write disclaimer acceptance record to output directory
$disclaimerFile = Join-Path $OutputPath "DISCLAIMER_ACCEPTANCE.txt"
@"
DISCLAIMER ACCEPTANCE RECORD
=============================
Accepted By : $($DisclaimerRecord.AcceptedBy)
Accepted At : $($DisclaimerRecord.AcceptedAt)
Host        : $($DisclaimerRecord.Host) ($($DisclaimerRecord.HostIP))
Script      : $($DisclaimerRecord.Script)
Purpose     : $($DisclaimerRecord.Purpose)
"@ | Set-Content -Path $disclaimerFile -Encoding UTF8

# Write report header
Set-Content -Path $ReportFile -Value @"
================================================================================
  FORENSIC LOG COLLECTION REPORT - WINDOWS
  Host         : $HostName
  Collected By : forensic_windows_log_collector.ps1 v2.0
  Collection   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
  Analyst      : $env:USERNAME
  Run As Admin : $isAdmin
================================================================================
"@

Get-InstallDate
Get-SecurityLogs
Get-SystemLogs
Get-ApplicationLogs
Get-PowerShellLogs
Get-TaskSchedulerLogs
Get-NetworkLogs
Get-RDPLogs
Get-DefenderLogs
Get-WMIAndAppLockerLogs
Get-USBLogs
Get-UserAccountInfo
Get-ProcessServiceSnapshot
Get-InstalledSoftware
Write-Summary

Write-Host ""
Write-Log "Collection complete."
Write-Log "Report : $ReportFile"
Write-Log "CSVs   : $CsvDir"
Write-Log "Summary: $SummaryFile"
Write-Host ""
Write-Host "[!] Hash the output for chain of custody:" -ForegroundColor Yellow
Write-Host "    Get-FileHash '$OutputPath\*' -Algorithm SHA256 | Export-Csv '$OutputPath\HASHES.csv'" -ForegroundColor White
Write-Host "    Compress-Archive -Path '$OutputPath' -DestinationPath 'Forensic_${HostName}_${Timestamp}.zip'" -ForegroundColor White
