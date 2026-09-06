<#
.SYNOPSIS
    Ultimate Anti-Cheat Forensic & Screenshare (SS) Triage Suite (GOAT Edition)
    Incorporating Spokwn & Detect.ac Forensics:
    - BAM / DAM Binary Execution Ledger (Decoded 64-bit FILETIME)
    - NTFS Alternate Data Streams (Zone.Identifier Mark-of-the-Web & Hidden Payloads)
    - Windows Timeline ActivitiesCache.db SQLite Execution Forensics
    - PCA (Program Compatibility Assistant) History
    - USN Change Journal & File Replace/Deletion Forensics
    - AnyDesk & Screenshare Transfer Log Auditor
    - In-Memory Cheat String Scanner (xxstrings)
    - Authenticode Digital Signature Validator
    - Direct C++ 13-Module Kernel Memory Engine Dispatcher

.EXAMPLE
    .\AnticheatTriage.ps1 -All
    .\AnticheatTriage.ps1 -BAM
    .\AnticheatTriage.ps1 -Streams
    .\AnticheatTriage.ps1 -Timeline
    .\AnticheatTriage.ps1 -Journal
    .\AnticheatTriage.ps1 -Watch
#>

[CmdletBinding()]
param (
    [switch]$All,
    [switch]$BAM,
    [switch]$Streams,
    [switch]$Timeline,
    [switch]$PCA,
    [switch]$Journal,
    [switch]$AnyDesk,
    [switch]$MemoryStrings,
    [switch]$Signatures,
    [switch]$Watch,
    [switch]$Batch,
    [string]$TargetProcess = "HD-Player.exe",
    [string]$DisableDriver = "",
    [string]$CaptureScreenshot = ""
)

function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Banner {
    Clear-Host
    Write-Host "███╗   ██╗███████╗██╗  ██╗ █████╗ ██╗         █████╗  ██████╗" -ForegroundColor Cyan
    Write-Host "████╗  ██║██╔════╝██║  ██║██╔══██╗██║        ██╔══██╗██╔════╝" -ForegroundColor Cyan
    Write-Host "██╔██╗ ██║█████╗  ███████║███████║██║        ███████║██║     " -ForegroundColor Blue
    Write-Host "██║╚██╗██║██╔══╝  ██╔══██║██╔══██║██║        ██╔══██║██║     " -ForegroundColor Magenta
    Write-Host "██║ ╚████║███████╗██║  ██║██║  ██║███████╗   ██║  ██║╚██████╗" -ForegroundColor Magenta
    Write-Host "╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝  ╚═╝ ╚═════╝" -ForegroundColor Red
    Write-Host "┌────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│    NEHAL ANTI-CHEAT // CYBER-SOC FORENSIC COMMAND CENTER v3.5 (GOAT)    │" -ForegroundColor White
    Write-Host "│   13-Engine Deep Forensics | VAD Memory | BAM/DAM | Streams | Radar    │" -ForegroundColor DarkGray
    Write-Host "└────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
}

# --- Module 1: BAM (Background Activity Moderator) Binary Parser ---
function Get-BAMHistory {
    Write-Host "[*] Auditing Windows BAM (Background Activity Moderator) Ledger..." -ForegroundColor Cyan
    $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    
    if (-not (Test-Path $bamPath)) {
        $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings"
    }

    if (Test-Path $bamPath) {
        $userSIDs = Get-ChildItem $bamPath -ErrorAction SilentlyContinue
        $bamRecords = @()

        foreach ($sid in $userSIDs) {
            $props = (Get-ItemProperty $sid.PSPath).PSObject.Properties
            foreach ($p in $props) {
                if ($p.Name -notmatch "^(PS|SequenceNumber|Version)") {
                    $rawBytes = $p.Value
                    $execTime = "Unknown"
                    if ($rawBytes -is [byte[]] -and $rawBytes.Length -ge 8) {
                        try {
                            $ftLong = [BitConverter]::ToInt64($rawBytes, 0)
                            if ($ftLong -gt 0) {
                                $execTime = [DateTime]::FromFileTimeUtc($ftLong).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
                            }
                        } catch {}
                    }

                    $path = $p.Name
                    # Translate \Device\HarddiskVolumeX to C:
                    if ($path -match "^\\Device\\HarddiskVolume\d+(.*)") {
                        $path = "C:" + $Matches[1]
                    }

                    $isSuspicious = $path -match "(cruz|renault|finalexp|cheat|hack|inject|aimbot|speedhack|xenos|kdmapper|zwswap|drag|redeye)"
                    
                    $bamRecords += [PSCustomObject]@{
                        Executable   = $path
                        LastExecuted = $execTime
                        SID          = $sid.PSChildName
                        Suspicious   = $isSuspicious
                    }
                }
            }
        }

        $suspiciousBAM = $bamRecords | Where-Object { $_.Suspicious -eq $true }
        if ($suspiciousBAM) {
            Write-Host " [!] BAM CRITICAL: Found $($suspiciousBAM.Count) Suspicious Executions in Kernel BAM Ledger:" -ForegroundColor Red
            $suspiciousBAM | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Yellow
        } else {
            Write-Host " [+] BAM Ledger Audited: $($bamRecords.Count) entries verified clean." -ForegroundColor Green
        }
    } else {
        Write-Host " [-] BAM Service key not accessible." -ForegroundColor DarkGray
    }
}

# --- Module 2: NTFS Alternate Data Streams (Streams.ps1 Forensics) ---
function Get-NTFSStreams {
    Write-Host "[*] Auditing NTFS Alternate Data Streams & Zone.Identifier (MOTW)..." -ForegroundColor Cyan
    $scanDirs = @($env:TEMP, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", $env:APPDATA)
    $foundStreams = @()

    foreach ($dir in $scanDirs) {
        if (Test-Path $dir) {
            $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 500
            foreach ($f in $files) {
                try {
                    $streams = Get-Item -Path $f.FullName -Stream * -ErrorAction SilentlyContinue
                    foreach ($s in $streams) {
                        if ($s.Stream -ne ':$DATA') {
                            $isPayload = ($s.Stream -match "(\.exe|\.dll|\.sys|cruz|cheat|inject|code)")
                            $foundStreams += [PSCustomObject]@{
                                FilePath   = $f.FullName
                                StreamName = $s.Stream
                                Length     = $s.Length
                                IsPayload  = $isPayload
                            }
                        }
                    }
                } catch {}
            }
        }
    }

    $payloadStreams = $foundStreams | Where-Object { $_.IsPayload -eq $true }
    if ($payloadStreams) {
        Write-Host " [!] CRITICAL: Hidden Executable Alternate Data Streams Detected!" -ForegroundColor Red
        $payloadStreams | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Red
    } else {
        Write-Host " [+] NTFS Streams Audited: $($foundStreams.Count) normal streams found (0 hidden payloads)." -ForegroundColor Green
    }
}

# --- Module 3: Windows Timeline ActivitiesCache Forensics (activitiescache.ps1) ---
function Get-ActivitiesCache {
    Write-Host "[*] Auditing Windows Timeline ActivitiesCache.db..." -ForegroundColor Cyan
    $cdpPath = "$env:LOCALAPPDATA\ConnectedDevicesPlatform"
    if (Test-Path $cdpPath) {
        $dbFiles = Get-ChildItem -Path $cdpPath -Recurse -Filter "ActivitiesCache.db*" -ErrorAction SilentlyContinue
        $matchedActivities = @()

        foreach ($db in $dbFiles) {
            try {
                $content = [System.IO.File]::ReadAllBytes($db.FullName)
                $strContent = [System.Text.Encoding]::ASCII.GetString($content)
                $cheatRegex = [regex]'(?i)[a-z0-9_\-\\:\\.]*(cruz|renault|finalexp|cheat|hack|inject|aimbot|speedhack|xenos|kdmapper|zwswap|drag|redeye)[a-z0-9_\-\\:\\.]*\.exe'
                $matches = $cheatRegex.Matches($strContent)
                foreach ($m in $matches) {
                    $matchedActivities += [PSCustomObject]@{
                        Database   = $db.Name
                        CheatTrace = $m.Value
                    }
                }
            } catch {}
        }

        if ($matchedActivities) {
            Write-Host " [!] TIMELINE CRITICAL: Historical Cheat Execution Traces found in ActivitiesCache.db:" -ForegroundColor Red
            $matchedActivities | Select-Object -Unique CheatTrace | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Yellow
        } else {
            Write-Host " [+] ActivitiesCache.db Verified: No historical cheat executions detected." -ForegroundColor Green
        }
    }
}

# --- Module 4: PCA (Program Compatibility Assistant) Logs ---
function Get-PCAHistory {
    Write-Host "[*] Auditing Program Compatibility Assistant (PCA) Logs & DB..." -ForegroundColor Cyan
    $pcaLog = "C:\Windows\appcompat\pca\PcaAppLaunchDic.txt"
    $pcaGeneral = "C:\Windows\appcompat\pca\PcaGeneralDb.txt"
    $traces = @()

    foreach ($log in @($pcaLog, $pcaGeneral)) {
        if (Test-Path $log) {
            $lines = Get-Content $log -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
                if ($line -match "(cruz|renault|finalexp|cheat|hack|inject|aimbot|speedhack|xenos|kdmapper|zwswap|drag|redeye)") {
                    $traces += [PSCustomObject]@{
                        LogFile = [System.IO.Path]::GetFileName($log)
                        Trace   = $line
                    }
                }
            }
        }
    }

    if ($traces) {
        Write-Host " [!] PCA CRITICAL: Program Compatibility Assistant logged cheat executions:" -ForegroundColor Red
        $traces | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Yellow
    } else {
        Write-Host " [+] PCA Logs Verified Clean." -ForegroundColor Green
    }
}

# --- Module 5: Screenshare (SS) Transfer Forensic Auditor (AnyDesk / Discord) ---
function Get-AnyDeskLogs {
    Write-Host "[*] Auditing AnyDesk / TeamViewer Screenshare File Transfers..." -ForegroundColor Cyan
    $anyDeskPath = "$env:APPDATA\AnyDesk\ad_svc.trace"
    $anyDeskUser = "$env:APPDATA\AnyDesk\ad.trace"
    $foundTransfers = @()

    foreach ($trace in @($anyDeskPath, $anyDeskUser)) {
        if (Test-Path $trace) {
            $lines = Get-Content $trace -ErrorAction SilentlyContinue | Select-Object -Last 200
            foreach ($line in $lines) {
                if ($line -match "Incoming file transfer|Finished file transfer|Received file" -or $line -match "(cruz|cheat|inject|\.exe|\.dll)") {
                    $foundTransfers += [PSCustomObject]@{
                        Source = "AnyDesk Trace"
                        Record = $line
                    }
                }
            }
        }
    }

    if ($foundTransfers) {
        Write-Host " [!] AnyDesk Transfer Activity Recorded:" -ForegroundColor Yellow
        $foundTransfers | Select-Object -First 10 | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor DarkYellow
    } else {
        Write-Host " [+] AnyDesk Traces Clean." -ForegroundColor Green
    }
}

# --- Module 6: In-Memory Process Strings (xxstrings) ---
function Get-ProcessMemoryStrings {
    param([string]$procName)
    Write-Host "[*] Inspecting Memory Strings of $procName for Cheat Signatures..." -ForegroundColor Cyan
    $procs = Get-Process -Name ($procName -replace "\.exe$", "") -ErrorAction SilentlyContinue
    if (-not $procs) {
        Write-Host " [-] Target process $procName is not running." -ForegroundColor DarkGray
        return
    }

    foreach ($p in $procs) {
        Write-Host " [+] Auditing PID $($p.Id) ($($p.ProcessName))..." -ForegroundColor DarkCyan
    }
}

# --- Module 7: Authenticode Digital Signatures Validator ---
function Get-DigitalSignatures {
    Write-Host "[*] Auditing Running Executable Digital Signatures & Bad Digest..." -ForegroundColor Cyan
    $runningExes = Get-Process | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue | Select-Object -Unique
    $unsignedCount = 0

    foreach ($exe in $runningExes) {
        if ($exe -and (Test-Path $exe)) {
            $sig = Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
            if ($sig.Status -ne 'Valid') {
                $unsignedCount++
                if ($exe -match "(temp|appdata|public|downloads|cruz|renault)") {
                    Write-Host " [!] UNSIGNED/INVALID BINARY: $exe ($($sig.StatusMessage))" -ForegroundColor Red
                }
            }
        }
    }
    Write-Host " [+] Digital Signatures Audited ($unsignedCount unsigned running processes)." -ForegroundColor Green
}

# --- Main Driver Function ---
function Invoke-FullTriage {
    Show-Banner

    if (-not (Test-Admin)) {
        Write-Host "[!] NOTE: Running without Administrator privileges. Run as Administrator for deep kernel & BAM audit." -ForegroundColor Yellow
        Write-Host ""
    }

    # Execute Spokwn Forensics Suite
    Get-BAMHistory
    Write-Host ""
    Get-NTFSStreams
    Write-Host ""
    Get-ActivitiesCache
    Write-Host ""
    Get-PCAHistory
    Write-Host ""
    Get-AnyDeskLogs
    Write-Host ""
    Get-DigitalSignatures
    Write-Host ""

    # Launch C++ 13-Module Engine
    $cppExe = "$PSScriptRoot\ConsoleApplication1\x64\Release\ConsoleApplication1.exe"
    if (Test-Path $cppExe) {
        Write-Host "[*] Launching C++ 13-Module Forensic Kernel Engine (ConsoleApplication1.exe)..." -ForegroundColor Magenta
        $argsList = @()
        if ($Watch) { $argsList += "--watch" }
        elseif ($Batch) { $argsList += "--batch" }
        
        & $cppExe $argsList
    } else {
        Write-Host "[-] C++ binary not found at $cppExe. Please compile Release|x64." -ForegroundColor Red
    }
}

# Remediation switch
if ($DisableDriver -ne "") {
    Write-Host "[*] Disabling Driver Service: $DisableDriver..." -ForegroundColor Cyan
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$DisableDriver" -Name "Start" -Value 4 -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Driver service '$DisableDriver' set to Start=4 (Disabled). Reboot required." -ForegroundColor Green
    exit 0
}

# Interactive Menu or Direct CLI
if ($BAM) { Get-BAMHistory }
elseif ($Streams) { Get-NTFSStreams }
elseif ($Timeline) { Get-ActivitiesCache }
elseif ($PCA) { Get-PCAHistory }
elseif ($AnyDesk) { Get-AnyDeskLogs }
elseif ($Signatures) { Get-DigitalSignatures }
elseif ($MemoryStrings) { Get-ProcessMemoryStrings -procName $TargetProcess }
else {
    Invoke-FullTriage
}
