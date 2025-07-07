# System Inventory & Forensics Collection Script
# Run as Administrator for best results

$usbIdsPath = "$PSScriptRoot\usb.ids.txt"
if (-not (Test-Path $usbIdsPath)) {
    Invoke-WebRequest -Uri "http://www.linux-usb.org/usb.ids" -OutFile $usbIdsPath
}

$report = @()

# 📌 System Identification
$sysInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$timezone = Get-TimeZone
$bootTime = Get-Date $osInfo.LastBootUpTime -Format "yyyy-MM-dd HH:mm:ss"
$installDate = Get-Date $osInfo.InstallDate -Format "yyyy-MM-dd HH:mm:ss"
$arch = if ($osInfo.OSArchitecture -match "64") { "64-bit" } else { "32-bit" }
$controlSet = Get-ItemProperty -Path "HKLM:\SYSTEM\Select" | Select-Object -ExpandProperty Current
$currentVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Select-Object -ExpandProperty ReleaseId
$bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint, VolumeStatus, ProtectionStatus

$report += ""
$report += "=== System Identification ===:"
$report += "- System Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "- Computer Name: $($sysInfo.Name)"
$report += "- Architecture: $arch"
$report += "- Current Version: $currentVersion"
$report += "- Manufacturer & Model: $($sysInfo.Manufacturer) $($sysInfo.Model)"
$report += "- OS Version & Build: $($osInfo.Caption) $($osInfo.Version) (Build $($osInfo.BuildNumber))"
$report += "- System Install Date: $installDate"
$report += "- Time Zone: $($timezone.DisplayName)"
$report += "- Active ControlSet: $controlSet"
if ($bitlocker) {
    foreach ($vol in $bitlocker) {
        $report += "- BitLocker Status ($($vol.MountPoint)): $($vol.ProtectionStatus)"
    }
}
else {
    $report += "- BitLocker Status: Not enabled or unavailable"
}

# 💽 Storage & Volumes
$report += "`n=== Storage & Volumes ===:"

$disks = Get-Disk
$volumes = Get-Volume
$partitions = Get-Partition

foreach ($disk in $disks) {
    $physicalName = "\\.\PHYSICALDRIVE$($disk.Number):"
    $model = (Get-CimInstance -ClassName Win32_DiskDrive | Where-Object { $_.Index -eq $disk.Number }).Model
    $serial = (Get-CimInstance -ClassName Win32_DiskDrive | Where-Object { $_.Index -eq $disk.Number }).SerialNumber
    $partitionStyle = $disk.PartitionStyle

    # Get all partitions for this disk
    $diskPartitions = $partitions | Where-Object { $_.DiskNumber -eq $disk.Number }
    if ($diskPartitions) {
        foreach ($part in $diskPartitions) {
            # Get all volumes for this partition, safely check AccessPaths and UniqueId
            $partVolumes = @()
            if ($part.PSObject.Properties.Match('AccessPaths') -and $part.AccessPaths -and $part.AccessPaths.Count -gt 0) {
                $partVolumes = $volumes | Where-Object { $_.ObjectId -eq $part.AccessPaths[0] }
            }
            if (-not $partVolumes -and $part.PSObject.Properties.Match('UniqueId') -and $part.UniqueId) {
                $partVolumes = $volumes | Where-Object { $_.UniqueId -eq $part.UniqueId }
            }
            if (-not $partVolumes -and $part.PSObject.Properties.Match('DriveLetter') -and $part.DriveLetter) {
                $partVolumes = $volumes | Where-Object { $_.DriveLetter -eq $part.DriveLetter }
            }
            foreach ($vol in $partVolumes) {
                $driveLetter = $vol.DriveLetter
                $volSerial = $vol.UniqueId
                $fs = $vol.FileSystem
                $totalSize = [math]::Round($vol.Size / 1GB, 2)
                $free = [math]::Round($vol.SizeRemaining / 1GB, 2)
                $used = [math]::Round(($vol.Size - $vol.SizeRemaining) / 1GB, 2)
                $report += "$physicalName"
                $report += "  - Drive Letter: $driveLetter"
                $report += "  - Partition Number: $($part.PartitionNumber)"
                $report += "  - Partition GUID: $($part.GUID)"
                $report += "  - Volume Serial: $volSerial"
                $report += "  - File System: $fs"
                $report += "  - Disk Model: $model"
                $report += "  - Serial Number: $serial"
                $report += "  - Partition Style: $partitionStyle"
                $report += "  - Total Size: $totalSize GB"
                $report += "  - Used Space: $used GB"
                $report += "  - Free Space: $free GB"
            }
        }
    }
    else {
        # Disk with no partitions/volumes
        $report += "$physicalName"
        $report += "  - Disk Model: $model"
        $report += "  - Serial Number: $serial"
        $report += "  - Partition Style: $partitionStyle"
        $report += "  - No volumes/partitions found"
    }
}

# 🌐 Network Configuration
$report += "`n=== Network Configuration ===:"
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    $ip = (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
    $mac = $adapter.MacAddress
    $dhcp = (Get-NetIPInterface -InterfaceIndex $adapter.ifIndex).Dhcp
    $report += "- Adapter: $($adapter.Name) | IP: $ip | MAC: $mac | DHCP: $dhcp"
}
$wifi = netsh wlan show interfaces 2>$null | Select-String 'SSID' | ForEach-Object { $_.Line.Trim() }
$wifi = netsh wlan show interfaces 2>$null | Select-String 'SSID' | ForEach-Object { $_.Line.Trim() }
if ($wifi) { $report += "- Wi-Fi SSIDs: $(($wifi | ForEach-Object { $_ }) -join ', ')" }
$dns = (Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses }).ServerAddresses -join ', '
$report += "- Default Gateway: $gateway"
$report += "- DNS Servers: $dns"
$report += "- ARP Table:"
$report += arp -a
$report += "- Hosts File Entries:"
$report += Get-Content "$env:SystemRoot\System32\drivers\etc\hosts"
$vpn = Get-VpnConnection -ErrorAction SilentlyContinue
if ($vpn) { $report += "- VPN Connections: $($vpn.Name -join ', ')" }
$proxy = netsh winhttp show proxy
$report += "- Proxy Settings: $proxy"

# 👥 User Accounts
$report += "`n=== User Accounts ===:"
$users = Get-LocalUser
foreach ($user in $users) {
    $sid = (Get-LocalUser $user.Name).SID.Value
    $lastLogon = if ($user.LastLogon) { $user.LastLogon.ToString('yyyy-MM-dd HH:mm:ss') } else { "Never" }
    $report += "- User: $($user.Name)"
    $report += "  SID: $sid"
    $report += "  Enabled: $($user.Enabled)"
    $report += "  Last Logon: $lastLogon"
}
$groups = Get-LocalGroup
$report += "`nGroups:"
foreach ($group in $groups) {
    $members = (Get-LocalGroupMember $group.Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ', '
    $report += "- Group-name: $($group.Name) | Members: $members"
}
$report += "`nPassword Policy:"
$report += net accounts

# 🔌 Connected Devices
$report += "`n=== Previously Connected USB, Wifi, Blueooth, and Network Shares ===:"
$report += "Network Adapters:"
$networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $networkAdapters) {
    $report += "- Adapter: $($adapter.Name) | MAC: $($adapter.MacAddress) | Status: $($adapter.Status)"
}
$report += "`nWi-Fi Networks:"
$wifiNetworks = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { $_.ToString().Split(":")[1].Trim() }
if ($wifiNetworks) {
    foreach ($network in $wifiNetworks) {
        $report += "- Wi-Fi Network: $network"
    }
}
$report += "`nBluetooth Devices:"
$bluetoothDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue
if ($bluetoothDevices) {
    foreach ($device in $bluetoothDevices) {
        $report += "- Bluetooth Device: $($device.FriendlyName) | Instance ID: $($device.InstanceId)"
    }
}
$report += "`nUSB Devices:"
$usbDevices = Get-PnpDevice -Class USB -ErrorAction SilentlyContinue
if ($usbDevices) {
    foreach ($device in $usbDevices) {
        $report += "- USB Device: $($device.FriendlyName) | Instance ID: $($device.InstanceId) | Status: $($device.Status) | Manufacturer: $($device.Manufacturer) | Description: $($device.Description)"
    }
}
$report += "`nMounted Drives:"
$mountedDrives = Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -or $_.DriveType -eq 'Fixed' }
foreach ($drive in $mountedDrives) {
    $driveLetter = if ($drive.DriveLetter) { $drive.DriveLetter } else { "_" }
    $report += "- Mounted Drive: $driveLetter | Label: $($drive.FileSystemLabel) | Size: $([math]::Round($drive.Size / 1GB, 2)) GB"
}

$report += "`nRegistry Mounted Points:"
# Get all mounted devices and exclude PS* properties
$mountPoints = Get-ItemProperty -Path "HKLM:\SYSTEM\MountedDevices" | Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider

# Build a hashtable to group mount points by their binary target
$targetMap = @{}
foreach ($mp in $mountPoints.PSObject.Properties) {
    if ($mp.Name -ne "Default") {
        $bin = [BitConverter]::ToString($mp.Value)
        if (-not $targetMap.ContainsKey($bin)) {
            $targetMap[$bin] = @()
        }
        $targetMap[$bin] += $mp.Name
    }
}

# Output combined mount points
foreach ($bin in $targetMap.Keys) {
    $names = $targetMap[$bin] -join ", "
    $report += "- MountPoint(s): $names | Target: $bin"
}
foreach ($mp in $mountPoints) {
    if ($mp.Name -ne "Default") {
        # Collect all mountpoints and their targets
        $mountPointsList = @()
        $mountPointsList += "- MountPoint: $($mp.Name) | Target: $($mp.Value)"
        # After the loop, join all targets for the same mountpoint
        if ($mountPointsList.Count -gt 0) {
            $report += ($mountPointsList -join ", ")
        }
    }
}

$report += "`nNetwork Shares:"
$shares = Get-SmbShare | Select-Object Name, Path, Description
foreach ($share in $shares) {
    $report += "- Share: $($share.Name) | Path: $($share.Path) | Description: $($share.Description)"
}
$report += "`n- Previous Connections (MountPoints2):"
$mountPoints = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\DOS Devices" -ErrorAction SilentlyContinue
if ($mountPoints) {
    foreach ($mp in $mountPoints.PSObject.Properties) {
        if ($mp.Name -ne "Default") {
            $report += "- MountPoint: $($mp.Name) | Target: $($mp.Value)"
        }
    }
}
else {
    $report += "- No previous connections found."
}
$report += "`nUSB Devices:"
# Using Get-WmiObject for USB devices
$usb = Get-WmiObject Win32_USBHub
foreach ($dev in $usb) {
    $report += "- USB Device: $($dev.DeviceID) | $($dev.Description) | $($dev.PNPDeviceID)"
}
$report += "`nBluetooth Devices:"
$bt = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue
if ($bt) { $bt | ForEach-Object { $report += "- $($_.FriendlyName): $($_.InstanceId)" } }
$report += "`nMounted External Drives:"
$ext = Get-Volume | Where-Object { $_.DriveType -eq 'Removable' }
foreach ($e in $ext) {
    $report += "- Drive: $($e.DriveLetter) | Label: $($e.FileSystemLabel)"
}

# 📂 System & Artifact Analysis
#$report += "`n=== System and Artifact Analysis ===:"
#$report += "- Installed Applications:"
#$apps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null | Select-Object DisplayName, DisplayVersion, Publisher
#foreach ($app in $apps) {
#    if ($app.DisplayName) { $report += "$($app.DisplayName) ($($app.DisplayVersion)) - $($app.Publisher)" }
#}
#$report += "- Running Processes:"
#$procs = Get-Process | Select-Object ProcessName, Id, StartTime
#foreach ($proc in $procs) {
#    $report += "$($proc.ProcessName) (PID: $($proc.Id)) Started: $($proc.StartTime)"
#}
#$report += "- Scheduled Tasks:"
#$tasks = Get-ScheduledTask | Select-Object TaskName, State
#foreach ($task in $tasks) {
#    $report += "$($task.TaskName) - $($task.State)"
#}

$report += "`nStartup Programs:"
$startup = Get-CimInstance Win32_StartupCommand
foreach ($item in $startup) {
    $report += "  $($item.Name):"
    $report += "  - Command: `'$($item.Command)`'"
    $report += "  - Location: $($item.Location)"
    $report += "  - User: $($item.User)"
}
# $report += "- TSL/SSL Certificates and private keys:"
$certs = Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Subject, Thumbprint, NotBefore, NotAfter
foreach ($cert in $certs) {
    $report += "- Certificate: $($cert.Subject) | Thumbprint: $($cert.Thumbprint) | Valid From: $($cert.NotBefore) To: $($cert.NotAfter)"
}

$report += "`nCleared Event Logs:"
# Look for event log clear events (Event ID 104) in Windows Event Logs
$clearedEvents = Get-WinEvent -LogName 'Security', 'System', 'Application' -FilterXPath "*[System[(EventID=104)]]" -ErrorAction SilentlyContinue
if ($clearedEvents) {
    foreach ($evt in $clearedEvents) {
        $report += "- Log: $($evt.LogName) | Cleared By: $($evt.Properties[1].Value) | Time: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))"
    }
}
else {
    $report += "- No log clear events found."
}

$report += "`nWindows Defender Quarantined:"
$defenderQuarantine = Get-MpThreat -ErrorAction SilentlyContinue | Select-Object Name, Action, Severity
if ($defenderQuarantine) {
    foreach ($threat in $defenderQuarantine) {
        $report += "- Threat: $($threat.Name) | Action: $($threat.Action) | Severity: $($threat.Severity)"
    }
}
else {
    $report += "- No threats found in Windows Defender quarantine."
}

$report += ""
$report += "`nWindows Defender Scan History:"
# Windows Defender Scan History
# Get recent scan start/finish events (ID 1000=start, 1001=finish)
$defenderScanEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -ErrorAction SilentlyContinue |
Where-Object { $_.Id -eq 1000 -or $_.Id -eq 1001 } |
Sort-Object TimeCreated -Descending |
Select-Object -First 20

if ($defenderScanEvents) {
    # Group by Scan ID (from Message, GUID format)
    $scanGroups = @{}
    foreach ($evt in $defenderScanEvents) {
        $scanId = $null
        if ($evt.Message -match 'Scan ID:\s*({[A-F0-9\-]+})') {
            $scanId = $matches[1]
        }
        elseif ($evt.Message -match 'Scan ID:\s*(\d+)') {
            $scanId = $matches[1]
        }
        else {
            $scanId = "Unknown"
        }
        if (-not $scanGroups.ContainsKey($scanId)) {
            $scanGroups[$scanId] = @()
        }
        $scanGroups[$scanId] += $evt
    }

    foreach ($scanId in $scanGroups.Keys) {
        $scanEvents = $scanGroups[$scanId] | Sort-Object TimeCreated
        $startEvt = $scanEvents | Where-Object { $_.Id -eq 1000 } | Select-Object -First 1
        $finishEvt = $scanEvents | Where-Object { $_.Id -eq 1001 } | Select-Object -First 1

        $report += "Scan ID: $scanId"
        if ($startEvt) {
            $report += "- ScanStart: $($startEvt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | Event ID: 1000 | Microsoft Defender Antivirus scan has started."
        }
        if ($finishEvt) {
            $report += "- ScanFinish: $($finishEvt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | Event ID: 1001 | Microsoft Defender Antivirus scan has finished."
        }
        if ($startEvt -and $finishEvt) {
            $span = $finishEvt.TimeCreated - $startEvt.TimeCreated
            $report += "- Scan Time: $($span.ToString('hh\:mm\:ss'))"
        }

        # Extract Scan Type, Parameters, User from start event message
        $scanType = $null
        $scanParams = $null
        $user = $null
        if ($startEvt) {
            if ($startEvt.Message -match 'Scan Type:\s*(.+)') { $scanType = $matches[1].Trim() }
            if ($startEvt.Message -match 'Scan Parameters:\s*(.+)') { $scanParams = $matches[1].Trim() }
            if ($startEvt.Message -match 'User:\s*(.+)') { $user = $matches[1].Trim() }
        }
        if ($scanType) { $report += "- Scan Type: $scanType" }
        if ($scanParams) { $report += "- Scan Parameters: $scanParams" }
        if ($user) { $report += "- User: $user" }
    }
}
else {
    $report += "- No scan history events found in Windows Defender."
}

# Symantec Endpoint Protection Scan History
$report += "`nSymantec Endpoint Protection Scan History:"
$symantecLogs = @(
    "$env:ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\AV\*.log",
    "$env:ProgramData\Symantec\Symantec Endpoint Protection\*.log"
)
$symantecFound = $false
foreach ($logPath in $symantecLogs) {
    $files = Get-ChildItem -Path $logPath -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $lines = Get-Content $file.FullName -ErrorAction SilentlyContinue | Select-String -Pattern "Scan", "Virus", "Threat"
        if ($lines) {
            $symantecFound = $true
            $report += "- Log File: $($file.FullName)"
            foreach ($line in $lines) {
                $report += "  $($line.Line.Trim())"
            }
        }
    }
}
if (-not $symantecFound) {
    $report += "- No Symantec scan logs found."
}

# McAfee/Trillix Scan History
$report += "`nMcAfee/Trillix Scan History:"
$mcafeeLogs = @(
    "$env:ProgramData\McAfee\Endpoint Security\Logs\*.log",
    "$env:ProgramFiles\McAfee\Endpoint Security\Logs\*.log",
    "$env:ProgramFiles(x86)\McAfee\Endpoint Security\Logs\*.log"
)
$mcafeeFound = $false
foreach ($logPath in $mcafeeLogs) {
    $files = Get-ChildItem -Path $logPath -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $lines = Get-Content $file.FullName -ErrorAction SilentlyContinue | Select-String -Pattern "Scan", "Threat", "Virus"
        if ($lines) {
            $mcafeeFound = $true
            $report += "- Log File: $($file.FullName)"
            foreach ($line in $lines) {
                $report += "  $($line.Line.Trim())"
            }
        }
    }
}
if (-not $mcafeeFound) {
    $report += "- No McAfee/Trillix scan logs found."
}

# Malwarebytes Scan History
$report += "`nMalwarebytes Scan History:"
$mbamLogDirs = @(
    "$env:ProgramData\Malwarebytes\MBAMService\logs\*.txt",
    "$env:ProgramData\Malwarebytes\MBAMService\ScanResults\*.xml",
    "$env:ProgramData\Malwarebytes\MBAMService\ScanResults\*.json"
)
$mbamFound = $false
foreach ($logPath in $mbamLogDirs) {
    $files = Get-ChildItem -Path $logPath -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $mbamFound = $true
        $report += "- Log File: $($file.FullName)"
        # Output first few lines for summary
        $lines = Get-Content $file.FullName -ErrorAction SilentlyContinue | Select-Object -First 10
        foreach ($line in $lines) {
            $report += "  $($line.Trim())"
        }
    }
}
if (-not $mbamFound) {
    $report += "- No Malwarebytes scan logs found."
}

# Output to file

# === Whitelist Filtering ===
$whitelistPath = "$PSScriptRoot\whitelist.txt"
$whitelist = @()
if (Test-Path $whitelistPath) {
    $whitelist = Get-Content $whitelistPath | Where-Object { $_ -and -not $_.Trim().StartsWith('#') } | ForEach-Object { $_.Trim() }
}

if ($whitelist.Count -gt 0) {
    $filteredReport = @()
    foreach ($line in $report) {
        $ignore = $false
        foreach ($item in $whitelist) {
            if ($item -and $line -match [regex]::Escape($item)) {
                $ignore = $true
                break
            }
        }
        if (-not $ignore) { $filteredReport += $line }
    }
    $report = $filteredReport
}

$report | Out-File -Encoding UTF8 -FilePath "$env:COMPUTERNAME-ForensicReport.yaml"
Write-Host "Report saved to $env:COMPUTERNAME-ForensicReport.yaml"