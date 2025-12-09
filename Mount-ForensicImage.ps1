<#
.SYNOPSIS
    Arsenal Image Mounter helper functions for mounting forensic images.
.DESCRIPTION
    Provides Mount-E01Image and Dismount-E01Image functions using the Arsenal
    Image Mounter CLI (aim_cli.exe) for mounting forensic images.
.NOTES
    Part of KAPErton forensic workflow toolkit.
    Requires Administrator privileges for mounting operations.
#>

#Requires -Version 5.1

# Script root path
$script:ScriptRoot = $PSScriptRoot
if (-not $script:ScriptRoot) { $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

# AIM CLI paths - check multiple locations
$script:AIMCliPath = $null
$possiblePaths = @(
    (Join-Path $script:ScriptRoot "AIM\aim_cli.exe"),
    (Join-Path $script:ScriptRoot "AIM\aim_cli"),
    (Join-Path $script:ScriptRoot "AIM\PowerShell\net48\aim_cli.exe"),
    (Join-Path $script:ScriptRoot "AIM\PowerShell\net48\aim_cli")
)

foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $script:AIMCliPath = $path
        break
    }
}

# Track mounted disks for cleanup
$script:MountedDisks = @{}

function Test-AIMInstallation {
    <#
    .SYNOPSIS
        Verifies AIM CLI is available and functional.
    #>
    [CmdletBinding()]
    param()
    
    if (-not $script:AIMCliPath -or -not (Test-Path $script:AIMCliPath)) {
        Write-Host "AIM CLI not found. Searched locations:" -ForegroundColor Red
        foreach ($path in $possiblePaths) {
            Write-Host "  - $path" -ForegroundColor Gray
        }
        return $false
    }
    
    Write-Verbose "AIM CLI found at: $script:AIMCliPath"
    return $true
}

function Get-MountedAIMDevices {
    <#
    .SYNOPSIS
        Lists all currently mounted AIM devices.
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-AIMInstallation)) { return @() }
    
    try {
        $output = & $script:AIMCliPath --list 2>&1
        return $output
    }
    catch {
        Write-Warning "Failed to list AIM devices: $($_.Exception.Message)"
        return @()
    }
}

function Mount-E01Image {
    <#
    .SYNOPSIS
        Mounts an E01/EWF forensic image using Arsenal Image Mounter CLI.
    .DESCRIPTION
        Mounts the specified forensic image with a write overlay (temp file),
        fake disk signature, and brings partitions online with drive letter assignment.
    .PARAMETER ImagePath
        Full path to the E01 image file.
    .PARAMETER ReadOnly
        Mount as read-only without write overlay.
    .OUTPUTS
        PSCustomObject with mount information including drive letters.
    .EXAMPLE
        $mount = Mount-E01Image -ImagePath "C:\Evidence\disk.E01"
        $mount.DriveLetters  # Returns array of assigned drive letters
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$ImagePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$ReadOnly
    )
    
    if (-not (Test-AIMInstallation)) {
        throw "Arsenal Image Mounter CLI not found."
    }
    
    $imageName = Split-Path $ImagePath -Leaf
    $imageDir = Split-Path $ImagePath -Parent
    $imageBaseName = [System.IO.Path]::GetFileNameWithoutExtension($imageName)
    
    # Check if this image is already mounted
    Write-Verbose "Checking if image is already mounted..."
    $listOutput = & $script:AIMCliPath --list 2>&1 | Out-String
    
    if ($listOutput -match [regex]::Escape($ImagePath)) {
        Write-Host "Image is already mounted: $imageName" -ForegroundColor Yellow
        Write-Verbose "Parsing existing mount information..."
        
        # Parse existing mount points
        $driveLetters = @()
        $listOutput -split "`n" | ForEach-Object {
            if ($_ -match 'Mounted at ([A-Z]:\\)') {
                $driveLetter = $Matches[1].TrimEnd('\')
                if ($driveLetter -notin $driveLetters) {
                    $driveLetters += $driveLetter
                }
            }
        }
        
        if ($driveLetters.Count -gt 0) {
            Write-Host "  Using existing mount: $($driveLetters -join ', ')" -ForegroundColor Green
            
            return [PSCustomObject]@{
                ImagePath = $ImagePath
                ImageName = $imageName
                DriveLetters = $driveLetters
                MountedAt = Get-Date
                AlreadyMounted = $true
            }
        }
        else {
            Write-Host "  Warning: Image appears mounted but no drive letters found. Attempting to dismount and remount..." -ForegroundColor Yellow
            
            # Try to dismount the stuck mount
            try {
                & $script:AIMCliPath --dismount --device=all 2>&1 | Out-Null
                Start-Sleep -Seconds 2
            }
            catch {
                Write-Verbose "Dismount attempt completed: $_"
            }
        }
    }
    
    Write-Host "Mounting image: $imageName" -ForegroundColor Cyan
    Write-Verbose "Full path: $ImagePath"
    
    # Get disk state before mounting to detect new drives
    $disksBefore = Get-Disk | Select-Object -ExpandProperty Number
    $drivesBefore = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
    
    try {
        # Build AIM CLI arguments
        # --mount: Mount the image
        # --fakesig: Use fake disk signature to avoid conflicts
        # --online: Bring partitions online with drive letters
        # --provider=libewf: Use libewf for E01 format
        # --writeoverlay: Temp file for write operations (forensic integrity)
        # --autodelete: Delete overlay file when dismounted
        
        $overlayPath = Join-Path $imageDir "$imageBaseName.diff"
        
        $aimArgs = @(
            "--mount",
            "--fakesig",
            "--online",
            "--filename=$ImagePath",
            "--provider=libewf",
            "--background"
        )
        
        if (-not $ReadOnly) {
            $aimArgs += "--writeoverlay=$overlayPath"
            $aimArgs += "--autodelete"
            Write-Verbose "Using write overlay: $overlayPath"
        }
        else {
            $aimArgs += "--readonly"
            Write-Verbose "Mounting as read-only."
        }
        
        Write-Debug "AIM CLI command: & `"$script:AIMCliPath`" $($aimArgs -join ' ')"
        Write-Host "  Executing AIM CLI..." -ForegroundColor Yellow
        
        # Build command line string manually to avoid quoting issues
        $cmdLine = $aimArgs -join " "
        Write-Verbose "Command line: $cmdLine"
        
        # Execute AIM CLI with --background flag (don't wait, it returns immediately)
        $process = Start-Process -FilePath $script:AIMCliPath -ArgumentList $cmdLine -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\aim_mount_stdout.txt" -RedirectStandardError "$env:TEMP\aim_mount_stderr.txt"
        
        # Give it a moment to start
        Start-Sleep -Milliseconds 500
        
        # Check if process already exited (quick execution)
        if ($process.HasExited) {
            $exitCode = $process.ExitCode
            Write-Host "  AIM CLI completed with exit code: $exitCode" -ForegroundColor Gray
            
            $stdout = Get-Content "$env:TEMP\aim_mount_stdout.txt" -Raw -ErrorAction SilentlyContinue
            $stderr = Get-Content "$env:TEMP\aim_mount_stderr.txt" -Raw -ErrorAction SilentlyContinue
            
            if ($stdout) { Write-Verbose "AIM stdout: $stdout" }
            if ($stderr) { 
                Write-Verbose "AIM stderr: $stderr"
                if ($stderr -match 'error|fail|exception|denied') {
                    Write-Host "  AIM stderr: $stderr" -ForegroundColor Yellow
                }
            }
            
            if ($exitCode -ne 0) {
                throw "AIM CLI failed with exit code: $exitCode. Error: $stderr"
            }
        }
        else {
            Write-Verbose "AIM CLI running in background..."
        }
        
        # Wait for drives to appear
        Write-Verbose "Waiting for drive letters to be assigned..."
        Start-Sleep -Seconds 3
        
        # Use aim_cli --list to get actual mounted drives
        Write-Host "  Checking mounted drives..." -ForegroundColor Yellow
        $listOutput = & $script:AIMCliPath --list 2>&1 | Out-String
        Write-Verbose "AIM --list output: $listOutput"
        
        # Parse mount points from --list output
        $driveLetters = @()
        if ($listOutput -match 'Mounted at ([A-Z]:\\)') {
            $driveLetters += $Matches[1].TrimEnd('\')
        }
        # Check for multiple mounts
        $listOutput -split "`n" | ForEach-Object {
            if ($_ -match 'Mounted at ([A-Z]:\\)') {
                $driveLetter = $Matches[1].TrimEnd('\')
                if ($driveLetter -notin $driveLetters) {
                    $driveLetters += $driveLetter
                }
            }
        }
        
        # Fallback: Detect new drives by comparison
        if ($driveLetters.Count -eq 0) {
            Write-Verbose "No drives found via --list, falling back to drive comparison..."
            $disksAfter = Get-Disk | Select-Object -ExpandProperty Number
            $drivesAfter = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
            
            $newDrives = $drivesAfter | Where-Object { $_ -notin $drivesBefore -and $_.Length -eq 1 }
            $driveLetters = @($newDrives | ForEach-Object { "$($_):" })
        }
        
        # Parse device ID from output if possible
        $deviceId = $null
        if ($stdout -match '(\d{6})') {
            $deviceId = $Matches[1]
        }
        
        # Create result object
        $result = [PSCustomObject]@{
            ImagePath = $ImagePath
            ImageName = $imageName
            DeviceId = $deviceId
            DriveLetters = $driveLetters
            OverlayPath = if (-not $ReadOnly) { $overlayPath } else { $null }
            MountTime = Get-Date
            AIMOutput = $stdout
        }
        
        # Track for cleanup
        $script:MountedDisks[$ImagePath] = $result
        
        Write-Host "  Mounted successfully." -ForegroundColor Green
        if ($driveLetters.Count -gt 0) {
            Write-Host "  Drive letters: $($driveLetters -join ', ')" -ForegroundColor Green
        }
        else {
            Write-Host "  Warning: No drive letters assigned. Check disk management." -ForegroundColor Yellow
        }
        
        return $result
    }
    catch {
        $errorMessage = $_.Exception.Message
        
        # Parse common error conditions
        if ($errorMessage -match "access.*denied|permission" -or $errorMessage -match "administrator") {
            Write-Host "Access denied mounting $imageName. Ensure you're running as Administrator." -ForegroundColor Red
        }
        elseif ($errorMessage -match "file.*not.*found|cannot find") {
            Write-Host "Image file not found: $ImagePath" -ForegroundColor Red
        }
        elseif ($errorMessage -match "libewf|ewf") {
            Write-Host "E01/EWF format error. Ensure libewf.dll is available." -ForegroundColor Red
        }
        elseif ($errorMessage -match "signature|duplicate") {
            Write-Host "Disk signature conflict. The image may have a duplicate signature." -ForegroundColor Red
        }
        elseif ($errorMessage -match "corrupt|invalid|damaged") {
            Write-Host "Image appears to be corrupted or invalid: $imageName" -ForegroundColor Red
        }
        else {
            Write-Host "Failed to mount $imageName`: $errorMessage" -ForegroundColor Red
        }
        
        Write-Debug "Full error: $($_.Exception | Format-List -Force | Out-String)"
        return $null
    }
}

function Dismount-E01Image {
    <#
    .SYNOPSIS
        Dismounts a previously mounted forensic image.
    .PARAMETER MountInfo
        The mount information object returned by Mount-E01Image.
    .PARAMETER ImagePath
        Alternatively, specify the original image path to dismount.
    .PARAMETER DeviceId
        AIM device ID to dismount.
    .PARAMETER Force
        Force dismount even if volumes are in use.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'ByMountInfo')]
        [PSCustomObject]$MountInfo,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'ByPath')]
        [string]$ImagePath,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'ByDeviceId')]
        [string]$DeviceId,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    if (-not (Test-AIMInstallation)) {
        Write-Host "AIM CLI not found." -ForegroundColor Red
        return $false
    }
    
    # Determine device to dismount
    $targetDeviceId = $null
    $imageName = "Unknown"
    
    if ($PSCmdlet.ParameterSetName -eq 'ByPath' -and $ImagePath) {
        if ($script:MountedDisks.ContainsKey($ImagePath)) {
            $MountInfo = $script:MountedDisks[$ImagePath]
            $targetDeviceId = $MountInfo.DeviceId
            $imageName = $MountInfo.ImageName
        }
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'ByDeviceId' -and $DeviceId) {
        $targetDeviceId = $DeviceId
    }
    elseif ($MountInfo) {
        $targetDeviceId = $MountInfo.DeviceId
        $imageName = $MountInfo.ImageName
    }
    
    Write-Host "Dismounting: $imageName" -ForegroundColor Cyan
    
    try {
        $aimArgs = "--dismount"
        if ($targetDeviceId) {
            $aimArgs += "=$targetDeviceId"
        }
        if ($Force) {
            $aimArgs += " --force"
        }
        
        Write-Debug "AIM CLI command: $script:AIMCliPath $aimArgs"
        
        $process = Start-Process -FilePath $script:AIMCliPath -ArgumentList $aimArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            # Remove from tracking
            if ($MountInfo -and $MountInfo.ImagePath -and $script:MountedDisks.ContainsKey($MountInfo.ImagePath)) {
                $script:MountedDisks.Remove($MountInfo.ImagePath)
            }
            elseif ($ImagePath -and $script:MountedDisks.ContainsKey($ImagePath)) {
                $script:MountedDisks.Remove($ImagePath)
            }
            
            Write-Host "  Dismounted successfully." -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "  Dismount may have failed (exit code: $($process.ExitCode))." -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Host "Failed to dismount: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Dismount-AllImages {
    <#
    .SYNOPSIS
        Dismounts all AIM mounted images.
    .PARAMETER Force
        Force dismount even if volumes are in use.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    if (-not (Test-AIMInstallation)) {
        Write-Host "AIM CLI not found." -ForegroundColor Red
        return
    }
    
    Write-Host "Dismounting all AIM devices..." -ForegroundColor Cyan
    
    try {
        $aimArgs = "--dismount"
        if ($Force) {
            $aimArgs += " --force"
        }
        
        $process = Start-Process -FilePath $script:AIMCliPath -ArgumentList $aimArgs -Wait -PassThru -NoNewWindow
        
        # Clear tracking
        $script:MountedDisks.Clear()
        
        if ($process.ExitCode -eq 0) {
            Write-Host "  All devices dismounted." -ForegroundColor Green
        }
        else {
            Write-Host "  Dismount completed with code: $($process.ExitCode)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Failed to dismount all: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-MountedImages {
    <#
    .SYNOPSIS
        Lists all currently mounted forensic images (tracked by this session).
    #>
    [CmdletBinding()]
    param()
    
    if ($script:MountedDisks.Count -eq 0) {
        Write-Host "No images currently tracked as mounted by this session." -ForegroundColor Yellow
        Write-Host "Use 'Get-MountedAIMDevices' to see all AIM devices." -ForegroundColor Gray
        return @()
    }
    
    return $script:MountedDisks.Values | ForEach-Object {
        [PSCustomObject]@{
            ImageName = $_.ImageName
            DriveLetters = $_.DriveLetters -join ', '
            DeviceId = $_.DeviceId
            MountTime = $_.MountTime
            ImagePath = $_.ImagePath
        }
    }
}
