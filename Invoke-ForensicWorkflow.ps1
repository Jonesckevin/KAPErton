<#
.SYNOPSIS
    Integrated forensic workflow orchestrator for KAPErton toolkit.
.DESCRIPTION
    Main entry point that coordinates:
    1. Administrator privilege check with elevation prompt
    2. Arsenal Image Mounter (AIM) for mounting E01 forensic images from data/
    3. KAPE collection and module processing on each mounted partition
    4. ThorLite scanning of output folders for IOC detection
    5. Consolidated report generation
    
    Supports sequential processing (default) or parallel processing (PS 7+ only).
.PARAMETER Parallel
    Enable parallel processing of multiple E01 images (requires PowerShell 7+).
.PARAMETER ThrottleLimit
    Maximum number of parallel jobs when using -Parallel (default: 2).
.PARAMETER CaseName
    Name for the case/investigation (default: auto-generated from timestamp).
.PARAMETER SkipKAPE
    Skip KAPE collection phase (useful for re-running Thor scans only).
.PARAMETER SkipThor
    Skip ThorLite scanning phase.
.PARAMETER SkipSync
    Skip KAPE sync prompt and don't sync.
.PARAMETER ForceSync
    Force KAPE sync without prompting.
.EXAMPLE
    .\Invoke-ForensicWorkflow.ps1
    Runs the full workflow with default settings.
.EXAMPLE
    .\Invoke-ForensicWorkflow.ps1 -Parallel -Verbose
    Runs in parallel mode (PS 7+) with verbose output.
.EXAMPLE
    .\Invoke-ForensicWorkflow.ps1 -CaseName "Investigation_2024" -SkipThor
    Runs KAPE collection only with a custom case name.
.NOTES
    Part of KAPErton forensic workflow toolkit.
    Requires Administrator privileges for AIM mounting operations.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Parallel,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 8)]
    [int]$ThrottleLimit = 2,
    
    [Parameter(Mandatory = $false)]
    [string]$CaseName,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipKAPE,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipThor,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipSync,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForceSync
)

#region Script Configuration
$script:ScriptRoot = $PSScriptRoot
if (-not $script:ScriptRoot) { $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

# Paths
$script:DataPath = Join-Path $script:ScriptRoot "data"
$script:OutputPath = Join-Path $script:ScriptRoot "output"
$script:KapePath = Join-Path $script:ScriptRoot "KAPE\kape.exe"
$script:ThorPath = Join-Path $script:ScriptRoot "ThorLite\win_bin\thor64-lite.exe"
$script:ThorLicPath = Join-Path $script:ScriptRoot "ThorLite\win_bin"
$script:MountScript = Join-Path $script:ScriptRoot "Mount-ForensicImage.ps1"
$script:KapeScript = Join-Path $script:ScriptRoot "KaperTon.ps1"

# Results tracking
$script:Results = @{
    ImagesProcessed = 0
    ImagesSucceeded = 0
    ImagesFailed = 0
    StartTime = $null
    EndTime = $null
    Details = @()
}

# Trap Ctrl+C and cleanup
$Script:CleanupNeeded = $false
trap {
    if ($Script:CleanupNeeded) {
        Write-Host "`n`nScript interrupted! Cleaning up..." -ForegroundColor Yellow
        
        # Import mount script if not already loaded
        $mountScriptPath = Join-Path $script:ScriptRoot "Mount-ForensicImage.ps1"
        if (Test-Path $mountScriptPath) {
            . $mountScriptPath
            Write-Host "Dismounting all images..." -ForegroundColor Yellow
            Dismount-AllImages -Force
        }
        
        Write-Host "Cleanup complete." -ForegroundColor Green
    }
    break
}
#endregion

#region Helper Functions
function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Checks if the current session is running with Administrator privileges.
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-AdminElevation {
    <#
    .SYNOPSIS
        Prompts user to elevate to Administrator and re-launches if accepted.
    #>
    Write-Host "`n=== Administrator Privileges Required ===" -ForegroundColor Yellow
    Write-Host "This script requires Administrator privileges to mount forensic images." -ForegroundColor Yellow
    Write-Host ""
    
    $response = Read-Host "Would you like to restart as Administrator? (Y/n) [Default: y]"
    if ([string]::IsNullOrWhiteSpace($response) -or $response -eq 'y' -or $response -eq 'yes') {
        Write-Host "Restarting with elevated privileges..." -ForegroundColor Cyan
        
        # Build argument list preserving original parameters
        $argList = @("-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
        if ($Parallel) { $argList += "-Parallel" }
        if ($ThrottleLimit -ne 2) { $argList += "-ThrottleLimit"; $argList += $ThrottleLimit }
        if ($CaseName) { $argList += "-CaseName"; $argList += "`"$CaseName`"" }
        if ($SkipKAPE) { $argList += "-SkipKAPE" }
        if ($SkipThor) { $argList += "-SkipThor" }
        if ($SkipSync) { $argList += "-SkipSync" }
        if ($ForceSync) { $argList += "-ForceSync" }
        if ($VerbosePreference -eq 'Continue') { $argList += "-Verbose" }
        if ($DebugPreference -eq 'Continue') { $argList += "-Debug" }
        
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs
            Write-Host "New elevated session started. This window will close." -ForegroundColor Green
            Start-Sleep -Seconds 2
            exit 0
        }
        catch {
            Write-Host "Failed to elevate: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "Administrator privileges are required. Exiting." -ForegroundColor Red
        exit 1
    }
}

function Test-ThorLicense {
    <#
    .SYNOPSIS
        Checks if a ThorLite license file exists and returns license type.
    .OUTPUTS
        PSCustomObject with HasLicense and IsFreeLicense properties.
    #>
    $licenseFiles = Get-ChildItem -Path $script:ThorLicPath -Filter "*.lic" -ErrorAction SilentlyContinue
    
    if ($licenseFiles.Count -eq 0) {
        return [PSCustomObject]@{
            HasLicense = $false
            IsFreeLicense = $false
        }
    }
    
    # Check license content to determine if it's a free license
    $licenseContent = Get-Content $licenseFiles[0].FullName -Raw -ErrorAction SilentlyContinue
    $isFreeLicense = $licenseContent -match 'TYPE.*Lite' -or $licenseContent -match 'non-commercial'
    
    return [PSCustomObject]@{
        HasLicense = $true
        IsFreeLicense = $isFreeLicense
    }
}

function Update-ThorRules {
    <#
    .SYNOPSIS
        Updates Thor YARA rules from Valhalla API.
    .DESCRIPTION
        Downloads latest YARA rules from Nextron Valhalla API (free tier).
    #>
    Write-Host "`n=== Thor YARA Rules Update ===" -ForegroundColor Cyan
    
    $thorSigPath = Join-Path $script:ScriptRoot "ThorLite\win_bin\signatures\yara"
    if (-not (Test-Path $thorSigPath)) {
        Write-Host "Creating signatures directory: $thorSigPath" -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $thorSigPath -Force | Out-Null
    }
    
    # Check if existing ruleset already present
    $existingRules = Get-ChildItem -Path $thorSigPath -Filter "valhalla*.yar" -ErrorAction SilentlyContinue
    if ($existingRules) {
        $totalSize = ($existingRules | Measure-Object -Property Length -Sum).Sum
        Write-Host "Existing Valhalla rules found: $([math]::Round($totalSize/1KB, 2)) KB" -ForegroundColor Green
        
        $updateResponse = Read-Host "Update/replace existing rules? (y/N) [Default: n]"
        if (-not ($updateResponse -eq 'y' -or $updateResponse -eq 'yes')) {
            Write-Host "Keeping existing rules." -ForegroundColor Gray
            return
        }
    }
    
    try {
        Write-Host "Downloading YARA rules from Valhalla API..." -ForegroundColor Yellow
        
        # Check for API key in environment or use demo
        $apiKey = $env:VALHALLA_API_KEY
        
        if ($apiKey) {
            Write-Verbose "Using API key from environment variable"
            $apiUrl = "https://valhalla.nextron-systems.com/api/v1/get"
            $headers = @{
                "X-API-KEY" = $apiKey
                "Accept" = "text/plain"
            }
            $yaraFile = Join-Path $thorSigPath "valhalla-rules.yar"
        }
        else {
            Write-Host "No API key found (set `$env:VALHALLA_API_KEY for full ruleset)" -ForegroundColor Yellow
            Write-Host "Using free demo ruleset..." -ForegroundColor Gray
            $apiUrl = "https://valhalla.nextron-systems.com/api/v1/get"
            # Use demo API key (64 '1' characters as shown in Valhalla docs)
            $headers = @{
                "X-API-KEY" = "1111111111111111111111111111111111111111111111111111111111111111"
                "Accept" = "text/plain"
            }
            $yaraFile = Join-Path $thorSigPath "valhalla-demo-rules.yar"
        }
        
        Write-Verbose "Downloading from: $apiUrl"
        
        # Download YARA rules with POST request
        if ($apiKey -and $apiKey -ne "1111111111111111111111111111111111111111111111111111111111111111") {
            # Real API key - use GET with header
            $rules = Invoke-RestMethod -Uri "$apiUrl" -Method Get -Headers $headers
        }
        else {
            # Demo mode - POST with demo key
            $body = @{
                apikey = "1111111111111111111111111111111111111111111111111111111111111111"
            }
            $rules = Invoke-RestMethod -Uri $apiUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        }
        
        if ($rules) {
            # Save rules to file
            $rules | Out-File -FilePath $yaraFile -Encoding UTF8 -Force
            
            $fileSize = (Get-Item $yaraFile).Length
            if ($fileSize -gt 1KB) {
                Write-Host "Successfully downloaded YARA rules: $([math]::Round($fileSize/1KB, 2)) KB" -ForegroundColor Green
                Write-Host "Rules saved to: $yaraFile" -ForegroundColor Gray
                
                if (-not $apiKey) {
                    Write-Host ""
                    Write-Host "Note: Using demo ruleset with limited coverage." -ForegroundColor Yellow
                    Write-Host "Get a free API key at: https://valhalla.nextron-systems.com/" -ForegroundColor Gray
                    Write-Host "Then set: `$env:VALHALLA_API_KEY = 'your-key-here'" -ForegroundColor Gray
                }
            }
            else {
                Write-Host "Warning: Downloaded file is too small or empty." -ForegroundColor Yellow
                Remove-Item $yaraFile -ErrorAction SilentlyContinue
            }
        }
        else {
            Write-Host "Warning: No rules received from API." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Failed to update Thor YARA rules: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "You can manually download from: https://valhalla.nextron-systems.com/" -ForegroundColor Gray
    }
}

function Invoke-ThorScan {
    <#
    .SYNOPSIS
        Runs ThorLite scan on a specified path.
    .PARAMETER ScanPath
        Path to scan (mounted drive or output folder).
    .PARAMETER OutputPath
        Directory to write Thor reports.
    .NOTES
        ThorLite license does not support -j (hostname) or --virtual-map parameters.
        These features require Forensic Lab license.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScanPath,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    if (-not (Test-Path $script:ThorPath)) {
        Write-Host "ThorLite not found at: $script:ThorPath" -ForegroundColor Red
        return $false
    }
    
    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    Write-Host "  Running ThorLite scan on: $ScanPath" -ForegroundColor Cyan
    Write-Verbose "  Thor output: $OutputPath"
    
    try {
        # Build Thor arguments
        # Note: -j (hostname) and --virtual-map require Forensic Lab license (not available in Lite)
        # --alldrives + --lab mode for scanning only specified path
        # Disable modules that scan live system
        $thorArgs = @(
            "-p", "`"$ScanPath`"",
            "-e", "`"$OutputPath`"",
            "--noautoruns",
            "--noprocs",
            "--noevents"
        )
        
        Write-Debug "Thor command: $script:ThorPath $($thorArgs -join ' ')"
        
        $thorProcess = Start-Process -FilePath $script:ThorPath -ArgumentList $thorArgs -Wait -PassThru -NoNewWindow
        
        if ($thorProcess.ExitCode -eq 0) {
            Write-Host "  ThorLite scan completed successfully." -ForegroundColor Green
            return $true
        }
        else {
            # Parse exit codes for common issues
            switch ($thorProcess.ExitCode) {
                1 { Write-Host "  Thor scan completed with warnings." -ForegroundColor Yellow }
                2 { Write-Host "  Thor scan found alerts/matches." -ForegroundColor Yellow }
                default { Write-Host "  Thor scan completed with exit code: $($thorProcess.ExitCode)" -ForegroundColor Yellow }
            }
            return $true  # Non-zero doesn't always mean failure
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        
        if ($errorMessage -match "license|expired|invalid") {
            Write-Host "  ThorLite license error: $errorMessage" -ForegroundColor Red
        }
        elseif ($errorMessage -match "access.*denied|permission") {
            Write-Host "  ThorLite access denied to scan path." -ForegroundColor Red
        }
        elseif ($errorMessage -match "not found|missing") {
            Write-Host "  Scan path not found: $ScanPath" -ForegroundColor Red
        }
        else {
            Write-Host "  ThorLite scan failed: $errorMessage" -ForegroundColor Red
        }
        
        return $false
    }
}

function New-FinalReport {
    <#
    .SYNOPSIS
        Generates a consolidated YAML report from all Thor scan results.
    .PARAMETER OutputPath
        Base output path containing case folders.
    .PARAMETER CaseName
        Name of the case to report on.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$CaseName
    )
    
    $casePath = Join-Path $OutputPath $CaseName
    $thorPath = Join-Path $casePath "thor"
    $reportPath = Join-Path $casePath "FinalReport.yaml"
    
    Write-Host "`nGenerating final report..." -ForegroundColor Cyan
    
    # Collect Thor output files
    $thorFiles = @()
    if (Test-Path $thorPath) {
        $thorFiles = Get-ChildItem -Path $thorPath -Recurse -Include "*.txt", "*.csv", "*.json", "*.html" -ErrorAction SilentlyContinue
    }
    
    # Build report structure
    $report = @"
# KAPErton Forensic Workflow Report
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# Case: $CaseName

workflow:
  start_time: $($script:Results.StartTime)
  end_time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  duration_minutes: $([math]::Round(((Get-Date) - [datetime]$script:Results.StartTime).TotalMinutes, 2))

summary:
  images_processed: $($script:Results.ImagesProcessed)
  images_succeeded: $($script:Results.ImagesSucceeded)
  images_failed: $($script:Results.ImagesFailed)

thor_scan_files:
"@

    if ($thorFiles.Count -gt 0) {
        foreach ($file in $thorFiles) {
            $relativePath = $file.FullName.Replace($casePath, "").TrimStart('\', '/')
            $report += "`n  - path: `"$relativePath`""
            $report += "`n    size_kb: $([math]::Round($file.Length / 1KB, 2))"
            $report += "`n    modified: $($file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        }
    }
    else {
        $report += "`n  # No Thor scan files found"
    }
    
    $report += @"

images_processed:
"@

    foreach ($detail in $script:Results.Details) {
        $report += "`n  - image: `"$($detail.ImageName)`""
        $report += "`n    status: $($detail.Status)"
        $report += "`n    drive_letters: `"$($detail.DriveLetters -join ', ')`""
        if ($detail.Error) {
            $report += "`n    error: `"$($detail.Error)`""
        }
        if ($detail.KAPESuccess -ne $null) {
            $report += "`n    kape_success: $($detail.KAPESuccess.ToString().ToLower())"
        }
        if ($detail.ThorSuccess -ne $null) {
            $report += "`n    thor_success: $($detail.ThorSuccess.ToString().ToLower())"
        }
    }
    
    # Write report
    try {
        $report | Out-File -FilePath $reportPath -Encoding UTF8 -Force
        Write-Host "Final report saved: $reportPath" -ForegroundColor Green
        return $reportPath
    }
    catch {
        Write-Host "Failed to save report: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Process-SingleImage {
    <#
    .SYNOPSIS
        Processes a single E01 image through the full workflow.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ImagePath,
        
        [Parameter(Mandatory = $true)]
        [string]$CaseName,
        
        [Parameter(Mandatory = $true)]
        [int]$ImageIndex
    )
    
    $imageName = Split-Path $ImagePath -Leaf
    $imageBaseName = [System.IO.Path]::GetFileNameWithoutExtension($imageName)
    
    $detail = @{
        ImageName = $imageName
        ImagePath = $ImagePath
        Status = "Processing"
        DriveLetters = @()
        Error = $null
        KAPESuccess = $null
        ThorSuccess = $null
    }
    
    Write-Host "`n[$ImageIndex] Processing: $imageName" -ForegroundColor Cyan
    Write-Host ("-" * 60) -ForegroundColor Gray
    
    $mountInfo = $null
    
    try {
        # Mount the image
        Write-Host "  Mounting image..." -ForegroundColor Yellow
        $mountInfo = Mount-E01Image -ImagePath $ImagePath
        
        if (-not $mountInfo -or $mountInfo.DriveLetters.Count -eq 0) {
            throw "Failed to mount image or no drive letters assigned."
        }
        
        $detail.DriveLetters = $mountInfo.DriveLetters
        Write-Verbose "  Mounted drives: $($mountInfo.DriveLetters -join ', ')"
        
        # Run KAPE collection if not skipped
        if (-not $SkipKAPE) {
            Write-Host "  Running KAPE collection..." -ForegroundColor Yellow
            
            $kapeParams = @{
                SourceDrives = $mountInfo.DriveLetters
                OutputPath = $script:OutputPath
                CaseName = $CaseName
            }
            
            $kapeResults = Invoke-KAPECollection @kapeParams
            
            if ($kapeResults -and $kapeResults.Failed.Count -eq 0) {
                $detail.KAPESuccess = $true
                Write-Host "  KAPE collection completed." -ForegroundColor Green
            }
            else {
                $detail.KAPESuccess = ($kapeResults.Success.Count -gt 0)
                if ($kapeResults.Failed.Count -gt 0) {
                    Write-Host "  KAPE had $($kapeResults.Failed.Count) failure(s)." -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "  Skipping KAPE collection (--SkipKAPE)." -ForegroundColor Gray
        }
        
        # Run Thor scan if not skipped and license exists
        if (-not $SkipThor -and -not $script:SkipThorDueToLicense) {
            $licenseInfo = Test-ThorLicense
            if ($licenseInfo.HasLicense) {
                Write-Host "  Running ThorLite scan..." -ForegroundColor Yellow
                
                # Scan the KAPE output folder, not the raw mounted drive
                $kapeOutputFolder = Join-Path $script:OutputPath "$CaseName\PE01"
                $thorOutputPath = Join-Path $script:OutputPath "$CaseName\thor"
                
                if (Test-Path $kapeOutputFolder) {
                    $scanResult = Invoke-ThorScan -ScanPath $kapeOutputFolder -OutputPath $thorOutputPath
                    $detail.ThorSuccess = $scanResult
                }
                else {
                    Write-Host "  Warning: KAPE output folder not found: $kapeOutputFolder" -ForegroundColor Yellow
                    $detail.ThorSuccess = $false
                }
                
            }
            else {
                Write-Host "  Skipping Thor scan (no license found)." -ForegroundColor Yellow
                $detail.ThorSuccess = $null
            }
        }
        else {
            if ($script:SkipThorDueToLicense) {
                Write-Host "  Skipping Thor scan (free license + parallel mode)." -ForegroundColor Gray
            }
            else {
                Write-Host "  Skipping Thor scan (--SkipThor)." -ForegroundColor Gray
            }
        }
        
        $detail.Status = "Completed"
        Write-Host "[$ImageIndex] Completed: $imageName" -ForegroundColor Green
    }
    catch {
        $detail.Status = "Failed"
        $detail.Error = $_.Exception.Message
        Write-Host "[$ImageIndex] Failed: $imageName" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        # Always attempt to dismount (unless it was already mounted when we started)
        if ($mountInfo) {
            if ($mountInfo.AlreadyMounted) {
                Write-Host "  Leaving image mounted (was already mounted before workflow)." -ForegroundColor Gray
            }
            else {
                Write-Host "  Dismounting image..." -ForegroundColor Yellow
                try {
                    Dismount-E01Image -MountInfo $mountInfo
                }
                catch {
                    Write-Host "  Warning: Failed to dismount cleanly: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
    }
    
    return $detail
}
#endregion

#region Main Execution
function Start-ForensicWorkflow {
    <#
    .SYNOPSIS
        Main entry point for the forensic workflow.
    #>
    
    # Display banner
    Write-Host @"

 _  __    _    ____  _____     _              
| |/ /   / \  |  _ \| ____|_ _| |_ ___  _ __  
| ' /   / _ \ | |_) |  _| | '__| __/ _ \| '_ \ 
| . \  / ___ \|  __/| |___| |  | || (_) | | | |
|_|\_\/_/   \_\_|   |_____|_|   \__\___/|_| |_|
                                               
    Integrated Forensic Workflow Toolkit
    
"@ -ForegroundColor Cyan
    
    $script:Results.StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Enable cleanup on interrupt
    $Script:CleanupNeeded = $true
    
    #region Pre-flight Checks
    Write-Host "=== Pre-flight Checks ===" -ForegroundColor Yellow
    
    # Check Administrator privileges
    Write-Host "Checking Administrator privileges... " -NoNewline
    if (-not (Test-IsAdministrator)) {
        Write-Host "NO" -ForegroundColor Red
        Request-AdminElevation
        return  # Should not reach here
    }
    Write-Host "OK" -ForegroundColor Green
    
    # Check parallel mode compatibility
    if ($Parallel) {
        Write-Host "Checking parallel mode compatibility... " -NoNewline
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            Write-Host "WARNING" -ForegroundColor Yellow
            Write-Warning "Parallel processing requires PowerShell 7+. You are running PowerShell $($PSVersionTable.PSVersion). Falling back to sequential processing."
            $script:UseParallel = $false
        }
        else {
            Write-Host "OK (PS $($PSVersionTable.PSVersion.Major))" -ForegroundColor Green
            $script:UseParallel = $true
        }
    }
    else {
        $script:UseParallel = $false
    }
    
    # Import Mount-ForensicImage functions
    Write-Host "Loading Mount-ForensicImage module... " -NoNewline
    if (Test-Path $script:MountScript) {
        try {
            . $script:MountScript
            Write-Host "OK" -ForegroundColor Green
        }
        catch {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "Mount-ForensicImage.ps1 not found at: $script:MountScript" -ForegroundColor Red
        exit 1
    }
    
    # Import KaperTon functions
    Write-Host "Loading KaperTon module... " -NoNewline
    if (Test-Path $script:KapeScript) {
        try {
            . $script:KapeScript
            Write-Host "OK" -ForegroundColor Green
        }
        catch {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "KaperTon.ps1 not found at: $script:KapeScript" -ForegroundColor Red
        exit 1
    }
    
    # Check AIM CLI installation
    Write-Host "Checking AIM CLI installation... " -NoNewline
    if (-not (Test-AIMInstallation)) {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "Arsenal Image Mounter CLI is required for mounting forensic images." -ForegroundColor Red
        exit 1
    }
    else {
        Write-Host "OK" -ForegroundColor Green
    }
    
    # Check/Install KAPE
    Write-Host "Checking KAPE installation... " -NoNewline
    if (-not (Test-Path $script:KapePath)) {
        Write-Host "NOT FOUND" -ForegroundColor Yellow
        Write-Host "Installing KAPE..." -ForegroundColor Cyan
        $installed = Install-KAPE
        if (-not $installed) {
            Write-Host "Failed to install KAPE. Exiting." -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "OK" -ForegroundColor Green
    }
    
    # KAPE sync prompt
    if (-not $SkipSync) {
        if ($ForceSync) {
            Write-Host "Syncing KAPE (--ForceSync)..." -ForegroundColor Cyan
            Sync-KAPE
            Update-ThorRules
        }
        else {
            $syncResponse = Read-Host "`nSync KAPE targets/modules and Thor YARA rules? (y/N) [Default: n]"
            if ($syncResponse -eq 'y' -or $syncResponse -eq 'yes') {
                Sync-KAPE
                Update-ThorRules
            }
        }
    }
    
    # Check ThorLite
    Write-Host "Checking ThorLite installation... " -NoNewline
    if (-not (Test-Path $script:ThorPath)) {
        Write-Host "NOT FOUND" -ForegroundColor Yellow
        Write-Warning "ThorLite not found. Thor scanning will be skipped."
        $script:SkipThorDueToLicense = $true
    }
    else {
        Write-Host "OK" -ForegroundColor Green
        
        # Check license
        Write-Host "Checking ThorLite license... " -NoNewline
        $licenseInfo = Test-ThorLicense
        if (-not $licenseInfo.HasLicense) {
            Write-Host "NOT FOUND" -ForegroundColor Yellow
            Write-Warning "No ThorLite license file found in $script:ThorLicPath. Thor scanning will be skipped."
            $script:SkipThorDueToLicense = $true
        }
        else {
            Write-Host "OK" -ForegroundColor Green
            
            # Check if using free license with parallel mode
            if ($licenseInfo.IsFreeLicense -and $script:UseParallel) {
                Write-Host ""
                Write-Warning "Free/Lite Thor licenses only support single-process scanning."
                Write-Host "Parallel mode may cause Thor to fail when multiple processes attempt to scan simultaneously." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Options:" -ForegroundColor Cyan
                Write-Host "  1. Remove -Parallel flag to run sequentially" -ForegroundColor White
                Write-Host "  2. Thor scans will be skipped in parallel mode with free license" -ForegroundColor White
                Write-Host "  3. Obtain a commercial THOR license: https://www.nextron-systems.com/thor/" -ForegroundColor White
                Write-Host ""
                
                $script:SkipThorDueToLicense = $true
                $SkipThor = $true
            }
            else {
                $script:SkipThorDueToLicense = $false
            }
        }
    }
    
    # Check data directory
    Write-Host "Checking data directory... " -NoNewline
    if (-not (Test-Path $script:DataPath)) {
        Write-Host "CREATING" -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $script:DataPath -Force | Out-Null
    }
    else {
        Write-Host "OK" -ForegroundColor Green
    }
    
    # Find E01 images
    $e01Images = Get-ChildItem -Path $script:DataPath -Filter "*.E01" -ErrorAction SilentlyContinue
    Write-Host "E01 images found: " -NoNewline
    if ($e01Images.Count -eq 0) {
        Write-Host "0" -ForegroundColor Yellow
        Write-Host "`nNo E01 images found in: $script:DataPath" -ForegroundColor Yellow
        Write-Host "Please place E01 forensic images in the data/ directory and re-run." -ForegroundColor Yellow
        exit 0
    }
    else {
        Write-Host "$($e01Images.Count)" -ForegroundColor Green
        foreach ($img in $e01Images) {
            Write-Host "  - $($img.Name)" -ForegroundColor Gray
        }
    }
    
    # Create output directory
    if (-not (Test-Path $script:OutputPath)) {
        New-Item -ItemType Directory -Path $script:OutputPath -Force | Out-Null
    }
    #endregion
    
    #region Case Setup
    # Generate case name if not provided (format: filename_yyyyMMdd)
    if (-not $CaseName) {
        $dateStamp = Get-Date -Format 'yyyyMMdd'
        if ($e01Images.Count -eq 1) {
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($e01Images[0].Name)
            $CaseName = "${baseName}_${dateStamp}"
        }
        else {
            $CaseName = "Case_${dateStamp}"
        }
    }
    
    Write-Host "`n=== Workflow Configuration ===" -ForegroundColor Yellow
    Write-Host "Case Name: $CaseName"
    Write-Host "Images to process: $($e01Images.Count)"
    Write-Host "Output path: $script:OutputPath\$CaseName"
    Write-Host "Processing mode: $(if ($script:UseParallel) { 'Parallel (throttle: $ThrottleLimit)' } else { 'Sequential' })"
    Write-Host "Skip KAPE: $SkipKAPE"
    Write-Host "Skip Thor: $SkipThor"
    
    # Confirmation
    $confirmResponse = Read-Host "`nProceed with workflow? (Y/n) [Default: y]"
    if (-not ([string]::IsNullOrWhiteSpace($confirmResponse) -or $confirmResponse -eq 'y' -or $confirmResponse -eq 'yes')) {
        Write-Host "Workflow cancelled by user." -ForegroundColor Yellow
        exit 0
    }
    #endregion
    
    #region Process Images
    Write-Host "`n=== Processing Images ===" -ForegroundColor Yellow
    
    $script:Results.ImagesProcessed = $e01Images.Count
    $imageIndex = 1
    
    if ($script:UseParallel) {
        # PowerShell 7+ parallel processing
        Write-Host "Starting parallel processing with throttle limit: $ThrottleLimit" -ForegroundColor Cyan
        
        # Create indexed array for parallel processing
        $imageList = @()
        for ($i = 0; $i -lt $e01Images.Count; $i++) {
            $imageList += @{
                Path = $e01Images[$i].FullName
                Index = $i + 1
            }
        }
        
        $parallelResults = $imageList | ForEach-Object -Parallel {
            # Pass all necessary script variables to parallel runspace
            $mountScript = $using:script:MountScript
            $kapeScript = $using:script:KapeScript
            $outputPath = $using:script:OutputPath
            $thorPath = $using:script:ThorPath
            $thorLicPath = $using:script:ThorLicPath
            $skipKAPE = $using:SkipKAPE
            $skipThor = $using:SkipThor
            $skipThorDueToLicense = $using:script:SkipThorDueToLicense
            
            # Re-import modules in parallel runspace
            . $mountScript
            . $kapeScript
            
            # Re-define Process-SingleImage function in parallel runspace
            function Process-SingleImage {
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$ImagePath,
                    
                    [Parameter(Mandatory = $true)]
                    [string]$CaseName,
                    
                    [Parameter(Mandatory = $true)]
                    [int]$ImageIndex
                )
                
                $imageName = Split-Path $ImagePath -Leaf
                $imageBaseName = [System.IO.Path]::GetFileNameWithoutExtension($imageName)
                
                $detail = @{
                    ImageName = $imageName
                    ImagePath = $ImagePath
                    Status = "Processing"
                    DriveLetters = @()
                    Error = $null
                    KAPESuccess = $null
                    ThorSuccess = $null
                }
                
                Write-Host "`n[$ImageIndex] Processing: $imageName" -ForegroundColor Cyan
                Write-Host ("-" * 60) -ForegroundColor Gray
                
                $mountInfo = $null
                
                try {
                    # Mount the image
                    Write-Host "  Mounting image..." -ForegroundColor Yellow
                    $mountInfo = Mount-E01Image -ImagePath $ImagePath
                    
                    if (-not $mountInfo -or $mountInfo.DriveLetters.Count -eq 0) {
                        throw "Failed to mount image or no drive letters assigned."
                    }
                    
                    $detail.DriveLetters = $mountInfo.DriveLetters
                    Write-Verbose "  Mounted drives: $($mountInfo.DriveLetters -join ', ')"
                    
                    # Run KAPE collection if not skipped
                    if (-not $skipKAPE) {
                        Write-Host "  Running KAPE collection..." -ForegroundColor Yellow
                        
                        $kapeParams = @{
                            SourceDrives = $mountInfo.DriveLetters
                            OutputPath = $outputPath
                            CaseName = $CaseName
                        }
                        
                        $kapeResults = Invoke-KAPECollection @kapeParams
                        
                        if ($kapeResults -and $kapeResults.Failed.Count -eq 0) {
                            $detail.KAPESuccess = $true
                            Write-Host "  KAPE collection completed." -ForegroundColor Green
                        }
                        else {
                            $detail.KAPESuccess = ($kapeResults.Success.Count -gt 0)
                            if ($kapeResults.Failed.Count -gt 0) {
                                Write-Host "  KAPE had $($kapeResults.Failed.Count) failure(s)." -ForegroundColor Yellow
                            }
                        }
                    }
                    else {
                        Write-Host "  Skipping KAPE collection (--SkipKAPE)." -ForegroundColor Gray
                    }
                    
                    # Run Thor scan if not skipped and license exists
                    if (-not $skipThor -and -not $skipThorDueToLicense) {
                        $licenseFiles = Get-ChildItem -Path $thorLicPath -Filter "*.lic" -ErrorAction SilentlyContinue
                        if ($licenseFiles.Count -gt 0) {
                            Write-Host "  Running ThorLite scan..." -ForegroundColor Yellow
                            
                            # Scan the KAPE output folder, not the raw mounted drive
                            $kapeOutputFolder = Join-Path $outputPath "$CaseName\PE01"
                            $thorOutputPath = Join-Path $outputPath "$CaseName\thor"
                            
                            if (Test-Path $kapeOutputFolder) {
                                # Create output directory
                                if (-not (Test-Path $thorOutputPath)) {
                                    New-Item -ItemType Directory -Path $thorOutputPath -Force | Out-Null
                                }
                                
                                # Run Thor scan on KAPE output
                                # --lab mode + disable live system modules
                                $thorArgs = @(
                               #     "--lab",
                                    "-p", "`"$kapeOutputFolder`"",
                                    "-e", "`"$thorOutputPath`"",
                                    "--noautoruns",
                                    "--noprocs",
                                    "--noevents"
                                )
                                
                                $thorProcess = Start-Process -FilePath $thorPath -ArgumentList $thorArgs -Wait -PassThru -NoNewWindow
                                
                                if ($thorProcess.ExitCode -eq 0) {
                                    Write-Host "  ThorLite scan completed successfully." -ForegroundColor Green
                                    $detail.ThorSuccess = $true
                                }
                                elseif ($thorProcess.ExitCode -le 2) {
                                    switch ($thorProcess.ExitCode) {
                                        1 { Write-Host "  Thor scan completed with warnings." -ForegroundColor Yellow }
                                        2 { Write-Host "  Thor scan found alerts/matches." -ForegroundColor Yellow }
                                    }
                                    $detail.ThorSuccess = $true
                                }
                                else {
                                    Write-Host "  Thor scan failed with exit code: $($thorProcess.ExitCode)" -ForegroundColor Red
                                    $detail.ThorSuccess = $false
                                }
                            }
                            else {
                                Write-Host "  Warning: KAPE output folder not found: $kapeOutputFolder" -ForegroundColor Yellow
                                $detail.ThorSuccess = $false
                            }
                        }
                        else {
                            Write-Host "  Skipping Thor scan (no license found)." -ForegroundColor Yellow
                            $detail.ThorSuccess = $null
                        }
                    }
                    else {
                        Write-Host "  Skipping Thor scan (--SkipThor)." -ForegroundColor Gray
                    }
                    
                    $detail.Status = "Completed"
                    Write-Host "[$ImageIndex] Completed: $imageName" -ForegroundColor Green
                }
                catch {
                    $detail.Status = "Failed"
                    $detail.Error = $_.Exception.Message
                    Write-Host "[$ImageIndex] Failed: $imageName" -ForegroundColor Red
                    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
                }
                finally {
                    # Always attempt to dismount (unless it was already mounted when we started)
                    if ($mountInfo) {
                        if ($mountInfo.AlreadyMounted) {
                            Write-Host "  Leaving image mounted (was already mounted before workflow)." -ForegroundColor Gray
                        }
                        else {
                            Write-Host "  Dismounting image..." -ForegroundColor Yellow
                            try {
                                Dismount-E01Image -MountInfo $mountInfo
                            }
                            catch {
                                Write-Host "  Warning: Failed to dismount cleanly: $($_.Exception.Message)" -ForegroundColor Yellow
                            }
                        }
                    }
                }
                
                return $detail
            }
            
            # Now call the function
            $result = Process-SingleImage -ImagePath $_.Path -CaseName $using:CaseName -ImageIndex $_.Index
            return $result
        } -ThrottleLimit $ThrottleLimit
        
        $script:Results.Details = $parallelResults
    }
    else {
        # Sequential processing
        foreach ($image in $e01Images) {
            $detail = Process-SingleImage -ImagePath $image.FullName -CaseName $CaseName -ImageIndex $imageIndex
            $script:Results.Details += $detail
            $imageIndex++
        }
    }
    
    # Calculate success/failure counts
    $script:Results.ImagesSucceeded = ($script:Results.Details | Where-Object { $_.Status -eq 'Completed' }).Count
    $script:Results.ImagesFailed = ($script:Results.Details | Where-Object { $_.Status -eq 'Failed' }).Count
    #endregion
    
    #region Final Report
    Write-Host "`n=== Workflow Summary ===" -ForegroundColor Yellow
    Write-Host "Total images: $($script:Results.ImagesProcessed)"
    Write-Host "Succeeded: $($script:Results.ImagesSucceeded)" -ForegroundColor Green
    if ($script:Results.ImagesFailed -gt 0) {
        Write-Host "Failed: $($script:Results.ImagesFailed)" -ForegroundColor Red
        Write-Host "`nFailed images:" -ForegroundColor Red
        foreach ($failed in ($script:Results.Details | Where-Object { $_.Status -eq 'Failed' })) {
            Write-Host "  - $($failed.ImageName): $($failed.Error)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Failed: 0" -ForegroundColor Green
    }
    
    # Generate consolidated report
    $reportPath = New-FinalReport -OutputPath $script:OutputPath -CaseName $CaseName
    
    $script:Results.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $duration = ((Get-Date) - [datetime]$script:Results.StartTime).TotalMinutes
    Write-Host "`nTotal duration: $([math]::Round($duration, 2)) minutes" -ForegroundColor Cyan
    
    # Cleanup - ensure all images are dismounted
    Write-Host "`nEnsuring all images are dismounted..." -ForegroundColor Yellow
    Dismount-AllImages -Force
    
    Write-Host "`n=== Workflow Complete ===" -ForegroundColor Green
    #endregion
}

# Execute main workflow
Start-ForensicWorkflow
#endregion
