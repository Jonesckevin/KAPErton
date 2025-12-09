
<#
.SYNOPSIS
    KAPE Collection Script - Downloads and runs KAPE forensic collection tool.
.DESCRIPTION
    This script downloads KAPE to the KAPE\ subdirectory and provides functions
    for running target collection and module processing on forensic images.
.NOTES
    Part of KAPErton forensic workflow toolkit.
#>

#Requires -Version 5.1

# Script root path for relative references
$script:ScriptRoot = $PSScriptRoot
if (-not $script:ScriptRoot) { $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

# KAPE directory and executable paths
$script:KapeDir = Join-Path $script:ScriptRoot "KAPE"
$script:KapePath = Join-Path $script:KapeDir "kape.exe"
$script:KapeZipPath = Join-Path $script:ScriptRoot "kape.zip"

function Install-KAPE {
    <#
    .SYNOPSIS
        Downloads and extracts KAPE to the KAPE\ subdirectory.
    #>
    [CmdletBinding()]
    param()
    
    if (Test-Path -Path $script:KapePath) {
        Write-Verbose "KAPE already exists at $script:KapePath. Skipping download."
        Write-Host "KAPE already exists. Skipping download." -ForegroundColor Green
        return $true
    }
    
    # Download KAPE if zip doesn't exist
    if (-not (Test-Path -Path $script:KapeZipPath)) {
        Write-Host "Downloading KAPE..." -ForegroundColor Cyan
        $kapeUrl = 'https://s3.amazonaws.com/cyb-us-prd-kape/kape.zip'
        try {
            Invoke-WebRequest -Uri $kapeUrl -OutFile $script:KapeZipPath -UseBasicParsing
            Write-Verbose "Downloaded KAPE to $script:KapeZipPath"
        }
        catch {
            Write-Host "Failed to download KAPE: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
    else {
        Write-Host "kape.zip already exists. Skipping download." -ForegroundColor Yellow
    }
    
    # Create KAPE directory if it doesn't exist
    if (-not (Test-Path -Path $script:KapeDir)) {
        New-Item -ItemType Directory -Path $script:KapeDir -Force | Out-Null
    }
    
    # Extract to a temp folder first
    $tempExtractPath = Join-Path $script:ScriptRoot "kape_temp"
    Write-Host "Extracting KAPE to $script:KapeDir..." -ForegroundColor Cyan
    
    try {
        Expand-Archive -Path $script:KapeZipPath -DestinationPath $tempExtractPath -Force
        
        # Move contents from first folder inside temp to KAPE directory
        $firstFolder = Get-ChildItem -Path $tempExtractPath | Where-Object { $_.PSIsContainer } | Select-Object -First 1
        if ($firstFolder) {
            Get-ChildItem -Path $firstFolder.FullName -Recurse -Force | ForEach-Object {
                $relativePath = $_.FullName.Substring($firstFolder.FullName.Length).TrimStart('\', '/')
                $destPath = Join-Path -Path $script:KapeDir -ChildPath $relativePath
                
                if ($_.PSIsContainer) {
                    if (-not (Test-Path $destPath)) {
                        New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                    }
                }
                else {
                    $destDir = Split-Path $destPath -Parent
                    if (-not (Test-Path $destDir)) {
                        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                    }
                    Move-Item -Path $_.FullName -Destination $destPath -Force
                }
            }
            Remove-Item -Path $tempExtractPath -Recurse -Force
            Write-Host "KAPE extracted successfully." -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "Unexpected archive structure. Extraction failed." -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Failed to extract KAPE: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Sync-KAPE {
    <#
    .SYNOPSIS
        Synchronizes KAPE targets and modules with the latest versions.
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-Path -Path $script:KapePath)) {
        Write-Host "KAPE not found. Please run Install-KAPE first." -ForegroundColor Red
        return $false
    }
    
    Write-Host "Syncing KAPE targets and modules..." -ForegroundColor Cyan
    try {
        $process = Start-Process -FilePath $script:KapePath -ArgumentList "--sync" -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -eq 0) {
            Write-Host "KAPE sync completed successfully." -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "KAPE sync completed with exit code: $($process.ExitCode)" -ForegroundColor Yellow
            return $true
        }
    }
    catch {
        Write-Host "Failed to sync KAPE: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Invoke-KAPECollection {
    <#
    .SYNOPSIS
        Runs KAPE target collection and module processing on specified source drives.
    .PARAMETER SourceDrives
        Array of source drive letters to collect from (e.g., @('C:', 'D:'))
    .PARAMETER OutputPath
        Base output directory for collected artifacts
    .PARAMETER CaseName
        Name of the case (used for folder organization)
    .PARAMETER Targets
        KAPE target specifications (default: '!BasicCollection,!Triage-Singularity')
    .PARAMETER Modules
        KAPE module specifications (default: '!EZParser')
    .PARAMETER CustomModules
        Custom module specifications (default: 'CustoM')
    .PARAMETER EnableMFlush
        Enable module flush option
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SourceDrives,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [string]$CaseName = "Case_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
        
        [Parameter(Mandatory = $false)]
        [string]$Targets = '!BasicCollection,!Triage-Singularity',
        
        [Parameter(Mandatory = $false)]
        [string]$Modules = '!EZParser',
        
        [Parameter(Mandatory = $false)]
        [string]$CustomModules = '!!CustoM',
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableMFlush
    )
    
    # Verify KAPE exists
    if (-not (Test-Path -Path $script:KapePath)) {
        Write-Host "KAPE not found at $script:KapePath. Please run Install-KAPE first." -ForegroundColor Red
        return $false
    }
    
    # Build mflush argument
    $mflushArg = if ($EnableMFlush) { "--mflush" } else { "" }
    
    # Create case output directory
    $caseOutputPath = Join-Path $OutputPath $CaseName
    if (-not (Test-Path $caseOutputPath)) {
        New-Item -ItemType Directory -Path $caseOutputPath -Force | Out-Null
    }
    
    $results = @{
        Success = @()
        Failed = @()
    }
    
    # Process each source drive
    $i = 1
    foreach ($source in $SourceDrives) {
        $label = "PE{0:D2}" -f $i
        $targetDest = Join-Path $caseOutputPath $label
        $moduleDest = Join-Path $targetDest "module"
        
        Write-Host "`n[$label] Processing source: $source" -ForegroundColor Cyan
        Write-Verbose "Target destination: $targetDest"
        Write-Verbose "Module destination: $moduleDest"
        
        try {
            # Target collection
            Write-Host "  Running target collection..." -ForegroundColor Yellow
            $targetArgs = @(
                "--tsource", "`"$source`"",
                "--tdest", "`"$targetDest`"",
                "--target", "`"$Targets`""
            )
            Write-Debug "KAPE Target Command: $script:KapePath $($targetArgs -join ' ')"
            
            $targetProcess = Start-Process -FilePath $script:KapePath -ArgumentList $targetArgs -Wait -PassThru -NoNewWindow
            if ($targetProcess.ExitCode -ne 0) {
                Write-Host "  Target collection completed with warnings (exit code: $($targetProcess.ExitCode))" -ForegroundColor Yellow
            }
            else {
                Write-Host "  Target collection completed." -ForegroundColor Green
            }
            
            # Module processing
            Write-Host "  Running module processing..." -ForegroundColor Yellow
            $moduleArgs = @(
                "--msource", "`"$targetDest`"",
                "--mdest", "`"$moduleDest`""
            )
            if ($mflushArg) { $moduleArgs += $mflushArg }
            $moduleArgs += @("--module", "`"$Modules`"")
            Write-Debug "KAPE Module Command: $script:KapePath $($moduleArgs -join ' ')"
            
            $moduleProcess = Start-Process -FilePath $script:KapePath -ArgumentList $moduleArgs -Wait -PassThru -NoNewWindow
            if ($moduleProcess.ExitCode -ne 0) {
                Write-Host "  Module processing completed with warnings (exit code: $($moduleProcess.ExitCode))" -ForegroundColor Yellow
            }
            else {
                Write-Host "  Module processing completed." -ForegroundColor Green
            }
            
            # Custom modules
            if ($CustomModules) {
                Write-Host "  Running custom modules..." -ForegroundColor Yellow
                $customArgs = @(
                    "--msource", "`"$targetDest`"",
                    "--mdest", "`"$moduleDest`""
                )
                if ($mflushArg) { $customArgs += $mflushArg }
                $customArgs += @("--module", "`"$CustomModules`"")
                Write-Debug "KAPE Custom Command: $script:KapePath $($customArgs -join ' ')"
                
                $customProcess = Start-Process -FilePath $script:KapePath -ArgumentList $customArgs -Wait -PassThru -NoNewWindow
                if ($customProcess.ExitCode -ne 0) {
                    Write-Host "  Custom modules completed with warnings (exit code: $($customProcess.ExitCode))" -ForegroundColor Yellow
                }
                else {
                    Write-Host "  Custom modules completed." -ForegroundColor Green
                }
            }
            
            $results.Success += @{
                Label = $label
                Source = $source
                OutputPath = $targetDest
            }
            Write-Host "[$label] Completed successfully." -ForegroundColor Green
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-Host "[$label] Failed: $errorMsg" -ForegroundColor Red
            $results.Failed += @{
                Label = $label
                Source = $source
                Error = $errorMsg
            }
        }
        
        $i++
    }
    
    # Summary
    Write-Host "`n=== KAPE Collection Summary ===" -ForegroundColor Cyan
    Write-Host "Successful: $($results.Success.Count)" -ForegroundColor Green
    Write-Host "Failed: $($results.Failed.Count)" -ForegroundColor $(if ($results.Failed.Count -gt 0) { "Red" } else { "Green" })
    
    return $results
}

#region Standalone Execution
# This section runs when the script is executed directly (not dot-sourced)
if ($MyInvocation.InvocationName -ne '.') {
    # Default configuration for standalone mode
    $defaultConfig = @{
        SourceDrives = @('C:')
        OutputPath = Join-Path $script:ScriptRoot "output"
        Targets = '!BasicCollection,!Triage-Singularity'
        Modules = '!EZParser'
        CustomModules = '!!CustoM'
        EnableMFlush = $false
    }
    
    # Install KAPE if needed
    $installed = Install-KAPE
    if (-not $installed) {
        Write-Host "Failed to install KAPE. Exiting." -ForegroundColor Red
        exit 1
    }
    
    # Display current configuration
    Write-Host "`n=== Current Configuration ===" -ForegroundColor Cyan
    Write-Host "KAPE Path: $script:KapePath"
    Write-Host "Source Drives: $($defaultConfig.SourceDrives -join ', ')"
    Write-Host "Output Path: $($defaultConfig.OutputPath)"
    Write-Host "Targets: $($defaultConfig.Targets)"
    Write-Host "Modules: $($defaultConfig.Modules)"
    Write-Host "Custom Modules: $($defaultConfig.CustomModules)"
    Write-Host "MFlush Enabled: $($defaultConfig.EnableMFlush)"
    
    # Prompt for confirmation
    $response = Read-Host "`nWould you like to proceed with these settings? (y/N) [Default: n]"
    if ($response -eq 'y' -or $response -eq 'yes') {
        # Ask about KAPE sync
        $syncResponse = Read-Host "Sync KAPE targets/modules before running? (y/N) [Default: n]"
        if ($syncResponse -eq 'y' -or $syncResponse -eq 'yes') {
            Sync-KAPE
        }
        
        # Run collection
        $results = Invoke-KAPECollection @defaultConfig
    }
    else {
        Write-Host "Please edit the configuration in this script or use Invoke-ForensicWorkflow.ps1 for the full pipeline." -ForegroundColor Yellow
    }
}
#endregion