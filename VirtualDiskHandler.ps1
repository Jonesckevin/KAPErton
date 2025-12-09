<#
.SYNOPSIS
    Legacy Virtual Disk Handler using Hyper-V cmdlets.
.DESCRIPTION
    This script creates and mounts VHDX virtual disks using Hyper-V cmdlets.
    
    NOTE: This script is DEPRECATED in favor of Mount-ForensicImage.ps1 which uses
    Arsenal Image Mounter (AIM) for forensic image mounting. AIM provides:
    - E01/EWF forensic image support
    - No Hyper-V dependency
    - Forensic-grade read-only or write-overlay mounting
    - Support for VHD, VMDK, raw (dd), AFF4, qcow formats
    
    For forensic workflows, please use Invoke-ForensicWorkflow.ps1 instead.
.NOTES
    Part of KAPErton forensic workflow toolkit.
    DEPRECATED - Use Mount-ForensicImage.ps1 for forensic image mounting.
#>

#Requires -Version 5.1

Write-Warning @"
DEPRECATED: VirtualDiskHandler.ps1 is deprecated.

For forensic image mounting (E01, VHD, raw, etc.), please use:
  - Mount-ForensicImage.ps1 - Direct AIM mounting functions
  - Invoke-ForensicWorkflow.ps1 - Full automated workflow

This script only creates new VHDX files using Hyper-V, which requires:
  - Hyper-V Windows feature enabled
  - Does NOT mount existing forensic images

Press Enter to continue with legacy VHDX creation, or Ctrl+C to cancel.
"@
Read-Host

# Prompt for case number
$CaseNum = Read-Host "Please enter the Case Number [e.g 2025-001]"

# Define the path for the Virtual Disk
$VHDPath = "C:\Users\$env:USERNAME\Desktop\Evidence\$CaseNum.vhdx"

# Ensure the Hyper-V module is available. If not, skip.
if (-Not (Get-Module -ListAvailable -Name Hyper-V)) {
    Write-Host "The Hyper-V module is not installed or enabled. Please enable it in Windows Features. To Automate creating and mount a Virtual Disk (VHDX)" -ForegroundColor Red
} else {
    Write-Host "The Hyper-V module is available." -ForegroundColor Green
    # Check if Hyper-V is enabled
    $hyperVEnabled = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V | Where-Object { $_.State -eq "Enabled" }
    if (-Not $hyperVEnabled) {
        Write-Host "Hyper-V is not enabled on this system. Please enable it using 'Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All'." -ForegroundColor Red
    } else {
        Write-Host "Hyper-V is enabled." -ForegroundColor Green
        # Import the Hyper-V module
        Import-Module Hyper-V -ErrorAction Stop

        # Create the VHDX file if it doesn't exist and mount it
        if (-Not (Test-Path $VHDPath)) {
            $VHDSize = 100GB                    # Size of the VHD
            $VHDFormat = "Dynamic"              # Format of the VHD (Dynamic or Fixed)
            $VHDType = "VHDX"                   # Type of the VHD (VHD or VHDX)

            New-VHD -Path $VHDPath -SizeBytes $VHDSize -Dynamic -Format $VHDFormat -VHDType $VHDType
            Mount-VHD -Path $VHDPath
        } else {
            Write-Host "VHDX file already exists. Mounting the VHD..." -ForegroundColor Yellow
            Mount-VHD -Path $VHDPath
        }
    }
}
