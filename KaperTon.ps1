## Define variables for paths and configurations
$kapePath = '.\kape.exe'    # Update this to the actual location of kape.exe
$TSourceList = @('C:')      # List of source drives
$TDestinationDrive = 'J:'   # Destination drive letter
$VHDMountPath = "$TDestinationDrive" # Path to mount the VHD which should be the same as TDestinationDrive

$T = '!BasicCollection,!Triage-Singularity'
$M = '!EZParser'
$CustoM = '!!CustoM'

$mflushEnabled = $false       # Set to $true to include --mflush, $false to exclude it

# Assign the module flush option based on $mflushEnabled
if ($mflushEnabled) {$mf = "--mflush"} else {$mf = ""}

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
        $CaseNum = Read-Host "Please enter the Case Number [e.g 2025-001]" # Prompt for case number

        # Import the Hyper-V module
        Import-Module Hyper-V -ErrorAction Stop

        # Define the path for the Virtual Disk
        $VHDPath = "C:\Users\$env:USERNAME\Desktop\Evidence\$CaseNum.vhdx"

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

## Loop through each source drive
$i = 1 # PE01 to PE99 Counter as per TSourceList counting
foreach ($TSource in $TSourceList) {
    $label = "PE{0:D2}" -f $i
    $TDest = "$TDestinationDrive\$label"  # Destination path
    $MSource = $TDest                     # Module source path
    $MDest = "$TDest\module"              # Module destination path

    # Create a list of commands to be executed
    $commands = @(
        "$kapePath --tsource `"$TSource`" --tdest `"$TDest`" --target `"$T`"",                # Get all targets
        "$kapePath --msource `"$MSource`" --mdest `"$MDest`" $mf --module `"$M`"",            # Get all modules
        "$kapePath --msource `"$MSource`" --mdest `"$MDest`" $mf --module `"$CustoM`""        # Get Metadata of modules
    )

    # Display the commands to the user
    Write-Host "The following commands will be executed:" -ForegroundColor Yellow
    foreach ($command in $commands) {
        Write-Host $command -ForegroundColor Green
    }

    # Default to "yes" if no input is provided
    $response = Read-Host "Would you like to make changes? (Y/n) [Default: y]" 
    if ([string]::IsNullOrWhiteSpace($response) -or $response -eq "yes" -or $response -eq "y") {
        Write-Host "Please edit the script variables and re-run the script." -ForegroundColor Red
        break
    } elseif ($response -eq "no" -or $response -eq "n") {
        # Execute each command in the list
        foreach ($command in $commands) {
            Write-Host "Executing: $command" -ForegroundColor Green
            powershell -ExecutionPolicy Bypass -Command $command
        }
    } else {
        Write-Host "Invalid input. Exiting script." -ForegroundColor Red
        break
    }

    $i++
}
