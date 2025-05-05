## Define variables for paths and configurations
$kapePath = '.\kape.exe'    # Update this to the actual location of kape.exe
$TSourceList = @('C:')      # List of source drives
$TDestinationDrive = 'J:'   # Destination drive letter

$T = '!BasicCollection,!Triage-Singularity'
$M = '!EZParser'
$CustoM = '!!CustoM'

# Assign the module flush option based on $mflushEnabled
$mflushEnabled = $false       # Set to $true to include --mflush, $false to exclude it
if ($mflushEnabled) {$mf = "--mflush"} else {$mf = ""}

<#
## Run Virtual Disk Powershell Script & Import the Virtual Disk Handler script if it exists
$virtualDiskHandlerPath = ".\VirtualDiskHandler.ps1"; if (Test-Path $virtualDiskHandlerPath) {$VHDMountPath = "$TDestinationDrive"; . $virtualDiskHandlerPath} else {
    Write-Host "Virtual Disk Handler script not found. Skipping VHD creation." -ForegroundColor Yellow}
#>

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

## For Dev Testing, delete the console logs that are created in the folders
$logFiles = Get-ChildItem -Path $TDestinationDrive -Recurse -Include *ConsoleLog*, *CopyLog.csv, *SkipLog.csv*
foreach ($logFile in $logFiles) {
    Remove-Item $logFile.FullName -Force
}
