## Define variables for paths and configurations
$kapePath = '.\kape.exe'    # Update this to the actual location of kape.exe
$TSourceList = @('C:') # List of source drives
#$T = '!BasicCollection'
$T = '!Triage-Singularity'
#$M = '!EZParser'
$M = '!EZParser'
$CustoM = '!!CustoM'

$mflushEnabled = $false       # Set to $true to include --mflush, $false to exclude it

# Assign the module flush option based on $mflushEnabled
if ($mflushEnabled) {
    $mf = "--mflush"
} else {
    $mf = ""
}

## Loop through each source drive
$i = 1 #PE01 to PE99 Counter as per TSourceList counting
foreach ($TSource in $TSourceList) {
    $label = "PE{0:D2}" -f $i
    $TDest = "E:\$label"       # Destination path
    $MSource = $TDest          # Module source path
    $MDest = "$TDest\module"   # Module destination path

    # Create a list of commands to be executed
    $commands = @(
        "$kapePath --tsource `"$TSource`" --tdest `"$TDest`" --target `"$T`"",                # Get all targets
        "$kapePath --msource `"$MSource`" --mdest `"$MDest`" $mf --module `"$M`"",            # Get all modules
        "$kapePath --msource `"$MSource`" --mdest `"$MDest`" $mf --module `"$CustoM`""        # Get Metadata of modules
    )

    # Execute each command in the list
    foreach ($command in $commands) {
        powershell -ExecutionPolicy Bypass -Command $command
    }

    $i++
}
