# KAPErton# KAPErton

KAPErton is a PowerShell-based automation script designed to streamline the use of [KAPE (Kroll Artifact Parser and Extractor)](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape). It simplifies the process of collecting forensic artifacts and running modules across multiple target sources.

## Features

- Automates the execution of KAPE commands for multiple source drives.
- Supports dynamic destination paths labeled as `PE01`, `PE02`, etc., for each source.
- Allows toggling of the `--mflush` option via a configurable variable.
- Handles both target collection and module execution, including custom modules.

## Configuration

Before running the script, update the following variables in `KaperTon.ps1`:

- `$kapePath`: Path to the `kape.exe` executable.
- `$TSourceList`: List of source drives to process (e.g., `@('C:', 'D:')`).
- `$T`: Target collection profile (e.g., `!Triage - Singularity`).
- `$M`: Modules to execute (e.g., `!!ToolSync,!EZParser`).
- `$CustoM`: Custom modules to execute.
- `$mflushEnabled`: Set to `$true` to include the `--mflush` option, or `$false` to exclude it.

## Usage

1. Ensure KAPE is installed and accessible at the path specified in `$kapePath`.
2. Open `KaperTon.ps1` in a text editor and configure the variables as needed.
3. Run the script in PowerShell with the following command:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\KaperTon.ps1
   ```
4. The script will process each source drive in `$TSourceList` and output results to dynamically labeled directories (e.g., `E:\PE01`, `E:\PE02`).

## Example

For a configuration with:
- `$TSourceList = @('C:', 'D:')`
- `$T = '!Triage - Singularity'`
- `$mflushEnabled = $true`

The script will:
1. Collect targets from `C:` and `D:` into `E:\PE01` and `E:\PE02`.
2. Execute modules and custom modules with the `--mflush` option enabled.

## Notes

- Ensure you have the necessary permissions to access the source drives and write to the destination paths.
- Review the KAPE documentation for details on available targets and modules.
- Read the `Errors` because this script and repo only has files. You may need the default kape downloads to run the script with addit to these.

