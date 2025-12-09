# KAPErton Forensic Workflow Toolkit

## Overview
The KAPErton Forensic Workflow Toolkit is an integrated solution designed to streamline forensic investigations. It automates the process of mounting forensic images, collecting evidence, scanning for Indicators of Compromise (IOCs), and generating consolidated reports. The toolkit leverages Arsenal Image Mounter (AIM), KAPE, and ThorLite.

## Features
- **Image Mounting**: Supports mounting of E01 forensic images using Arsenal Image Mounter.
- **Evidence Collection**: Automates evidence collection using KAPE modules and targets.
- **IOC Scanning**: Integrates ThorLite for scanning collected evidence for IOCs.
- **Report Generation**: Produces consolidated YAML reports summarizing the workflow results.
- **Parallel Processing**: Supports parallel processing of multiple images (PowerShell 7+).
- **Customizable Workflow**: Offers options to skip specific phases (e.g., KAPE collection, Thor scanning).
- **Update Management**: Includes options for syncing KAPE and ThorLite databases.
- **User-Friendly Parameters**: Provides a range of parameters for customizing the workflow.

## Prerequisites
- **Operating System**: Windows
- **PowerShell Version**: 5.1 or later (Parallel processing requires PowerShell 7+).
- **Administrator Privileges**: Required for mounting forensic images.
- **Dependencies**:
  - Arsenal Image Mounter CLI
  - KAPE
  - ThorLite

## Installation
1. Clone the repository:
   ```powershell
   git clone https://github.com/Jonesckevin/KAPErton.git
   cd KAPErton
   ```

## Usage
### Basic Workflow
Run the full workflow with default settings:
```powershell
.\Invoke-ForensicWorkflow.ps1
```

### Custom Case Name
Specify a custom case name:
```powershell
.\Invoke-ForensicWorkflow.ps1 -CaseName "Investigation_2025"
```

### Parallel Processing
Enable parallel processing (requires PowerShell 7+):
```powershell
.\Invoke-ForensicWorkflow.ps1 -Parallel -ThrottleLimit 4
```

### Skip Specific Phases
Skip KAPE collection or Thor scanning:
```powershell
.\Invoke-ForensicWorkflow.ps1 -SkipKAPE -SkipThor
```

## Parameters

| Parameter       | Description                                           |
|-----------------|-------------------------------------------------------|
| `-Parallel`     | Enable parallel processing of multiple images.        |
| `-ThrottleLimit`| Set the maximum number of parallel jobs.              |
| `-CaseName`     | Specify a custom name for the case/investigation.     |
| `-SkipKAPE`     | Skip the KAPE collection phase.                       |
| `-SkipThor`     | Skip the ThorLite scanning phase.                     |
| `-SkipSync`     | Skip the KAPE sync prompt.                            |
| `-ForceSync`    | Force KAPE sync without prompting.                    |

## Workflow Phases
1. **Pre-flight Checks**:
   - Verifies administrator privileges.
   - Checks for required dependencies (AIM, KAPE, ThorLite).
2. **Image Mounting**:
   - Mounts E01 forensic images using Arsenal Image Mounter.
3. **Evidence Collection**:
   - Runs KAPE to collect evidence from mounted images.
4. **IOC Scanning**:
   - Scans collected evidence using ThorLite.
5. **Report Generation**:
   - Consolidates results into a YAML report.

## Troubleshooting
- **Administrator Privileges**: Ensure the script is run as an administrator.
- **Dependency Issues**: Verify that AIM, KAPE, and ThorLite are installed and accessible.
- **ThorLite License**: Ensure a valid ThorLite license file is present in the `ThorLite\win_bin` directory.
- **PowerShell Version**: Use PowerShell 7+ for parallel processing.

## Acknowledgments
- [Arsenal Image Mounter](https://arsenalrecon.com/)
- [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)
- [ThorLite](https://www.nextron-systems.com/thor-lite/)
