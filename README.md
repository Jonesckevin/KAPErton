# KAPErton v2.0

KAPErton is a PowerShell-based automation script designed to streamline the use of [KAPE (Kroll Artifact Parser and Extractor)](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape). It simplifies the process of collecting forensic artifacts and running modules across multiple target sources with enhanced error handling, parameter support, and user-friendly features.

## 🚀 Quick Start

```powershell
# Show help and all available options
.\KaperTon.ps1 -Help

# Run with default settings (interactive mode)
.\KaperTon.ps1

# Run silently with defaults
.\KaperTon.ps1 -Silent

# Custom configuration
.\KaperTon.ps1 -SourceDrives @('C:', 'D:') -DestinationDrive 'E:' -EnableMflush -Silent
```

## 📋 Features

### Core Functionality

- Automates KAPE execution for multiple source drives
- Dynamic destination paths labeled as `PE01`, `PE02`, etc.
- Handles target collection, module execution, and custom modules
- Automatic log cleanup after execution

### Enhanced Features (v2.0)

- **Parameter Support**: Configure everything via command line parameters
- **Validation Checks**: Automatic verification of KAPE executable and drive accessibility
- **Error Handling**: Comprehensive error checking with detailed reporting
- **Progress Tracking**: Visual feedback during long-running operations
- **Silent Mode**: Automation-friendly execution without user prompts
- **Help System**: Built-in help with examples and parameter descriptions
- **Virtual Disk Integration**: Optional VirtualDiskHandler script support

## 🔧 Configuration

### Command Line Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-KapePath` | `.\kape.exe` | Path to KAPE executable |
| `-SourceDrives` | `@('C:')` | Array of source drives |
| `-DestinationDrive` | `J:` | Destination drive letter |
| `-Targets` | `!BasicCollection,!Triage-Singularity` | Target collection string |
| `-Modules` | `!EZParser` | Module processing string |
| `-CustomModules` | `!!CustoM` | Custom module string |
| `-EnableMflush` | `$false` | Enable module flush option |
| `-CleanupLogs` | `$true` | Clean up logs after execution |
| `-Silent` | `$false` | Run without user confirmation |
| `-VirtualDisk` | `$false` | Enable virtual disk handler |

## 📖 Usage Examples

### Basic Usage

```powershell
# Interactive mode with confirmation prompts
.\KaperTon.ps1

# Silent execution with default settings
.\KaperTon.ps1 -Silent
```

```powershell
# Use parameters
.\KaperTon.ps1 -KapePath '.\kape.exe' -SourceDrives @('C:', 'D:') -Silent
```

### Advanced Usage

```powershell
# Multiple drives with custom destination
.\KaperTon.ps1 -SourceDrives @('C:', 'D:', 'E:') -DestinationDrive 'F:' -Silent

# Enable module flush and virtual disk support
.\KaperTon.ps1 -EnableMflush -VirtualDisk

# Custom targets and modules
.\KaperTon.ps1 -Targets '!SANS_Triage' -Modules '!EZParser,!SQLiteDB' -Silent
```

### Development/Testing

```powershell
# Keep logs for debugging
.\KaperTon.ps1 -CleanupLogs:$false

# Custom KAPE path
.\KaperTon.ps1 -KapePath 'C:\Tools\KAPE\kape.exe' -Silent
```

## 🛠️ Prerequisites

1. **KAPE Installation**: Ensure KAPE is installed and accessible
2. **PowerShell Execution Policy**: May need to run as Administrator
3. **Drive Access**: Ensure proper permissions for source and destination drives
4. **Virtual Disk Handler** (Optional): Place `VirtualDiskHandler.ps1` in the same directory


## 🤝 Support

For detailed usage instructions, see [USAGE.md](USAGE.md).

For issues or questions:

1. Run `.\KaperTon.ps1 -Help` for built-in help
2. Check the validation output for common issues
3. Review KAPE documentation for target/module specifics
4. Ensure all prerequisites are met

## 📝 Notes

- **Run as Administrator** for better system access to protected drives
- **Use dedicated destination drive** to avoid space issues
- **Test with single drive first** before processing multiple drives
- Review KAPE documentation for available targets and modules
- The script includes robust error handling but may require KAPE's default downloads for full functionality

## 🔄 Version History

- **v2.0**: Complete rewrite with parameter support, error handling, and enhanced UI
- **v1.0**: Basic automation script with variable-based configuration

