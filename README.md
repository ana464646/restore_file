# Windows Defender Quarantine File Restore Tool

This tool allows you to restore files that have been quarantined by Windows Defender. It supports both traditional and new Windows 11 quarantine file formats.

## Features

- Restores files quarantined by Windows Defender
- Supports both legacy and Windows 11 quarantine formats
- Automatically searches for quarantine files in multiple locations
- Registry-based quarantine location detection
- Handles both RC4 encrypted and XPRESS compressed files
- Includes security privilege elevation for accessing protected files
- Provides detailed error messages and debugging information

## Requirements

- Windows 10/11
- Python 3.6 or later
- Administrator privileges
- Required Python packages (install via pip):
  ```
  pip install -r requirements.txt
  ```

## Installation

1. Clone this repository or download the source code
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the script with administrator privileges:

```
python restore_file.py C:\
```

Optional arguments:
- `-d, --dump`: Export all quarantined files to a TAR archive (quarantine.tar)

## How it Works

1. Checks for administrator privileges
2. Searches for quarantined files in multiple locations:
   - Default Windows Defender paths
   - Registry-specified locations
   - Historical scan locations
3. Identifies quarantine files by their signatures
4. Decrypts/decompresses the quarantined content
5. Restores the file with original data
6. Saves the restored file in a `restored_files` directory

## Error Handling

The tool provides detailed error messages for common issues:
- Missing administrator privileges
- File access permission errors
- Invalid quarantine file formats
- Missing or corrupted files

## Security Notes

- Always run virus scans on restored files before use
- Be cautious when restoring unknown files
- The tool requires administrator privileges to access protected system locations

## Troubleshooting

If no quarantine files are found:
1. Check Windows Security > Virus & threat protection > Protection history
2. Verify that Windows Defender service is running
3. Ensure sufficient time has passed since quarantine
4. Run the tool with administrator privileges

## Credits

Based on the work by Nikola Knežević (2021)
Reference: https://github.com/ernw/quarantine-formats

## License

This project is licensed under the MIT License - see the LICENSE file for details.
