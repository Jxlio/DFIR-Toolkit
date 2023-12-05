# Security Toolkit

A PowerShell toolbox for security reconnaissance and information gathering.

## Requirements

- PowerShell 5.1 or later
- Administrative privileges

## Installation

1. Clone the repository.
2. Navigate to the script directory.
3. Execute the script with administrative privileges.

## Usage

Example : 

```powershell
.\SecurityToolkit.ps1 -o file/to/output/folder
or
.\SecurityToolkit.ps1 -o file/to/output/folder -mg
or
.\SecurityToolkit.ps1 -help
```

## Command Line Options

to show all option : 
### `-help` or `--h`

to set output folder (needed): 
### `-o`

to use MG-Graph: 
### `-mg`

## MG-Graph Module

If you want to use the MG-Graph module, ensure it's installed. Otherwise, the script will prompt you to install it.
```powershell
Install-Module MG-Graph
```

## Contributions

This project use PersistenceSniper, a project available [here](https://github.com/last-byte/PersistenceSniper).
Feel free to contribute to the project. Fork the repository, make changes, and submit a pull request.

## License

This project is licensed under the MIT License.

## Authors

-  [@Jxlio](https://github.com/Jxlio)


