#############################################################################################################
##                                                                                                         ##
##  Security Toolkit for reconnaissance and/or security information gathering.                             ##
##  Author : Jules LOUAPRE                                                                                 ##
##  Version : 1.0                                                                                          ##
##                                                                                                         ##
#############################################################################################################

<#
.SYNOPSIS
Security Toolkit - A collection of security tools for reconnaissance and information gathering.

.DESCRIPTION
The Security Toolkit script provides various actions to perform security analysis (DFIR) on the system where it is executed. Administrator rights are required to run the script.

.ACTIONS
The script supports the following actions:

[1] Persistence Sniper: Actively searches for persistences on the system using the persistences.csv file and displays the results in newPersistences.csv.
[2] RDPSession: Lists the RDP connection history.
[3] PStree: Lists the current processes or kills a process.
[4] TCP Connection: Lists all active TCP connections.
[5] Users: Lists local and Azure users on the system.
[6] IPInfo: Retrieves information about different network interfaces on the system.
[7] ShadowCopies: Displays if a ShadowCopy exists.
[8] AutoRunInfo: Lists AutoRun entries.
[9] DriverInstalled: Lists installed drivers.
[10] PowershellHistory: Retrieves PowerShell command history.
[11] OfficeConnection: Enumerates Office connections.
[12] SecurityEvents: Lists security events (may take some time).
[13] DNSCache: Retrieves DNS cache information.
[14] ScheduledTasks: Lists scheduled tasks and their details.
[15] RunningServices: Lists running services.
[16] SMBShares: Lists SMB shares.
[17] NetworkShares: Lists network shares.
[18] RemotelyOpenedFiles: Lists remotely opened files.
[19] RecentlyInstalledSoftware: Lists recently installed software.
[20] Global system report (may take some time).

.PARAMETER -o
Output Path: Specify the path where the reports will be saved.

.PARAMETER -mg
Microsoft Graph: Include this switch if you want to retrieve Azure users. Requires Microsoft Graph access.

.EXAMPLE
.\SecurityToolkit.ps1 -o C:\Reports -mg
Run the Security Toolkit script with output path set to C:\Reports and include Microsoft Graph for Azure user information.

.NOTES
Author: LOUAPRE Jules
Version: 1.0
Date: 2023-12-05
#>

param(
    [switch] $help,
    [string] $outputDirectory,
    [switch] $mg
)


if ($help -eq $True) {
    write-host = @"
                
         (((((((((((((((((           
        ((((((((((((((((((((              @@@@@@ @@@@@@@@  @@@@@@@    
        (((((((((((((((((((((            !@@     @@!      !@@    
   ((((&&&&&&&&&&&&&&&&&&&&&&&((((        !@@!!  @!!!:!   !@!    
  ((((((((((((#%&&%#((((((((((((((           !:! !!:      :!!            
      ,(((((((((((((((((((((((,          ::.: :  : :: :::  :: :: :      
      ,.&&&&&&&&&...&&&&&&&&&.,                                                                           
       &.&&&&&&&&...&&&&&&&&.             @@@@@@@  @@@@@@   @@@@@@  @@@      @@@@@@@   @@@@@@  @@@  @@@        
        .........//*.........               @@!   @@!  @@@ @@!  @@@ @@!      @@!  @@@ @@!  @@@ @@!  !@@    
      (((((((&#,.....,##(((((((             @!!   @!@  !@! @!@  !@! @!!      @!@!@!@  @!@  !@!  !@@!@!  
       (((((((((%#((((((((((((              !!:   !!:  !!! !!:  !!! !!:      !!:  !!! !!:  !!!  !: :!!
        (((((((((((&(((((((((                :     : :. :   : :. :  : ::.: : :: : ::   : :. :  :::  :::
      (((((((((&(((((((((((((((       
   (((((((((((&(((((((((((((((((((    
  (((((((((((((&((((((((((((((((((( 
"@
    write-host "================================================================================"
    Write-Host ""
    Write-Host @"
    The Sec Toolbox enables a DFIR analysis of the system on which it is executed. Administrative rights are required to run the script.

    The toolbox provides approximately 25 different actions:

        [1]  Persistence Sniper:           Actively searches for persistences on the system using the persistences.csv file and displays the results in newPersistences.csv.
        [2]  RDPSession:                   Lists the RDP connection history.
        [3]  PStree:                       Lists the current processes or kills a process.
        [4]  TCP Connection:               Lists all active TCP connections.
        [5]  Users:                        Lists local and Azure users on the system.
        [6]  IPInfo:                       Retrieves information about different network interfaces on the system.
        [7]  ShadowCopies:                 Displays if a ShadowCopy exists.
        [8]  AutoRunInfo:                  Lists AutoRun entries.
        [9]  DriverInstalled:              Lists installed drivers.
        [10] PowershellHistory:            Retrieves PowerShell command history.
        [11] OfficeConnection:             Enumerates Office connections.
        [12] SecurityEvents:               Lists security events (may take some time).
        [13] DNSCache:                     Retrieves DNS cache information.
        [14] ScheduledTasks:               Lists scheduled tasks and their details.
        [15] RunningServices:              Lists running services.
        [16] SMBShares:                    Lists SMB shares.
        [17] NetworkShares:                Lists network shares.
        [18] RemotelyOpenedFiles:          Lists remotely opened files.
        [19] RecentlyInstalledSoftware:    Lists recently installed software.
        [20] Global system report (may take some time).

    Options:
      -o                : Specifies the output format (json or text).
      -mg               : Enables additional Microsoft Graph features.

    Example Usage:
      .\SecurityToolbox.ps1 -o '/path/to/output/folder' -mg 

"@
    exit
}
if (-not $outputDirectory) {
    Write-Host "Error : Parameter -o (output folder) is missing."
    exit 1
}
if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -ErrorAction Stop
}

if (-not (Get-Module -Name PersistenceSniper -ListAvailable)) {
    Write-Host "PersistenceSniper module not found. Installing..."

    Install-Script -Name PersistenceSniper -Force
    Import-Module PersistenceSniper -ErrorAction SilentlyContinue

    Write-Host "PersistenceSniper module installed and imported."
} else {
    Write-Host "PersistenceSniper module found. Skipping installation."
}

If (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
}


if ($mg -eq $True) {
    $mgGraphModule = Get-Module -Name "MG-Graph" -ListAvailable

    if ($null -eq $mgGraphModule) {
        Write-Host "MG-Graph module is not installed."
        $installMGGraph = Read-Host "Do you want to install MG-Graph module? (Y/N)"
        if ($installMGGraph -eq 'Y') {
            Install-Module -Name "MG-Graph" -Force -Scope CurrentUser
        }
        else {
            Write-Host "MG-Graph module is required for some features. Exiting script."
            exit
        }
    }
    $clientIdGraph = Read-Host "Enter Client ID for MG-Graph"
    $tenantIdGraph = Read-Host "Enter Tenant ID for MG-Graph"
    $thumbprintGraph = Read-Host "Enter Thumbprint for MG-Graph"

    Connect-MgGraph -ClientID $clientIdGraph -TenantId $tenantIdGraph -CertificateThumbprint $thumbprintGraph
    Start-Sleep 2
}
#Clear-Host

############################################################################################################################################################################################################



Write-Host "Creating an output directory..."
$ExecutionTime = $(get-date -f yyyy-MM-dd)
$folderPath = $outputDirectory + "\DFIR\$ExecutionTime"
New-Item -ItemType Directory -Path $folderPath -ErrorAction SilentlyContinue
$folderPath = $outputDirectory + "\DFIR\$ExecutionTime\$env:computername"
New-Item -ItemType Directory -Path $folderPath -ErrorAction SilentlyContinue
Write-Host "Output directory created: $folderPath..."

#Uncomment here and add the local path to you presistenceSniper module 
#$pathmodule = path/to/PersistenceSniper.psm1'
#Import-Module -Name $pathModule -Verbose -ErrorAction SilentlyContinue


Start-Sleep 2
Clear-Host
While ($True) {
    write-host = @"
                
            (((((((((((((((((           
          ((((((((((((((((((((              @@@@@@ @@@@@@@@  @@@@@@@    
          (((((((((((((((((((((            !@@     @@!      !@@    
     ((((&&&&&&&&&&&&&&&&&&&&&&&((((        !@@!!  @!!!:!   !@!    
    ((((((((((((#%&&%#((((((((((((((           !:! !!:      :!!            
        ,(((((((((((((((((((((((,          ::.: :  : :: :::  :: :: :      
        ,.&&&&&&&&&...&&&&&&&&&.,                                                                           
         &.&&&&&&&&...&&&&&&&&.             @@@@@@@  @@@@@@   @@@@@@  @@@      @@@@@@@   @@@@@@  @@@  @@@        
          .........//*.........               @@!   @@!  @@@ @@!  @@@ @@!      @@!  @@@ @@!  @@@ @@!  !@@    
        (((((((&#,.....,##(((((((             @!!   @!@  !@! @!@  !@! @!!      @!@!@!@  @!@  !@!  !@@!@!  
         (((((((((%#((((((((((((              !!:   !!:  !!! !!:  !!! !!:      !!:  !!! !!:  !!!  !: :!!
          (((((((((((&(((((((((                :     : :. :   : :. :  : ::.: : :: : ::   : :. :  :::  :::
        (((((((((&(((((((((((((((       
     (((((((((((&(((((((((((((((((((    
    (((((((((((((&(((((((((((((((((((   

"@
    Write-Host "================================================================================"
    Write-Host ""
    Write-Host "[1]  Persistence Sniper:           Actively searches for persistences on the system using the
                                    persistences.csv file and displays the results in newPersistences.csv"
    Write-Host "[2]  RDPSession:                   Lists the RDP connection history"
    Write-Host "[3]  PStree:                       Lists the current processes or kills a process"
    Write-Host "[4]  TCP Connection:               Lists all active TCP connections"
    Write-Host "[5]  Users:                        Lists local and Azure users on the system"
    Write-Host "[6]  IPInfo:                       Retrieves information about different network interfaces on the system"
    Write-Host "[7]  ShadowCopies:                 Displays if a ShadowCopy exists"
    Write-Host "[8]  AutoRunInfo:                  Lists AutoRun entries"
    Write-Host "[9]  DriverInstalled:              Lists installed drivers"
    Write-Host "[10] PowershellHistory:            Retrieves PowerShell command history"
    Write-Host "[11] OfficeConnection:             Enumerates Office connections"
    Write-Host "[12] SecurityEvents:               Lists security events (may take some time)"
    Write-Host "[13] DNSCache:                     Retrieves DNS cache information"
    Write-Host "[14] ScheduledTasks:               Lists scheduled tasks and their details"
    Write-Host "[15] RunningServices:              Lists running services"
    Write-Host "[16] SMBShares:                    Lists SMB shares"
    Write-Host "[17] NetworkShares:                Lists network shares"
    Write-Host "[18] RemotelyOpenedFiles:          Lists remotely opened files"
    Write-Host "[19] RecentlyInstalledSoftware:    Lists recently installed software"
    Write-Host "[20] Global system report (may take some time)"
    $x = Read-Host " Choice > "

    switch ($x) {
        q { 
            exit 
        }
        1 { 
            Find-AllPersistence -DiffCSV .\persistences.csv -OutputCSV .\newPersistences.csv | Out-GridView 
        }
        2 {
            clear-host
            write-host "=========== RDPSession ==========="
            write-host "1: Incoming Connection"
            write-host "2: Outgoing Connection"
            $y = read-host "Choice > "
            switch ($y) {
                1 {
                    Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -ErrorAction SilentlyContinue | Out-GridView
                }
                2 {
                    Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -ErrorAction SilentlyContinue | Out-GridView
                }
            }         
        }
        3 {
            Clear-Host
            write-host "=========== PStree ===========" 
            write-host "1: Retrieve the list of processes"
            write-host "2: Terminate a process"
            write-host "3: Process Command Line Info"
            $y = read-host "Choice >"
            switch ($y) {
                1 {
                    Get-Process | Out-GridView 
                }
                2 {
                    $process = Read-Host "PID to kill >"
                    Stop-Process -Id $process -Force
                }
                3 {
                    Get-WmiObject Win32_Process | Select-Object Name, ProcessId, CommandLine, Path | Out-GridView
                }
            }
        } 
        4 { 
            Get-NetTCPConnection | Out-GridView
        } 
        5 {
            Clear-Host
            write-host "=========== List users ==========="
            write-host "1: List local users"
        
            if ($mg) {
                write-host "2: List Azure users"
            }
        
            $y = read-host "Choice >"
            switch ($y) {
                1 {
                    Get-LocalUser | Out-GridView
                } 
                2 {
                    if ($mg) {
                        $displayName = $env:COMPUTERNAME
                        $device = Get-MgDevice -Filter "displayName eq '$displayName'"
                        $deviceId = $device.Id
                        $users = Get-MgDeviceRegisteredUser -DeviceId $deviceId 
                        foreach ($user in $users) {
                            get-mguser -UserId $user.Id | Select-Object DisplayName | Out-GridView
                        }
                    }
                    else {
                        write-host"This option is available only if you used -mg during the script execution."
                    }
                }
            }
        }
        6 {
            Get-NetIPAddress | Out-GridView
        }
        7 {
            Get-CimInstance Win32_ShadowCopy | Out-GridView -ErrorAction SilentlyContinue
        }
        8 {
            Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Out-GridView
        }
        9 {
            driverquery | Out-GridView
        }
        10 {
            Get-History | Out-GridView
        }
        11 {
            Get-ChildItem -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Internet\Server Cache\' -erroraction 'silentlycontinue' | Out-GridView
        }
        12 { 
            Clear-Host
            write-host "=========== Security Events ===========" 
            write-host "1: SecurityEventsCount "
            write-host "2: SecurityEvents"
            $y = read-host "Choice >"
            switch ($y) {
                1 {
                    $SecurirtyEvents = Get-EventLog -LogName security -After (Get-Date).AddDays(-7)
                    $SecurirtyEvents | Group-Object -Property EventID -NoElement | Sort-Object -Property Count -Descending | Out-GridView
                }
                2 {
                    get-eventlog security -After (Get-Date).AddDays(-7) | Out-GridView
                }
            }
        }
        13 {
            Get-DnsClientCache | Out-GridView
        }
        14 {
            Clear-Host
            write-host "=========== Scheduled Tasks ===========" 
            write-host "1: ScheduledTasks"
            write-host "2: ScheduledTasksInfo"
            
            $y = read-host "Choice >"
            switch ($y) {
                1 {
                    Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Out-GridView
                }
                2 {
                    Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Get-ScheduledTaskInfo | Out-GridView
                }
                
            }
        }
        15 {
            Get-Service | Where-Object { $_.Status -eq "Running" } | Out-GridView -ErrorAction SilentlyContinue
        }
        16 {
            Get-SmbShare | Out-GridView
        }
        17 {
            Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ | Out-GridView
        }
        18 {
            openfiles | Out-GridView
        }
        19 {
            Get-WinEvent -ProviderName msiinstaller | Where-Object id -eq 1033 | Select-Object timecreated, message | Out-GridView
        }
        20 {
            Clear-Host

            Write-Host "Creating directories..."
            $PersistenceFolder = $folderPath + "\Persistence"
            mkdir  $PersistenceFolder -ErrorAction SilentlyContinue -Force
            $RDPSessionFolder = $folderPath + "\RDPSession"
            mkdir  $RDPSessionFolder -ErrorAction SilentlyContinue -Force
            $PStreeFolder = $folderPath + "\PStree" 
            mkdir $PStreeFolder -ErrorAction SilentlyContinue -Force
            $NetworkFolder = $folderPath + "\Network" 
            mkdir $NetworkFolder -ErrorAction SilentlyContinue -Force
            $UsersFolder = $folderPath + "\Users" 
            mkdir $UsersFolder -ErrorAction SilentlyContinue -Force
            $ShadowFolder = $folderPath + "\ShadowCopies" 
            mkdir $ShadowFolder -ErrorAction SilentlyContinue -Force
            $AutoRunFolder = $folderPath + "\AutoRun" 
            mkdir $AutoRunFolder -ErrorAction SilentlyContinue -Force
            $DriverFolder = $folderPath + "\Driver" 
            mkdir $DriverFolder -ErrorAction SilentlyContinue -Force
            $PowershellFolder = $folderPath + "\Powershell" 
            mkdir $PowershellFolder -ErrorAction SilentlyContinue -Force
            $OfficeFolder = $folderPath + "\Office" 
            mkdir $OfficeFolder -ErrorAction SilentlyContinue -Force
            $SecurityEventsFolder = $folderPath + "\SecurityEvents" 
            mkdir $SecurityEventsFolder -ErrorAction SilentlyContinue -Force
            $DNSFolder = $folderPath + "\DNSCache" 
            mkdir $DNSFolder -ErrorAction SilentlyContinue -Force
            $tasksFolder = $folderPath + "\ScheduledTasks" 
            mkdir $tasksFolder -ErrorAction SilentlyContinue -Force
            $ServiceFolder = $folderPath + "\Service" 
            mkdir $ServiceFolder -ErrorAction SilentlyContinue -Force
            $SMBFolder = $folderPath + "\SMB" 
            mkdir $SMBFolder -ErrorAction SilentlyContinue -Force
            $FilesFolder = $folderPath + "\Files" 
            mkdir $FilesFolder -ErrorAction SilentlyContinue -Force
            Write-Host "Directories created"
            ##########################################################################

            ###### RDPSessions ######
            Write-Host "[1/24] Creating report on RDP connections..."
            $ProcessOutput = "$RDPSessionFolder\RDPSessions.txt"
            "CURRENT CONNECTIONS :" | Out-File -Force -FilePath $ProcessOutput
            qwinsta /server:localhost | Add-Content $ProcessOutput
            "INCOMING CONNECTIONS :" | Add-Content $ProcessOutput
            Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -ErrorAction SilentlyContinue | Out-String | Add-Content $ProcessOutput 
            "OUTGOING CONNECTIONS :" | Add-Content $ProcessOutput 
            Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -ErrorAction SilentlyContinue | Out-String | Add-Content $ProcessOutput 
            Write-Host "[1/24] RDP Session report ready!"

            ###### PersistenceSniper ######

            Write-Host "[2/24] PersistenceSniper report creation..."
            $ProcessOutput = "$PersistenceFolder\Persistence.txt"
            $persistencecsv = 'persistences.csv'
            $newpersistencecsv = 'newPersistences.csv'
            $Persistence = Find-AllPersistence -DiffCSV $persistencecsv -OutputCSV $newpersistencecsv
            Import-Csv $newpersistencecsv | Format-Table | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[2/24] PersistenceSniper report ready!"

            ###### PStree ######

            Write-Host "[3/24] PSTree report creation..."
            $ProcessOutput = "$PStreeFolder\PStree.txt"
            Get-Process | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[3/24] PSTree report ready !"

            ###### TCPConnection ######

            Write-Host "[4/24] TCPConnection report creation..."
            $ProcessOutput = "$NetworkFolder\TCPConnection.txt"
            Get-NetTCPConnection | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[4/24] TCPConnection report ready !"

            ###### Users ######

            Write-Host "[5/24] Users report creation..."
            $ProcessOutput = "$UsersFolder\Users.txt"
            "LOCAL USERS :" | Out-File -Force -FilePath $ProcessOutput
            "" | Add-Content $ProcessOutput
            Get-LocalUser | Add-Content $ProcessOutput
            if ($mg) {
                $displayName = $env:COMPUTERNAME
                $device = Get-MgDevice -Filter "displayName eq '$displayName'"
                $deviceId = $device.Id
                $users = Get-MgDeviceRegisteredUser -DeviceId $deviceId 
                "" | Add-Content $ProcessOutput
                "AZURE USERS :" | Add-Content $ProcessOutput
                "" | Add-Content $ProcessOutput
            }

            foreach ($user in $users) {
                get-mguser -UserId $user.Id | Select-Object DisplayName | Add-Content $ProcessOutput
            }
            Write-Host "[5/24] Users report ready !"

            ###### IPInfo ######

            Write-Host "[6/24] IPInfo report creation..."
            $ProcessOutput = "$NetworkFolder\IPInfo.txt"
            Get-NetIPAddress | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[6/24] IPInfo report ready !"

            ###### ShadowCopies ######
            Write-Host "[7/24] ShadowCopies report creation..."
            $ProcessOutput = "$ShadowFolder\ShadowCopies.txt"
            Get-CimInstance Win32_ShadowCopy | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[7/24] ShadowCopies report ready !"


            ###### AutoRunInfo ######
            Write-Host "[8/24] Creating AutoRunInfo report..."
            $ProcessOutput = "$AutoRunFolder\AutoRunInfo.txt"
            Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[8/24] AutoRunInfo Report created!"

            ###### DriverInstalled ######
            Write-Host "[9/24] Creating DriverInstalled Report..."
            $ProcessOutput = "$DriverFolder\DriverInstalled.txt"
            driverquery | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[9/24] DriverInstalled Report created!"

            ###### PowershellHistory ######
            Write-Host "[10/24] Creating PowershellHistory Report..."
            $ProcessOutput = "$PowershellFolder\PowershellHistory.txt"
            Get-History | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[10/24] PowershellHistory Report created!"

            ###### OfficeConnection ######
            Write-Host "[11/24] Creating OfficeConnection Report..."
            $ProcessOutput = "$OfficeFolder\OfficeConnection.txt"
            Get-ChildItem -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Internet\Server Cache\' | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[11/24] OfficeConnection Report created!"

            ###### SecurityEventsCount ######
            Write-Host "[12/24] Creating SecurityEventsCount Report..."
            $ProcessOutput = "$SecurityEventsFolder\SecurityEventsCount.txt"
            $SecurityEvents = Get-EventLog -LogName security -After (Get-Date).AddDays(-7)
            $SecurityEvents | Group-Object -Property EventID -NoElement | Sort-Object -Property Count -Descending | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[12/24] SecurityEventsCount Report created!"

            ###### SecurityEvents ######
            Write-Host "[13/24] Creating SecurityEvents Report..."
            $ProcessOutput = "$SecurityEventsFolder\SecurityEvents.txt"
            Get-EventLog security -After (Get-Date).AddDays(-7) | Format-List * | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[13/24] SecurityEvents Report created!"

            ###### DNSCache ######
            Write-Host "[14/24] Creating DNSCache Report..."
            $ProcessOutput = "$DNSFolder\DNSCache.txt"
            Get-DnsClientCache | Format-List | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[14/24] DNSCache Report created!"

            ###### ScheduledTasks ######
            Write-Host "[15/24] Creating ScheduledTasks Report..."
            $ProcessOutput = "$tasksFolder\ScheduledTasks.txt"
            Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Format-List | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[15/24] ScheduledTasks Report created!"

            ###### ScheduledTasksRunInfo ######
            Write-Host "[16/24] Creating ScheduledTasksRunInfo Report..."
            $ProcessOutput = "$tasksFolder\ScheduledTasksRunInfo.txt"
            Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Get-ScheduledTaskInfo | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[16/24] ScheduledTasksRunInfo Report created!"

            ###### ActiveprocessPriority ######
            Write-Host "[17/24] Creating ActiveprocessPriority Report..."
            $ProcessOutput = "$PStreeFolder\ActiveprocessPriority.txt"
            $AllProcesses = Get-Process
            $AllProcesses | Get-Process | Format-Table -View priority | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[17/24] ActiveprocessPriority Report created!"

            ###### ProcessCommandLineInfo ######
            Write-Host "[18/24] Creating ProcessCommandLineInfo Report..."
            $ProcessOutput = "$PStreeFolder\ProcessCommandLineInfo.txt"
            Get-WmiObject Win32_Process | Select-Object Name, ProcessId, CommandLine, Path | Format-List | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[18/24] ProcessCommandLineInfo Report created!"

            ###### ActiveProcessesDetailed ######
            Write-Host "[19/24] Creating ActiveProcessesDetailed Report..."
            $ProcessOutput = "$PStreeFolder\ActiveProcessesDetailed.txt"
            Get-Process | Format-List * | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[19/24] ActiveProcessesDetailed Report created!"

            ###### RunningServices ######
            Write-Host "[20/24] Creating RunningServices Report..."
            $ProcessOutput = "$ServiceFolder\RunningServices.txt"
            Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }  | format-list | Out-File -Force -FilePath $ProcessOutput 
            Write-Host "[20/24] RunningServices Report created!"

            ###### SMBShares ######
            Write-Host "[21/24] Creating SMBShares Report..."
            $ProcessOutput = "$SMBFolder\SMBShares.txt"
            Get-SmbShare | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[21/24] SMBShares Report created!"

            ###### NetworkShares ######
            Write-Host "[22/24] Creating NetworkShares Report..."
            $ProcessOutput = "$NetworkFolder\NetworkShares.txt"
            Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ | Format-Table | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[22/24] NetworkShares Report created!"

            ###### RemotelyOpenedFile ######
            Write-Host "[23/24] Creating RemotelyOpenedFile Report..."
            $ProcessOutput = "$FilesFolder\RemotelyOpenedFile.txt"
            openfiles | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[23/24] RemotelyOpenedFile Report created!"

            ###### RecentlyInstalledSoftware ######
            Write-Host "[24/24] Creating RecentlyInstalledSoftware Report..."
            $ProcessOutput = "$FilesFolder\RecentlyInstalledSoftware.txt"
            Get-WinEvent -ProviderName msiinstaller | Where-Object id -eq 1033 | Select-Object timecreated, message | Format-List * | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[24/24] RecentlyInstalledSoftware Report created!"


            Write-Host "Writing results to $FolderPath.zip..."
            Compress-Archive -Force -LiteralPath $FolderPath -DestinationPath "$FolderPath.zip"
            Write-Host "Complete!"

            $z = Read-Host "> Continue? (Y/N)"
            if ($z -eq "N") {
                exit
            }
        }
    }
    clear-host
}