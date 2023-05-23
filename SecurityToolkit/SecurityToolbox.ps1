#############################################################################################################
##                                                                                                         ##
##  Toolbox d'outils de securite pour de la reconnaisance et/ou de la collecte d'informations de securite  ##
##  Author : Jules LOUAPRE                                                                                 ##
#############################################################################################################
param([switch] $help)
if ($help -eq $True){
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
    La sec toolbox permet de réaliser une analyse DFIR du système sur lequel elle est executee. Il est 
    obligatiore d'avoir des droits administrateurs pour lancer le script. 

    La toolbox permet de réaliser environ 25 actions différentes : 

    - Persistence Sniper : Le module PersistenceSniper est un module powershell qui vise à lister les 
        processus et/ou application effectuant de la persistence sur le poste. Ses detections se base sur 
        le modele MITRE. Les résultats sont stockee dans deux fichier csv nommes 'persistence.csv' et 
        'newPersistence.csv'. Le premier contient la liste des faux positif deja recenses, et le deuxieme 
        contient les nouveaux elements detectes par le script. Cette action correspond au numero [1] dans 
        le menu.  
        REMARQUE : Il est normal qu'un grand nombre de faux positif soit recense par le script.

    - RDPSession : Cette action se base sur les connexions RDP du poste. Il vient lister les sessions RDP 
        en cours et celle passee. Le script vient directement interroger les cles de registre a deux 
        endroits differents afin d'obtenir les connexions entrantes et sortantes en plus. Il utilise 
        egalement la commande qwinsta native a Windows pour voir les sessions actuelles. Cette action 
        correspond au numero [2] dans le menu. 

    - PStree : Cette action vient ouvrir un second menu offrant 2 choix. Le premier perme de lister 
        l'ensemble des processus en cours sur le poste et ainsi de recuperer leur PID. Le second permet 
        de kill (fin de tache) un processus a partir de son PID. Cette action est realise en tant 
        qu'administrateur et ermet donc de forcer la fermeture du processus. Cette action correspond au 
        numero [3] dans le menu. 

    - TCP Connection : Cette action vient referencer toutes les adresses IP contactes par le poste. 

"@
    exit
}

### Necessite les privileges Admin

If (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
}
$pshost = get-host
$pswindow = $pshost.ui.rawui
$newsize = $pswindow.buffersize
$newsize.height = 3000
$newsize.width = 150
$pswindow.buffersize = $newsize
$newsize = $pswindow.windowsize
$newsize.height = 400
$newsize.width = 600
$pswindow.windowsize = $newsize

Clear-Host

############################################################################################################################################################################################################

#Creation du repertoire pour le poste si non-existant

Write-Host "Creation d'un repertoire de sortie..."
$drive = Get-Volume -FileSystemLabel "TOOLSEC" -ErrorAction SilentlyContinue
$ExecutionTime = $(get-date -f yyyy-MM-dd)
$folderPath = $drive.DriveLetter + ":\DFIR\$ExecutionTime"
New-Item -ItemType Directory -Path $folderPath -ErrorAction SilentlyContinue
$folderPath = $drive.DriveLetter + ":\DFIR\$ExecutionTime\$env:computername"
New-Item -ItemType Directory -Path $folderPath -ErrorAction SilentlyContinue
Write-Host "Repertoire de sortie cree : $FolderPath..."
$pathmodule = $drive.DriveLetter + ':\SecurityToolkit\PersistenceSniper\test\PersistenceSniper.psm1'

Import-Module -Name $pathModule -Verbose -ErrorAction SilentlyContinue
#Connexion Microsoft Graph

$clientIdGraph = "0641e3de-c640-482d-b918-531ca43b636e"
$tenantIdGraph = "f2a49d08-2560-4646-97f7-44a38f4df04e"
$thumbprintGraph = "33B9B8521432EFF3450F5A8F079534E60C595E37"
Connect-MgGraph -ClientID $clientIdGraph -TenantId $tenantIdGraph -CertificateThumbprint $thumbprintGraph 
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
    write-host "================================================================================"
    Write-Host ""
    write-host "[1]  Persistence Sniper :           recherche activemment les persistences sur le poste a l'aide du fichier
                                    persistences.csv et affiche les resultats dans newPersistences.csv "
    write-host "[2]  RDPSession :                   Liste l'historique de connexion RDP"
    write-host "[3]  PStree :                       Liste les processus en cours ou kill un processus"
    write-host "[4]  TCP Connection :               Liste toute les connexions TCP actives"
    write-host "[5]  Users                          Repertorie les utilisateurs locaux et Azure sur le poste"
    write-host "[6]  IPIfo :                        Recupere les differente interfaces reseaux du poste"
    write-host "[7]  ShadowCopies :                 Montre si une shadowCopy existe"
    write-host "[8]  AutoRunInfo :                  Liste les AutoRun"
    write-host "[9]  DriverInstalled :              Liste les driver installes"
    write-host "[10] PowershellHstory :             Recupere l'historique powershell"
    write-host "[11] OfficeConnection :             Enumere les connexions Office"
    write-host "[12] SecurityEvents :               Liste les evenements de securite (peut prendre un peu de temps)"
    write-host "[13] DNSCache :                     Recupere le cache DNS"
    write-host "[14] ScheduledTasks :               Liste les tâches programmees et leurs infos"
    write-host "[15] RunningServices :              Liste les services en route"
    write-host "[16] SMBShares :                    Liste les SMBShares"
    write-host "[17] NetworkShares :                Liste les NetworkShares"
    write-host "[18] RemotelyopenedFiles :          Liste les fichiers ouverts a distance"
    write-host "[19] RecentelyInstalledSoftware :   Liste les logiciels installes recemment"
    write-host "[20] Rapport global du poste (peut prendre un peu de temps)"
    $x = Read-Host " Choix > " 
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
            write-host "1: Connexion entrante"
            write-host "2: Connexion sortante"
            $y = read-host "Choix > "
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
            write-host "1: Recupere la liste des processus"
            write-host "2: kill un processus"
            write-host "3: ProcessCommandLineinfo"
            $y = read-host " Choix >"
            switch ($y) {
                1 {
                    Get-Process | Out-GridView 
                }
                2 {
                    $process = Read-Host "PID a kill >"
                    Stop-Process -Id $process -Force
                }
                3{
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
            write-host "1: Repertorie les utilisateurs locaux "
            write-host "2: Repertorie les utilisateurs Azure"
            $y = read-host " Choix >"
            switch ($y) {
                1 {
                    Get-LocalUser | Out-GridView
                } 
                2 {
                    $displayName = $env:COMPUTERNAME
                    $device = Get-MgDevice -Filter "displayName eq '$displayName'"
                    $deviceId = $device.Id
                    $users = Get-MgDeviceRegisteredUser -DeviceId $deviceId 
                    foreach ($user in $users) {
                        get-mguser -UserId $user.Id | Select-Object DisplayName | Out-GridView
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
            $y = read-host " Choix >"
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
        13{
            Get-DnsClientCache | Out-GridView
        }
        14{
            Clear-Host
            write-host "=========== Scheduled Tasks ===========" 
            write-host "1: ScheduledTasks"
            write-host "2: ScheduledTasksInfo"
            
            $y = read-host " Choix >"
            switch ($y) {
                1 {
                    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Out-GridView
                }
                2 {
                    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo | Out-GridView
                }
                
            }
        }
        15 {
            Get-Service | Where-Object {$_.Status -eq "Running"} | Out-GridView -ErrorAction SilentlyContinue
        }
        16 {
            Get-SmbShare |Out-GridView
        }
        17 {
            Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ | Out-GridView
        }
        18{
            openfiles |Out-GridView
        }
        19 {
            Get-WinEvent -ProviderName msiinstaller | Where-Object id -eq 1033 | Select-Object timecreated,message | Out-GridView
        }
        20 {
            Clear-Host

            #Creation des differents dossiers

            Write-Host "Creation des repertoires..."
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
            Write-Host "Repertoires crees"
            ##########################################################################
            #Creation des rapports

            ###### RDPSessions ######
            Write-Host "[1/24] Creation du rapport sur les connexions RDP..."
            $ProcessOutput = "$RDPSessionFolder\RDPSessions.txt"
            "CONNEXIONS ACTUELLES :" | Out-File -Force -FilePath $ProcessOutput
            qwinsta /server:localhost | Add-Content $ProcessOutput
            "CONNEXIONS ENTRANTES :" | Add-Content $ProcessOutput
            Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -ErrorAction SilentlyContinue | Out-String | Add-Content $ProcessOutput 
            "CONNEXIONS SORTANTES :" | Add-Content $ProcessOutput
            Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -ErrorAction SilentlyContinue | Out-String | Add-Content $ProcessOutput 
            Write-Host "[1/24] Rapport RDPSession prêt !"

            ###### PersistenceSniper ######

            Write-Host "[2/24] Creation du rapport PersistenceSniper..."
            $ProcessOutput = "$PersistenceFolder\Persistence.txt"
            $persistencecsv = $drive.DriveLetter + ':\SecurityToolkit\persistences.csv'
            $newpersistencecsv = $drive.DriveLetter + ':\SecurityToolkit\newPersistences.csv'
            $Persistence = Find-AllPersistence -DiffCSV $persistencecsv -OutputCSV $newpersistencecsv
            Import-Csv $newpersistencecsv | Format-Table | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[2/24] Rapport PersistenceSniper prêt !"

            ###### PStree ######

            Write-Host "[3/24] Creation du rapport PStree..."
            $ProcessOutput = "$PStreeFolder\PStree.txt"
            Get-Process | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[3/24] Rapport PStree prêt !"

            ###### TCPConnection ######

            Write-Host "[4/24] Creation du rapport TCPConnection..."
            $ProcessOutput = "$NetworkFolder\TCPConnection.txt"
            Get-NetTCPConnection | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[4/24] Rapport TCPConnection prêt !"

            ###### Users ######

            Write-Host "[5/24] Creation du rapport Users..."
            $ProcessOutput = "$UsersFolder\Users.txt"
            "LOCAL USERS :" | Out-File -Force -FilePath $ProcessOutput
            "" | Add-Content $ProcessOutput
            Get-LocalUser | Add-Content $ProcessOutput
            $displayName = $env:COMPUTERNAME
            $device = Get-MgDevice -Filter "displayName eq '$displayName'"
            $deviceId = $device.Id
            $users = Get-MgDeviceRegisteredUser -DeviceId $deviceId 
            "" | Add-Content $ProcessOutput
            "AZURE USERS :" | Add-Content $ProcessOutput
            "" | Add-Content $ProcessOutput
            foreach ($user in $users) {
                get-mguser -UserId $user.Id | Select-Object DisplayName | Add-Content $ProcessOutput
            }
            Write-Host "[5/24] Rapport Users prêt !"

            ###### IPInfo ######

            Write-Host "[6/24] Creation du rapport IPInfo..."
            $ProcessOutput = "$NetworkFolder\IPInfo.txt"
            Get-NetIPAddress | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[6/24] Rapport IPInfo prêt !"

            ###### ShadowCopies ######
            Write-Host "[7/24] Creation du rapport ShadowCopies..."
            $ProcessOutput = "$ShadowFolder\ShadowCopies.txt"
            Get-CimInstance Win32_ShadowCopy | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[7/24] Rapport IPInfo prêt !"

            ###### AutoRunInfo ######
            Write-Host "[8/24] Creation du rapport AutoRunInfo..."
            $ProcessOutput = "$AutoRunFolder\AutoRunInfo.txt"
            Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[8/24] Rapport AutoRunInfo prêt !"

            ###### DriverInstalled ######
            Write-Host "[9/24] Creation du rapport DriverInstalled..."
            $ProcessOutput = "$DriverFolder\DriverInstalled.txt"
            driverquery | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[9/24] Rapport Driverinstalled prêt !"

            ###### PowershellHistory ######
            Write-Host "[10/24] Creation du rapport PowershellHistory..."
            $ProcessOutput = "$PowershellFolder\PowershellHistory.txt"
            Get-History | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[10/24] Rapport PowershellHistory prêt !"

            ###### OfficeConnection ######
            Write-Host "[11/24] Creation du rapport OfficeConnection..."
            $ProcessOutput = "$OfficeFolder\OfficeConnection.txt"
            Get-ChildItem -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Internet\Server Cache\' | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[11/24] Rapport OfficeConnection prêt !"

            ###### SecurityEventsCount ######
            Write-Host "[12/24] Creation du rapport SecurityEventsCount..."
            $ProcessOutput = "$SecurityEventsFolder\SecurityEventsCount.txt"
            $SecurirtyEvents = Get-EventLog -LogName security -After (Get-Date).AddDays(-7)
            $SecurirtyEvents | Group-Object -Property EventID -NoElement | Sort-Object -Property Count -Descending | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[12/24] Rapport SecurityEventsCount prêt !"

            ###### SecurityEvents ######
            Write-Host "[13/24] Creation du rapport SecurityEvents..."
            $ProcessOutput = "$SecurityEventsFolder\SecurityEvents.txt"
            get-eventlog security -After (Get-Date).AddDays(-7) | Format-List * | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[13/24] Rapport SecurityEvents prêt !"

            ###### DNSCache ######
            Write-Host "[14/24] Creation du rapport DNSCache..."
            $ProcessOutput = "$DNSFolder\DNSCache.txt"
            Get-DnsClientCache | Format-List | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[14/24] Rapport DNSCache prêt !"

            ###### ScheduledTasks ######
            Write-Host "[15/24] Creation du rapport ScheduledTasks..."
            $ProcessOutput = "$tasksFolder\ScheduledTasks.txt"
            Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-List | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[15/24] Rapport ScheduledTasks prêt !"

            ###### ScheduledTasksRunInfo ######
            Write-Host "[16/24] Creation du rapport ScheduledTasksRunInfo..."
            $ProcessOutput = "$tasksFolder\ScheduledTasksRunInfo.txt"
            Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[16/24] Rapport ScheduledTasksRunInfo prêt !"

            ###### ActiveprocessPriority ######
            Write-Host "[17/24] Creation du rapport ActiveprocessPriority..."
            $ProcessOutput = "$PStreeFolder\ActiveprocessPriority.txt"
            $AllProcesses = Get-Process
            $AllProcesses | Get-Process | Format-Table -View priority | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[17/24] Rapport ActiveprocessPriority prêt !"
            
            ###### ProcessCommandLineInfo ######
            Write-Host "[18/24] Creation du rapport ProcessCommandLineInfo..."
            $ProcessOutput = "$PStreeFolder\ProcessCommandLineInfo.txt"
            Get-WmiObject Win32_Process | Select-Object Name, ProcessId, CommandLine, Path | Format-List | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[18/24] Rapport ProcessCommandLineInfo prêt !"

            ###### ActiveProcessesDetailed ######
            Write-Host "[19/24] Creation du rapport ActiveProcessesDetailed..."
            $ProcessOutput = "$PStreeFolder\ActiveProcessesDetailed.txt"
            Get-Process | Format-List * | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[19/24] Rapport ActiveProcessesDetailed prêt !"

            ###### RunningServices ######
            Write-Host "[20/24] Creation du rapport RunningServices..."
            $ProcessOutput = "$ServiceFolder\RunningServices.txt"
            Get-Service -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq "Running"}  | format-list | Out-File -Force -FilePath $ProcessOutput 
            Write-Host "[20/24] Rapport RunningServices prêt !"

            ###### SMBShares ######
            Write-Host "[21/24] Creation du rapport SMBShares..."
            $ProcessOutput = "$SMBFolder\SMBShares.txt"
            Get-SmbShare | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[21/24] Rapport SMBShares prêt !"

            ###### NetworkShares ######
            Write-Host "[22/24] Creation du rapport NetworkShares..."
            $ProcessOutput = "$NetworkFolder\NetworkShares.txt"
            Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ | Format-Table | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[22/24] Rapport NetworkShares prêt !"

            ###### RemotelyOpenedFile ######
            Write-Host "[23/24] Creation du rapport RemotelyOpenedFile..."
            $ProcessOutput = "$FilesFolder\RemotelyOpenedFile.txt"
            openfiles | Out-File -Force -FilePath $ProcessOutput
            Write-Host "[23/24] Rapport RemotelyOpenedFile prêt !"

            ###### RecentlyInstalledSoftware ######
            Write-Host "[24/24] Creation du rapport RecentlyInstalledSoftware..."
            $ProcessOutput = "$FilesFolder\RecentlyInstalledSoftware.txt"
            Get-WinEvent -ProviderName msiinstaller | Where-Object id -eq 1033 | Select-Object timecreated,message | Format-List *| Out-File -Force -FilePath $ProcessOutput
            Write-Host "[24/24] Rapport RecentlyInstalledSoftware prêt !"

            Write-Host "Ecriture des resultats dans $FolderPath.zip..."
            Compress-Archive -Force -LiteralPath $FolderPath -DestinationPath "$FolderPath.zip"
            Write-Host "Termine !"

            $z = Read-Host "> Continue ?(O/N)"
            if ($z -eq "N") {
                exit
            }
        }
    }
    clear-host
}