@echo off
REM .bat con permisos de administrador
:-------------------------------------
REM  --> Analizando los permisos
    IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
		>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
		>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)
REM --> Si hay error es que no hay permisos de administrador.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
rem ===============================================================================================================
rem ===============================================================================================================
rem ===================================MENU========================================================================
cls
:MENU
cls
color 3F
title IncidentRecon
echo ==============================================================================
echo ==============================================================================
echo                    IncidentRecon
echo.   														
echo.    														
echo                                       -by Rumpelstiltsquin- 	
echo ==============================================================================
echo ==============================================================================
echo %DATE% %TIME% 
echo.
echo {1}--  Recon
echo {2}--  Files find
echo {3}--  Malware analysis 
echo {4}--  PowerShell
echo {5}--  RAM collection
echo {6}--  Hook Analyzer
echo {99}-- Exit
echo.
set/p  si=IncidentRecon:~# 
echo.
if %si%==1 goto Recon
if %si%==2 goto files
if %si%==3 goto Malware
if %si%==4 goto Power
if %si%==5 goto RAM
if %si%==6 goto Analyzer
if %si%==99 goto Exit
if %si%==%si% goto Error
pause>nul
rem ===================================Recon========================================================================
:Recon
cls
md Recon
md Recon\Reg
md Recon\Logs
md Recon\Loot
echo  Working.......
echo ============================================================================== > Recon\Loot\loot.txt
echo           SYSTEM INFORMATION >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt						 
echo.
echo Timestamp: >> Recon\Loot\loot.txt && echo %DATE% %TIME%  >> Recon\Loot\loot.txt
echo .       
echo HostName: >> Recon\Loot\loot.txt && hostname >> Recon\Loot\loot.txt 
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo.	
echo SystemInfo, Installed Software and disk info: >> Recon\Loot\loot.txt && systeminfo >> Recon\Loot\loot.txt
psinfo -accepteula -s -h -d >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo 			USER INFORMATION >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
echo Whoami: >> Recon\Loot\loot.txt && whoami >> Recon\Loot\loot.txt
echo User: >> Recon\Loot\loot.txt && wmic useraccount list >> Recon\Loot\loot.txt
echo Localgroup administrators: Recon\Loot\loot.txt && net localgroup administrators >> Recon\Loot\loot.txt
echo User RDP: >> Recon\Loot\loot.txt
wmic rdtoggle list >> Recon\Loot\loot.txt
echo Lastlogon, badpass: >> Recon\Loot\loot.txt 
wmic netlogin get name,lastlogon,badpasswordcount >> Recon\Loot\loot.txt
echo Network cliente mng: >> Recon\Loot\loot.txt  
wmic netclient list brief >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo 			NETWORK INFORMATION >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.	
echo Netstat: >> Recon\Loot\loot.txt && netstat -naob >> Recon\Loot\loot.txt
echo PrintRoute: >> Recon\Loot\loot.txt && route print >> Recon\Loot\loot.txt
echo Table ARP: >> Recon\Loot\loot.txt && arp -a >> Recon\Loot\loot.txt
echo IPconfig:  >> Recon\Loot\loot.txt && ipconfig /allcompartments /all >> Recon\Loot\loot.txt
echo DisplayDNS: >> Recon\Loot\loot.txt && ipconfig /displaydns >> Recon\Loot\loot.txt
echo ShowProxy: >> Recon\Loot\loot.txt && netsh winhttp show proxy >> Recon\Loot\loot.txt
echo Show Int WLAN: >> Recon\Loot\loot.txt && netsh wlan show interfaces >> Recon\Loot\loot.txt
echo IPconfig description: >> Recon\Loot\loot.txt
wmic nicconfig get description,IPaddress,MACaddress >> Recon\Loot\loot.txt
echo Hosts File: >> Recon\Loot\loot.txt && type %SYSTEMROOT%\system32\drivers\etc\hosts >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo           SERVICES INFORMATION >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt	
echo.
echo Tasks: >> Recon\Loot\loot.txt && schtasks >> Recon\Loot\loot.txt
echo services start: >> Recon\Loot\loot.txt && net start >> Recon\Loot\loot.txt
echo Query Services: >> Recon\Loot\loot.txt && sc query >> Recon\Loot\loot.txt
echo Running Services brief: >> Recon\Loot\loot.txt
wmic service list brief  >> Recon\Loot\loot.txt
echo Process list memory: >> Recon\Loot\loot.txt
wmic process list memory >> Recon\Loot\loot.txt
echo Job list brief: >> Recon\Loot\loot.txt
wmic job list brief >> Recon\Loot\loot.txt
echo TaskList: >> Recon\Loot\loot.txt && tasklist /svc >> Recon\Loot\loot.txt
echo Enumerates processes run: >> Recon\Loot\loot.txt && pslist  >> Recon\Loot\loot.txt
echo List DLLs: >> Recon\Loot\loot.txt && listdlls >> Recon\Loot\loot.txt
echo Shows information processes: >> Recon\Loot\loot.txt && psservice >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo 			POLICY, PATH AND SETTINGS INFORMATION >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
echo Enviroment variable: >> Recon\Loot\loot.txt && set >> Recon\Loot\loot.txt
echo Policy information: >> Recon\Loot\loot.txt && gpresult /r /z >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo 			AUTORUN AND AUTOLOAD INFORMATION >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
echo  Startuo list: >> Recon\Loot\loot.txt
wmic startup list full: >> Recon\Loot\loot.txt
echo DomainController: >> Recon\Loot\loot.txt
wmic ntdomain list brief:>> Recon\Loot\loot.txt
echo Autostart proogram: >> Recon\Loot\loot.txt && autorunsc -accepteula -m >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo 	     FILES, DRIVES AND SHARES INFORMATION >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
echo Use network: >> Recon\Loot\loot.txt && net use >> Recon\Loot\loot.txt
echo Share network: >> Recon\Loot\loot.txt && net share >> Recon\Loot\loot.txt
echo Session network: >> Recon\Loot\loot.txt && net session >> Recon\Loot\loot.txt
echo Files opened remotely: >> Recon\Loot\loot.txt && psfile >>  Recon\Loot\loot.txt
echo Share name, path: >> Recon\Loot\loot.txt
wmic share get name,path >> Recon\Loot\loot.txt
echo Drives info: >> Recon\Loot\loot.txt
wmic volume list brief >> Recon\Loot\loot.txt
wmic logicaldisk get >> Recon\Loot\loot.txt
wmic logicaldisk get description,filesystem,name,size >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo 			BASIC NETWORK DISCOVERY >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt	
echo.
net view /all >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo 			NETBIOS >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt	
echo.
nbtstat -A 127.0.0.1 >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo 			CACHE >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
nbtstat -c >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo 			USER CONECTED >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
psloggedon -l >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo           ACTIVE DIRECTORY INVENTORY >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
dsquery ou >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo           LIST WORKSTATION IN THE DOMAIN >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
netdom query WORKSTATION >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo           LIST SERVER IN THE DOMAIN >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
netdom query SERVER >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo           LIST OF DOMAIN CONTROLLER >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
netdom query DC >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo           SHOW ALL RULES FIREWALL >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
netsh advfirewall firewall show rule name=all >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo           CHECK SETTING OF SECURITY LOGS >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt
echo.
wevtutil gl security >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo           Copy Log >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt	
echo.
echo Copy log......
psloglist >> Recon\Loot\loot.txt
copy %systemroot%\Logs\CBS Recon\Logs\logs_cbs.txt
copy %systemroot%\system32\winevt\Logs\ Recon\Logs\
echo  path--- Recon\Logs\ >> Recon\Loot\loot.txt
echo.
echo ============================================================================== >> Recon\Loot\loot.txt
echo           EXPORT REG >> Recon\Loot\loot.txt
echo ============================================================================== >> Recon\Loot\loot.txt	
echo.
echo Export reg......
echo  path--- Recon\Reg\ >> Recon\Loot\loot.txt
reg export HKLM Recon\Reg\HKLM.reg
reg export HKCU Recon\Reg\HKCU.reg
reg export HKCR Recon\Reg\HKCR.reg
reg export HKU Recon\Reg\HKU.reg
reg export HKCC Recon\Reg\HKCC.reg
echo ....Complete works! 
echo press key continue
pause>nul


rem echo Limpiar cache dns presione una tecla para continuar                 
rem pause
rem ipconfig /flushdns
rem nbtstat -R

goto menu

rem ===================================Powershell========================================================================
:Power
CLS
echo  Working.......

mkdir PowerShell
ECHO.
echo %DATE% %TIME% > PowerShell\loot.txt
echo ============================================================================== >> PowerShell\loot.txt
echo           ACCOUNT LOGON/OFF >> PowerShell\loot.txt
echo ============================================================================== >> PowerShell\loot.txt	
echo.
powershell -ExecutionPolicy Bypass get-eventlog security 4625,4634,4647,4624,4625,4648,4675,6272,6273,6274,62,75,6276,6277,6278,6279,6280,4649,4778,4779,4800,4801,4802,4803,5378,5632,5633,4964 -after ((get-date).addDays(-1)) >> PowerShell\loot.txt
echo.
echo ============================================================================== >> PowerShell\loot.txt
echo           CHECK AVAILABLE LOGS >> PowerShell\loot.txt
echo ============================================================================== >> PowerShell\loot.txt	
echo.
powershell -ExecutionPolicy Bypass Get-eventlog -list >> PowerShell\loot.txt
echo.
echo ============================================================================== >> PowerShell\loot.txt
echo         DETAILED TRACKING RPC EVENTS  >> PowerShell\loot.txt
echo ============================================================================== >> PowerShell\loot.txt	
echo.
powershell -ExecutionPolicy Bypass get-eventlog security 4692,4693,4694,4695,4689,5712 -after ((get-date).addDays(-1)) >> PowerShell\loot.txt
echo.
echo ============================================================================== >> PowerShell\loot.txt
echo   DUMP NEW ACTIVE DIRECTORY ACCOUNTS IN LAST 90 DAYS  >> PowerShell\loot.txt
echo ============================================================================== >> PowerShell\loot.txt	
echo.
powershell -ExecutionPolicy Bypass import-module activedirectory >> PowerShell\loot.txt	
powershell -ExecutionPolicy Bypass Get-QADUser -CreatedAfter (GetDate).AddDays(-90) >> PowerShell\loot.txt	
echo.
echo ....Complete works! 
echo press key continue
pause>nul
goto menu
rem ===================================files========================================================================
:files  
CLS
echo  Working.......
mkdir Files
echo.
echo %DATE% %TIME% > Files\loot.txt
echo.
echo ============================================================================== >> Files\loot.txt
echo           Find Multiple file types >> Files\loot.txt
echo ============================================================================== >> Files\loot.txt	
echo.
dir /A /S /T:A *.exe *.dll *.bat *.psi *.zip*.pdf* >> Files\loot.txt
echo.
echo ==============================================================================  >> Files\loot.txt
echo           Signature check of dll, exe files>> Files\loot.txt
echo ============================================================================== >> Files\loot.txt
echo.
echo   ==Signature check of dll, exe files ==
echo.
set/p  path=path-to-search:~# 
sigcheck -e -u %path%  >> Files\loot.txt
sigcheck -e -u %path%
echo.
echo ....Complete press key continue
pause>nul
echo.
echo ============================================================================== >> Files\loot.txt
echo           Find files with alternate data streams >> Files\loot.txt
echo ============================================================================== >> Files\loot.txt	
echo.
echo    ==Find files with alternate data streams==
echo.
set/p  path=path-to-search:~# 
streams -s %path% >> Files\loot.txt
streams -s %path%
echo. 
echo ....Complete press key continue
pause>nul
echo.
echo ==============================================================================  >> Files\loot.txt
echo           Find and show only unsigned files with bad signature >> Files\loot.txt
echo ============================================================================== >> Files\loot.txt
echo.
echo   ==Find and show only unsigned files with bad signature ==
echo.
set/p  path=path-to-search:~# 
sigcheck -e -u -vt -s %path%  >> Files\loot.txt
sigcheck -e -u -vt -s %path%
echo.
echo ....Complete press key continue
pause>nul
echo.
echo ============================================================================== >> Files\loot.txt
echo           Search for files nawer than date >> Files\loot.txt
echo ============================================================================== 	>> Files\loot.txt
echo.
echo  ==Search for files nawer than date ==
set/p date=date:~# 
set/p type=Type-file(*.exe):~# 
set/p path=path-to-search:~# 
forfiles /P %path% /M %type% /S /D +%date% /C "cmd /c echo @fdate @ftime @path"  >> Files\loot.txt
echo.
echo ....Complete works! 
echo press key continue
pause>nul
goto menu

rem ===================================Malware========================================================================
:Malware 
CLS
echo  Working.......
mkdir Malware
echo.
echo %DATE% %TIME% > Malware\loot.txt
echo.
echo ============================================================================== >> Malware\loot.txt
echo           View HEX and SCAII any file >> Malware\loot.txt
echo ============================================================================== >> Malware\loot.txt	
echo.
echo == View HEX and SCAII any file ==
set/p path=Suspicious-file:~# 
hexdump.exe -C  %path% >> Malware\loot.txt
hexdump.exe -C  %path%
echo.
echo ....Complete press key continue
pause>nul
echo.
echo ============================================================================== >> Malware\loot.txt
echo           View string within PE >> Malware\loot.txt
echo ============================================================================== >> Malware\loot.txt	
echo.
echo == View string within PE ==
set/p path=Suspicious-file:~# 
strings -n 10  %path% >> Malware\loot.txt
strings -n 10  %path%
echo.
echo ....Complete press key continue
pause>nul
echo.
echo ============================================================================== >> Malware\loot.txt
echo           Send suspicious file to VirusTotal >> Malware\loot.txt
echo ============================================================================== >> Malware\loot.txt	
echo.
echo == Send suspicious file to VirusTotal ==
set/p path=Suspicious-file:~# 
sigcheck -vt %path% >> Malware\loot.txt
echo.
echo ....Complete works! 
echo press key continue
pause>nul
goto menu

rem ===================================RAM COLLECTION========================================================================
:RAM
CLS
echo %DATE% %TIME%
set/p continue=Continue [Y/n]:~# 
echo.
if %continue%==Y goto dumpit
if %continue%==n goto MENU
if %continue%==%continue% goto Error
pause>nul

				:dumpit
				color 0f
				echo.
				DumpIt.exe

echo ....Complete works! 
echo press key continue
pause>nul
goto menu
rem ===================================HookAnalyzer========================================================================
:Analyzer
cls
echo %DATE% %TIME%

color 0f
HookAnalyser.exe



rem ===================================EXIT========================================================================
:Exit 
cls
exit
rem ===================================ERROR========================================================================
:Error 
cls
echo ERROR!!!!
echo press key continue
pause>nul
goto menu
pause
exit
pause>nul





