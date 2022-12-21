@echo off

if not "%1"=="am_admin" (powershell start -verb runas '%0' am_admin & exit /b)

::Collects users input and goes to selected option.
:menu
CLS
Color 0f
echo. [101mCreated by Teddy Mazrin[0m
echo ===============================================================================
:menu
echo. [7mPC Maintenance:[0m
echo.  Press 1  -  Troubleshoot PC
echo.  Press 2  -  Clear Disk Space / Temp Files
echo.  Press 3  -  Reset Network       
echo.  Press 4  -  Download Anti Virus Programs
echo.  Press 5  -  Disable or Enable Windows Updates / Windows Defender
echo.  Press 6  -  Boot into BIOS, Safe Mode, or Recovery Mode  
echo. [7mPC Tweaking/Downloads:[0m
echo.  Press 7  -  Apply Gaming Optimizations
echo.  Press 8  -  Nvidia
echo.  Press 9  -  Programs
echo ===============================================================================
set /p userinp= ^> Enter Your Option: 
if [%userinp%]==[] echo.&echo Invalid User Input&echo.&pause&goto :menu
if %userinp% gtr 10 echo.&echo Invalid User Selection&echo.&pause&goto :menu
if %userinp%==1 goto :opt1
if %userinp%==2 goto :opt2
if %userinp%==3 goto :opt3
if %userinp%==4 goto :opt4
if %userinp%==5 goto :opt5
if %userinp%==6 goto :opt6
if %userinp%==7 goto :opt7
if %userinp%==8 goto :opt8
if %userinp%==9 goto :opt9
goto :eof

::Option 1 will start (System File Checker) to search for corrupt files and repair them, then move on to Deployment Image Servicing and Management (DISM) to mount/service images, then move on to (CHKDSK) which checks the file system and file system metadata of a volume for logical and physical errors.
:opt1
CLS
::SFC
SFC /scannow

::DISM
DISM /Online /Cleanup-Image /CheckHealth
DISM /Online /Cleanup-Image /ScanHealth
DISM /Online /Cleanup-Image /RestoreHealth

::CHKDSK
chkdsk /f c:
pause
goto :menu

::Option 2 will clear all temporary files.
:opt2
CLS

::Clear Temp
del /s /f /q %windir%\temp\*.*    
rd /s /q %windir%\temp    
md %windir%\temp    
del /s /f /q %windir%\Prefetch\*.*    
rd /s /q %windir%\Prefetch    
md %windir%\Prefetch    
del /s /f /q %windir%\system32\dllcache\*.*    
rd /s /q %windir%\system32\dllcache    
md %windir%\system32\dllcache    
del /s /f /q "%SysteDrive%\Temp"\*.*    
rd /s /q "%SysteDrive%\Temp"    
md "%SysteDrive%\Temp"    
del /s /f /q %temp%\*.*    
rd /s /q %temp%    
md %temp%    
del /s /f /q "%USERPROFILE%\Local Settings\History"\*.*    
rd /s /q "%USERPROFILE%\Local Settings\History"    
md "%USERPROFILE%\Local Settings\History"    
del /s /f /q "%USERPROFILE%\Local Settings\Temporary Internet Files"\*.*    
rd /s /q "%USERPROFILE%\Local Settings\Temporary Internet Files"    
md "%USERPROFILE%\Local Settings\Temporary Internet Files"    
del /s /f /q "%USERPROFILE%\Local Settings\Temp"\*.*    
rd /s /q "%USERPROFILE%\Local Settings\Temp"    
md "%USERPROFILE%\Local Settings\Temp"    
del /s /f /q "%USERPROFILE%\Recent"\*.*    
rd /s /q "%USERPROFILE%\Recent"    
md "%USERPROFILE%\Recent"    
del /s /f /q "%USERPROFILE%\Cookies"\*.*    
rd /s /q "%USERPROFILE%\Cookies"    
md "%USERPROFILE%\Cookies"

::Disk Cleanup
%SystemRoot%\System32\Cmd.exe /c Cleanmgr /sageset:65535 
%SystemRoot%\System32\Cmd.exe /c Cleanmgr /sagerun:65535
pause
goto :menu

::Option 3 will reset network, flush DNS, reset network cache.
:opt3
CLS
netsh int ipv4 reset
netsh int tcp reset
netsh int ipv6 reset
netsh int httpstunnel reset
netsh int portproxy reset
netsh advfirewall reset
netsh winsock reset
netsh http flush logbuffer
netsh nap reset configuration
netsh branchcache reset
netsh lan reconnect
ipconfig /flushdns
pause
goto :menu


Option 4 will download antivirus programs in a zip folder, unzip the the folder, delete the zip folder, and put the folder on your desktop.
:opt4
cls
:: 7-Zip
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/1049532213454188604/7z2201-x64.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\7z.exe
start /w "" "%HOMEPATH%\AppData\Local\Temp\7z.exe" /S
CLS
timeout 1
cd %HOMEPATH%\AppData\Local\Temp
del /f 7z.exe
::AntiVirus
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/845805180757737472/Anti_Virus_Programs.zip' -OutFile %~dp0\Anti_Virus_Programs.zip
for /R "%~dp0" %%I in (Anti_Virus_Programs.zip) do "C:\Program Files\7-Zip\7z.exe" x -o"%%~dpI" -y -- "%%I"
cd %~dp0 
del /f Anti_Virus_Programs.zip
goto :menu

::Option 5 gives you the ability to enable or disable windows update and windows defender.
:opt5
cls
echo ===============================================================================
echo.  Press 1 -  Enable Windows Updates
echo.  Press 2 -  Disable Windows Updates
echo.  Press 3 -  Skip
echo ===============================================================================
SET /P choice=  [101;44m^> Enter Your Option:[0m  
IF /I "%choice%"=="1" goto :EnableUpdates
IF /I "%choice%"=="2" goto :DisableUpdates
IF /I "%choice%"=="3" goto :WindowsDefenderOption

:EnableUpdates
cls
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/845922714598506516/NSudo.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\NSudo.exe
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196328491941889/846164447558369290/Enable_Windows_Updates.bat' -OutFile %HOMEPATH%\AppData\Local\Temp\Enable_Windows_Updates.bat
cd %HOMEPATH%\AppData\Local\Temp >NUL
start NSudo.exe -U:T -P:E "%HOMEPATH%\AppData\Local\Temp\Enable_Windows_Updates.bat"
Goto :WindowsDefenderOption

:DisableUpdates
cls
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/845922714598506516/NSudo.exe' -OutFile %temp%\NSudo.exe
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196328491941889/846164463447179294/Disable_Windows_Updates.bat' -OutFile %HOMEPATH%\AppData\Local\Temp\Disable_Windows_Updates.bat
cd %HOMEPATH%\AppData\Local\Temp >NUL
start NSudo.exe -U:T -P:E "%HOMEPATH%\AppData\Local\Temp\Disable_Windows_Updates.bat"
Goto :WindowsDefenderOption

:WindowsDefenderOption
cls
echo ===============================================================================
echo.  Press 1 -  Enable Windows Defender
echo.  Press 2 -  Disable Windows Defender
echo.  Press 3 -  Skip
echo ===============================================================================
SET /P choice=  [101;44m^> Enter Your Option:[0m  
IF /I "%choice%"=="1" goto :EnableDefender
IF /I "%choice%"=="2" goto :DisableDefender
IF /I "%choice%"=="3" goto :menu

:EnableDefender
cls
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/845922714598506516/NSudo.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\NSudo.exe
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196328491941889/845922789617172502/Enable_Windows_Defender.bat' -OutFile %HOMEPATH%\AppData\Local\Temp\Enable_Windows_Defender.bat
cd %HOMEPATH%\AppData\Local\Temp >NUL
start NSudo.exe -U:T -P:E "%HOMEPATH%\AppData\Local\Temp\Enable_Windows_Defender.bat"
goto :menu

:DisableDefender
cls
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/845922714598506516/NSudo.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\NSudo.exe
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196328491941889/845922809108365312/Disable_Windows_Defender.bat' -OutFile %HOMEPATH%\AppData\Local\Temp\Disable_Windows_Defender.bat
cd %HOMEPATH%\AppData\Local\Temp >NUL
start NSudo.exe -U:T -P:E "%HOMEPATH%\AppData\Local\Temp\Disable_Windows_Defender.bat"
goto :menu

::Option 6 will give you the option to Boot in BIOS, Safe Mode, or Recovery Mode.
:opt6
CLS
echo ===============================================================================
echo.  Press 1 -  Boot into BIOS
echo.  Press 2 -  Boot into Safe Mode
echo.  Press 3 -  Boot into Recovery Mode
echo.  Press 4 -  Exit
echo ===============================================================================
SET /P choice=  [101;44m^> Enter Your Option:[0m  
IF /I "%choice%"=="1" goto :Bootintobios
IF /I "%choice%"=="2" goto :Bootsafemode
IF /I "%choice%"=="3" goto :Bootrecoverymode
IF /I "%choice%"=="4" goto :Exit

:Bootintobios
shutdown /fw /r /t 00


:Bootsafemode
cls
@echo [101;41mEnable or Disable Safe Mode?:[0m
@echo Type "Enable" to Enable Safe Mode.
@echo Type "Disable" to Disable Safe Mode.

SET /P choice=  [101;44mEnable / Disable:[0m  
IF /I "%choice%"=="Enable" goto enable
IF /I "%choice%"=="Disable" goto disable

:enable
@echo Enabling Safe Mode...
bcdedit /set {default} safeboot minimal

CLS
echo Safemode Enabled
goto choice

:disable
@echo Disabling Safe Mode...
bcdedit /deletevalue {default} safeboot
@echo Safe Mode Disabled

CLS
echo Safe Mode Disabled
goto choice

:choice 
cls
@echo [101;44mDo you want to restart your PC for changes to apply?:[0m  
@echo Type "Yes" to Restart your PC
@echo Type "No" to Exit

SET /P choice=  [101;44mYes / No:[0m  
IF /I "%choice%"=="Yes" goto restart
IF /I "%choice%"=="No" goto Exit

:restart
shutdown.exe /r /t 00


:Bootrecoverymode
cls
shutdown /r /o /f /t 00 

:Exit
cls
goto :menu

::Option 7 will change various setting within Windows to optimize performance.
:opt7
CLS
echo ===============================================================================
echo.  Press 1 -  Create a Restore Point
echo.  Press 2 -  Continue Without Restore Point
echo ===============================================================================
SET /P choice=  [101;44m^> Enter Your Option:[0m  
IF /I "%choice%"=="1" goto :Restorepoint
IF /I "%choice%"=="2" goto :Resumetweaking

:Restorepoint
net start vss
Powershell.exe -command "& {Enable-ComputerRestore -Drive "C:"}"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Checkpoint-Computer -Description "BeforeTweaking"}"


:Resumetweaking
::Disable power throttling
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f

::Games scheduling
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "Normal" /f

::Disable sleep
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t REG_DWORD /d "0" /f

::Disable Fast Startup
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "1" /f

::Disable hibernate
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f

::Disable automatic maintenance
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f

::Disable menu show delay
Reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f

::Restore the classic context menu 4 w11
Reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f

::Disable background apps global 4 w11
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f

::Disable windows widgets 4 w11
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f

::Disable Cortana
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowCortana" /T REG_DWORD /d 0

::Win32Priority
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /F /V "Win32PrioritySeparation" /T REG_DWORD /d "2"

::Turn off Enhance Pointer Precision
Reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f

:: UAC Disable
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f

::Disable Hibernate
powercfg -h off

::High Performance Powerplan
powercfg -restoredefaultschemes
powercfg -SETACTIVE "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a

goto :menu

::Option 8 will give you options to optimize nvidia graphics driver.
:opt8
cls
echo ===============================================================================
echo.  Press 1 -  Download Nvidia Drivers
echo.  Press 2 -  Uninstall Graphics Driver
echo.  Press 3 -  Strip Graphics Driver
echo.  Press 4 -  Reset Nvidia Settings to Default
echo.  Press 5 -  Import Nvidia Settings
echo.  Press 6 -  Exit
echo ===============================================================================
SET /P choice=  [101;44m^> Enter Your Option:[0m  
IF /I "%choice%"=="1" goto :DownloadDriver
IF /I "%choice%"=="2" goto :UninstallDriver
IF /I "%choice%"=="3" goto :StripDriver
IF /I "%choice%"=="4" goto :ResetNvidia
IF /I "%choice%"=="5" goto :Importnvidiasettings
IF /I "%choice%"=="6" goto :Exit

:DownloadDriver
cls
Start https://www.nvidia.com/Download/Find.aspx?lang=en-us
goto :menu

:UninstallDriver
CLS
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196321470414910/1049522340326805544/CleanupTool.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\CleanupTool.exe
%SystemRoot%\explorer.exe "%HOMEPATH%\AppData\Local\Temp\CleanupTool.exe"
goto :menu

:restart
cls
shutdown.exe /r /t 00

:Exit
cls
goto :menu

:StripDriver
cls
::NVCleanstall
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196321470414910/1049530211265421373/NVCleanstall_1.14.0.exe' -OutFile %temp%\NVCleanstall.exe
%SystemRoot%\explorer.exe "%temp%\NVCleanstall.exe"
goto :menu

:ResetNvidia
cls
del "%programdata%\NVIDIA Corporation\Drs\nvdrsdb0.bin" 
del "%programdata%\NVIDIA Corporation\Drs\nvdrsdb1.bin" 
del "%programdata%\NVIDIA Corporation\Drs\nvdrssel.bin"
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/839176687282946048/restart64.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\restart64.exe
cd %HOMEPATH%\AppData\Local\Temp
restart64.exe
cd %HOMEPATH%\AppData\Local\Temp
del /f restart64.exe
pause
goto :menu


:Importnvidiasettings
::Nvidia Settings
echo Importing Nvidia Profile Settings
echo 
echo
:: Install 7-Zip
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/1049532213454188604/7z2201-x64.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\7z.exe
cd %HOMEPATH%\AppData\Local\Temp
start /wait 7z.exe /S
CLS
@echo off 
cd %HOMEPATH%\AppData\Local\Temp
del /f 7z.exe

::Import Nvidia Settings
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196321470414910/1049528556104978432/NvidiaProfileInspector.zip' -OutFile C:\Windows\NvidiaProfileInspector.zip
for /R "C:\Windows" %%I in (*.zip) do "C:\Program Files\7-Zip\7z.exe" x -o"%%~dpI" -y -- "%%I"
cd C:\Windows
del /f NvidiaProfileInspector.zip
cd C:\Windows\NvidiaProfileInspector
Performance.bat


::Option 9 will automatically download the program of your choice to utilize as a windows utility.
:opt9
cls
::Programs
cls
echo ===============================================================================
echo.  Press 1 -  Device Cleanup
echo.  Press 2 -  Revo Uninstaller
echo.  Press 3 -  Autoruns
echo.  Press 4 -  Custom Resolution Utility
echo ===============================================================================
SET /P choice=  [101;44m^> Enter Your Option:[0m  
IF /I "%choice%"=="1" goto :Devicecleanup
IF /I "%choice%"=="2" goto :Revouninstaller
IF /I "%choice%"=="3" goto :Autoruns
IF /I "%choice%"=="4" goto :Customresolutionutility


:Devicecleanup
CLS
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/839184777247457300/DeviceCleanup.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\DeviceCleanup.exe
%SystemRoot%\explorer.exe "%HOMEPATH%\AppData\Local\Temp\DeviceCleanup.exe"
goto :menu

:Revouninstaller
CLS
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/943703697731514398/revosetup.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\revosetup.exe
%SystemRoot%\explorer.exe "%HOMEPATH%\AppData\Local\Temp\revosetup.exe"

:Autoruns
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196321470414910/1049522625073926224/autoruns.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\autoruns.exe
%SystemRoot%\explorer.exe "%HOMEPATH%\AppData\Local\Temp\autoruns.exe"

:Customresolutionutility
CLS
color 0f
echo ===============================================================================
echo.  Press 1 -  Run Custom Resolution Utility
echo.  Press 2 -  Reset Display Settings
echo.  Press 3 -  Restart Display Driver
echo.  Press 4 -  Exit
echo ===============================================================================
SET /P choice=  [101;44m^> Enter Your Option:[0m  
IF /I "%choice%"=="1" goto :CRU
IF /I "%choice%"=="2" goto :Reset
IF /I "%choice%"=="3" goto :Restart
IF /I "%choice%"=="4" goto :Exit

:CRU
cls
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196313120735232/844475729848172544/CRU.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\CRU.exe
cd %HOMEPATH%\AppData\Local\Temp
CRU.exe
goto restart

:Reset
cls
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196313120735232/844475240117174282/reset-all.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\reset-all.exe
cd %HOMEPATH%\AppData\Local\Temp
reset-all.exe
cd %HOMEPATH%\AppData\Local\Temp
del /f reset-all.exe
goto Afterreset

:Restart
cls
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/839176687282946048/restart64.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\restart64.exe
cd %HOMEPATH%\AppData\Local\Temp
restart64.exe
cd %HOMEPATH%\AppData\Local\Temp
del /f restart64.exe
exit

:Afterreset
cls
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "2" /f >nul
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/817196316853141535/839176687282946048/restart64.exe' -OutFile %HOMEPATH%\AppData\Local\Temp\restart64.exe
cd %HOMEPATH%\AppData\Local\Temp
restart64.exe
cd %HOMEPATH%\AppData\Local\Temp
del /f restart64.exe
goto CRU


:Exit
cls
goto :menu



goto :menu

