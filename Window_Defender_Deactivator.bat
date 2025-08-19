@ECHO OFF
SETLOCAL EnableDelayedExpansion
SET Version=1.0.0
Set ReleaseTime=Aug 19, 2025
Title Windows Defender Deactivator - by S.H.E.I.K.H (V. %version%)

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Check to see if this batch file is being run as Administrator. If it is not, then rerun the batch file ::
:: automatically as admin and terminate the initial instance of the batch file.                           ::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

(Fsutil Dirty Query %SystemDrive%>nul 2>&1)||(PowerShell start """%~f0""" -verb RunAs & Exit /B) > NUL 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::
:: End Routine to check if being run as Admin ::
::::::::::::::::::::::::::::::::::::::::::::::::

CD /D "%~dp0"
CLS

ECHO :::::::::::::::::::::::::::::::::::::::
ECHO ::   Windows Defender Deactivator    ::
ECHO ::                                   ::
ECHO ::      Version %Version% (Stable)       ::
ECHO ::                                   ::
ECHO ::   %ReleaseTime% by  S.H.E.I.K.H    ::
ECHO ::                                   ::
ECHO ::       GitHub: Sheikh98-DEV        ::
ECHO :::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO.
ECHO  Press any key to start ...
Pause >nul 2>&1l


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Microsoft Defender :::::
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO.

::::::::::::::::::::::::::::::::
ECHO Disabling Tamper Protection
::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender\Features" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling System Guard Runtime Monitor Broker (when disabled, it might cause BSOD Critical Process Died)
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\System\CurrentControlSet\Services\SgrmBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\SgrmBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Windows Defender Security Center
:::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\System\CurrentControlSet\Services\SecurityHealthService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\SecurityHealthService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::
ECHO Disabling Antivirus Notifications
::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Security and Maitenance Notification
:::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::
ECHO Disabling Real-time Protection
:::::::::::::::::::::::::::::::::::
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "AllowFastServiceStartup" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableSpecialRunningModes" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "ServiceKeepAlive" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /V "MpEnablePus" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableIOAVProtection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "DisableBlockAtFirstSeen" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "AllowFastServiceStartup" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableSpecialRunningModes" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "ServiceKeepAlive" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\MpEngine" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\MpEngine" /V "MpEnablePus" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableIOAVProtection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Reporting" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "DisableBlockAtFirstSeen" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F) >nul 2>&1

::::::::::::::::::::::
ECHO Disabling Logging
::::::::::::::::::::::
REG Query "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::
ECHO Disabling Tasks
::::::::::::::::::::
SchTasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuaRD MDM policy Refresh" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >nul 2>&1 
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >nul 2>&1

:::::::::::::::::::::::::::
ECHO Disabling Systray icon
:::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /V "SecurityHealth" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /V "SecurityHealth" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth" /F) >nul 2>&1

:::::::::::::::::::::::::::
ECHO Disabling Context Menu
:::::::::::::::::::::::::::
REG Query "HKCR\*\shellex\ContextMenuHandlers\EPP" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /F) >nul 2>&1
REG Query "HKCR\Directory\shellex\ContextMenuHandlers\EPP" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /F) >nul 2>&1
REG Query "HKCR\Drive\shellex\ContextMenuHandlers\EPP" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /F) >nul 2>&1

:::::::::::::::::::::::
ECHO Disabling Services
:::::::::::::::::::::::
SC Query "MDCoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MDCoreSvc" Start=Disabled) >nul 2>&1
SC Query "MDCoreSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MDCoreSvc_*" Start=Disabled) >nul 2>&1
SC Query "SecurityHealthService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SecurityHealthService" Start=Disabled) >nul 2>&1
SC Query "SecurityHealthService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SecurityHealthService_*" Start=Disabled) >nul 2>&1
SC Query "Sense" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Sense" Start=Disabled) >nul 2>&1
SC Query "Sense_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Sense_*" Start=Disabled) >nul 2>&1
SC Query "WdNisSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WdNisSvc" Start=Disabled) >nul 2>&1
SC Query "WdNisSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WdNisSvc_*" Start=Disabled) >nul 2>&1
SC Query "WinDefend" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WinDefend" Start=Disabled) >nul 2>&1
SC Query "WinDefend_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WinDefend_*" Start=Disabled) >nul 2>&1
SC Query "webthreatdefsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefsvc" Start=Disabled) >nul 2>&1
SC Query "webthreatdefsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefsvc_*" Start=Disabled) >nul 2>&1
SC Query "webthreatdefusersvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefusersvc" Start=Disabled) >nul 2>&1
SC Query "webthreatdefusersvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefusersvc_*" Start=Disabled) >nul 2>&1
SC Query "wscsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wscsvc" Start=Disabled) >nul 2>&1
SC Query "wscsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wscsvc_*" Start=Disabled) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\MDCoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\MDCoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\WdBoot" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\WdBoot" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\WdFilter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\WdNisDrv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\WdNisSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\WinDefend" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\MDCoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\MDCoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\WdBoot" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\WdBoot" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\WdFilter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\WdNisDrv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\WdNisDrv" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\WdNisSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\WinDefend" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Web Threat Defense Service (Phishing Protection)
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
SC Stop "webthreatdefsvc" >nul 2>&1
SC Query "webthreatdefsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefsvc" Start=Disabled) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Web Threat Defense User Service (Phishing Protection)
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
SC Stop "webthreatdefusersvc" >nul 2>&1
SC Query "webthreatdefusersvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefusersvc" Start=Disabled) >nul 2>&1

::::::::::::::::::::::::::::::::::
ECHO Disabling Windows SmartScreen
::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F) >nul 2>&1
TakeOwn /S %computername% /U %username% /F "%WinDir%\System32\smartscreen.exe" >nul 2>&1
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:f >nul 2>&1
TaskKill /IM /F "smartscreen.exe" >nul 2>&1
DEL "%WinDir%\System32\smartscreen.exe" /S /F /Q >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling SmartScreen Filter in Microsoft Edge
:::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" /VE /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" /VE /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling SmartScreen PUA in Microsoft Edge
::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled" /VE /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled" /VE /T "REG_DWORD" /D "0" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Windows SmartScreen for Windows Store Apps
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Smartscreen (to restore run "SFC /ScanNow")
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
TakeOwn /S "%computername%" /U "%username%" /F "%WinDir%\System32\smartscreen.exe" >nul 2>&1
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:f >nul 2>&1
TaskKill /IM "smartscreen.exe" /F >nul 2>&1
DEL "%WinDir%\System32\smartscreen.exe" /S /F /Q >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Smart App Control Blocking Legitimate Apps
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /V "VerifiedAndReputablePolicyState" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender" /V "VerifiedAndReputablePolicyState" /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::
ECHO Disabling Other Registry Keys
::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "SettingsPageVisibility" /T "REG_SZ" /D "hide:home" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "SettingsPageVisibility" /T "REG_SZ" /D "hide:home" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO.
ECHO :::: Windows Defender deactivated successfully. Now restart your machine. ::::
ECHO.
ECHO :::: Script by Sheikh98-DEV ::::
ECHO.
ECHO  Press any key to exit ...
Pause >nul 2>&1l