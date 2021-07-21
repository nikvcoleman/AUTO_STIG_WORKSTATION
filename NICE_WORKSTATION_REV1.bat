@ECHO OFF
CLS
ECHO REMEMBER TO RUN THIS AS ADMINISTRATOR!
ECHO This is a Batch Script written for the AASF project server hardening efforts
ECHO BY Nikolas Coleman 2021. 
ECHO Thank me later...preferably with more money
SET /P DRIVELETTER="PLEASE ENTER THE CURRENT USB DRIVE LETTER: "
ECHO COPYING FILES FROM USB TO DESKTOP!
COPY "%DRIVELETTER%:\NICE_WORKSTATION\GPWKS\AuditPolicy\audit.ini" "C:\Users\ESSAdmin\Desktop"
ECHO COPIED AUDIT POLICY TO DESKTOP
COPY "%DRIVELETTER%:\NICE_WORKSTATION\GPWKS\SecurityConfigurations\security.csv" "C:\Users\ESSAdmin\Desktop"
ECHO COPIED SECURITY CONFIGURATIONS TO DESKTOP
XCOPY /E /I /Y "%DRIVELETTER%:\NICE_WORKSTATION\GPWKS\GroupPolicyObjects" "C:\Windows\System32\GroupPolicy"
ECHO COPIED GROUP POLICY OBJECTS TO GROUP POLICY FOLDER
ECHO APPLYING GROUP POLICY
GPUPDATE /FORCE
ECHO IMPORTING SECURITY CONFIGURATIONS!
secedit /configure /cfg C:\Users\ESSAdmin\Desktop\security.csv /db defltbase.sdb /verbose
ECHO IMPORTING AUDIT POLICY!
auditpol /restore /file:C:\Users\ESSAdmin\Desktop\audit.ini
ECHO CONFIGURING DEP
BCDEDIT /set {current} nx OptOut
ECHO DISABLING SECONDARY LOGON SERVICE
sc config seclogon start= disabled
ECHO DELETING POWERSHELL V2
DISM /online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2
ECHO ADDING REGISTRY VALUES
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\ /v SchUseStrongCrypto /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Kernel DMA Protection" /v DeviceEnumerationPolicy /t REG_DWORD /d 0
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LegalNoticeCaption /t REG_SZ /d "US Department of Defense Warning Statement"
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LegalNoticeText /t REG_SZ /d "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. At any time, the USG may inspect and seize data stored on this IS. Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
ECHO CLEANING UP FILES FROM DESKTOP!
DEL C:\Users\ESSAdmin\Desktop\audit.ini /f /q 
DEL C:\Users\ESSAdmin\Desktop\security.csv /f /q
ECHO THE COMPUTER WILL NOW RESTART
SHUTDOWN /R /T 5