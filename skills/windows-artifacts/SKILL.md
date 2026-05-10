# Skill: Windows Artifacts

## Overview
Use this skill for Windows host-based artifact analysis on the SIFT workstation.


## General information
General information chapter includes additional information related to Windows artifacts.

ALWAYS hunt for known malicious case related IOCs against processed evidence artifacts once new IOCs become available.


## Windows Event Logs

Verify all available event IDs and their relation to the investigation.
Investigate at least the below event log files/channels.

| Channel | EVTX File Name |
|---------|-----------|
| Application | Application.evtx |
| Microsoft-Windows-GroupPolicy/Operational | Microsoft-Windows-GroupPolicy%4Operational.evtx  |
| Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-PowerShell%4Operational.evtx |
| Microsoft-Windows-Sysmon/Operational | Microsoft-Windows-Sysmon%4Operational.evtx |
| Microsoft-Windows-TaskScheduler/Operational | Microsoft-Windows-TaskScheduler%4Operational.evtx |
| Microsoft-Windows-TerminalServices-RDPClient/Operational | Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender%4Operational.evtx |
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx |
| Microsoft-Windows-WinRM/Operational | Microsoft-Windows-WinRM%4Operational.evtx |
| Microsoft-Windows-WMI-Activity/Operational | Microsoft-Windows-WMI-Activity%4Operational.evtx |
| Security | Security.evtx |
| Setup | Setup.evtx |
| System | System.evtx |
| Windows PowerShell | Windows PowerShell.evtx |

Investigate other event log files/channels as needed.

Pay attention to the role of the investigated system.
Investigate T0-systems with extra attention.
Audit policy configuration often includes Active Directory Domain Services related events
Events include enumeration activity and CRUDL events against domain objects.

Assessment of certainty can be increased via multiple artifacts indicating same activity.
For example, if PowerShell, Security, and Sysmon logs all include similar process creation activity at the same time.
Do not be satisfied with investigation results after only a single source indicating certain activity. 
Verify multiple sources for increasing assessment of certainty.


## Common Windows persistence (TA0003) techniques

### Registry Run Keys

All registry keys defined in MITRE ATT&CK "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder" documentation: https://attack.mitre.org/techniques/T1547/001/

Key registry paths for Registry Run Keys:

| Registry Key | Description |
|--------------|-------------|
| HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run | Current user always run |
| HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce | Current user run once |
| HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run | All users always run | 
| HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce | All users run once |
| HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx | All users run |
| HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders | Current user user shell folders |
| HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders | Current users shell folders |
| HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders | All users user shell folders |
| HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders | All users shell folders |
| HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices | Current user run services |
| HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce | Current user run services once |
| HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices | All users run services |
| HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce | All users run services once |
| HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run | Current user explorer run |
| HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run | All users explorer run |
| HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows | Current user Windows run |
| HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager | All users Session Manager autocheck run | 

Key Event IDs for Registry Run Keys:

| Log | Event ID | Description |
|-----|----------|-------------|
| Security | 4657 | A registry value was modified. |
| Sysmon | 12 | RegistryEvent (Object create and delete) |
| Sysmon | 13 | RegistryEvent (Value Set) |

References:
- https://attack.mitre.org/techniques/T1547/001/


### Scheduled Tasks

Key Event IDs for Task Scheduler:

| Log | Event ID | Description |
|-----|----------|-------------|
| Security | 4657 | A registry value was modified. |
| Security | 4663 | An attempt was made to access an object. |
| Security | 4698 | A scheduled task was created. |
| Security | 4699 | A scheduled task was deleted. |
| Security | 4700 | A scheduled task was enabled. |
| Security | 4701 | A scheduled task was disabled. |
| Security | 4702 | A scheduled task was updated. |
| Microsoft-Windows-TaskScheduler/Operational | 106 | A scheduled task registered (created). |
| Microsoft-Windows-TaskScheduler/Operational | 140 | A scheduled task registration updated. |
| Microsoft-Windows-TaskScheduler/Operational | 141 | A scheduled task registration deleted. |
| Sysmon | 11 | FileCreate |
| Sysmon | 12 | RegistryEvent (Object create and delete) |
| Sysmon | 13 | RegistryEvent (Value Set) |

Registry events are generated under registry key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\".
File events are generated under folder path "C:\Windows\System32\Tasks\".

References:
- https://www.thedfirspot.com/post/evil-on-schedule-investigating-malicious-windows-tasks
- https://redcanary.com/threat-detection-report/techniques/scheduled-task/


### Startup Folder

Key folder paths for Startup Folders:

| Registry Key | Description |
|--------------|-------------|
| C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ | The startup folder path for the current user |
| C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\ | The startup folder path for all users |

Key Event IDs for Startup Folders:

| Log | Event ID | Description |
|-----|----------|-------------|
| Security | 4663 | An attempt was made to access an object. |
| Sysmon | 11 | FileCreate |

References:
- https://attack.mitre.org/techniques/T1547/001/
- https://www.nextron-systems.com/2025/07/29/detecting-the-most-popular-mitre-persistence-method-registry-run-keys-startup-folder/
- https://www.hackingarticles.in/windows-privilege-escalation-boot-logon-autostart-execution-startup-folder/


### Services

Key Event IDs for Services:

| Log | Event ID | Description |
|-----|----------|-------------|
| Security | 4657 | A registry value was modified. |
| Security | 4697 | A service was installed in the system. |
| System | 7045 | A service was installed in the system. |
| Sysmon | 12 | RegistryEvent (Object create and delete) |
| Sysmon | 13 | RegistryEvent (Value Set) |

Registry events are generated under registry key "HKLM\SYSTEM\CurrentControlSet\Services\".

References:
- https://redcanary.com/threat-detection-report/techniques/windows-service/
- https://detect.fyi/threat-hunting-suspicious-windows-service-names-2f0dceea204c?gi=5c37e5156035


### Windows Management Instrumentation (WMI) event filters and consumers 

Key Event IDs for Services:

| Log | Event ID | Description |
| Sysmon | 19 | WmiEvent (WmiEventFilter activity detected) |
| Sysmon | 20 | WmiEvent (WmiEventConsumer activity detected) |
| Sysmon | 21 | WmiEvent (WmiEventConsumerToFilter activity detected) |

WMI database is located under local folder: "C:\WINDOWS\system32\wbem\Repository\".

References:
- https://www.cybertriage.com/blog/wmi-malware/
- https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/
- https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics



## Common Windows lateral movement (TA0008) techniques

## PowerShell Remoting (WinRM)

Child process creation by WSMPROVHOST.EXE.
Correlate child process creation events with successful logon events.

References:
- https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution
- https://redcanary.com/blog/threat-detection/lateral-movement-winrm-wmi/
- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WinRM.htm


## Windows Management Instrumentation (WMI)

Child process creation by wmiprvse.exe.
Correlate child process creation events with successful logon events.

Executed binary names:
- wmiprvse.exe

References:
- https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution
- https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/
- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/wmic.htm


## Distributed Component Object Model (DCOM)

Child process creation by "C:\Windows\system32\svchost.exe -k DcomLaunch"
Correlate child process creation events with successful logon events.

References:
- https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution
- https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-2-dcom/
- https://www.cybereason.com/blog/dcom-lateral-movement-techniques


## PsExec

Detect Windows service creation.
Correlate service creation events with successful logon events.

Executed binary names:
- PSEXESVC.exe
- PSEXEC.exe
- PSEXEC64.exe
- Potentially others

References:
- https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution
- https://redcanary.com/blog/threat-detection/threat-hunting-psexec-lateral-movement/
- https://www.sans.org/blog/protecting-privileged-domain-accounts-psexec-deep-dive
- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PsExec.htm


## Remote Desktop Protocol (RDP)

Correlate with successful logon events.

| Log | Event ID | Description |
|-----|----------|-------------|
| Security | 4624 | LogonType 2 - Interactive |
| Security | 4624 | LogonType 10 - RemoteInteractive |
| Security | 4624 | LogonType 11 - CachedInteractive |
| Security | 4624 | LogonType 12 - CachedRemoteInteractive |
| Security | 4778 | A session was reconnected to a Window Station. |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 21 | Remote Desktop Services: Session logon succeeded. |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 22 | Remote Desktop Services: Shell start notification received. |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 25 | Remote Desktop Services: Session reconnection succeeded. |

References:
- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/mstsc.htm
- https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
- https://frsecure.com/blog/rdp-connection-event-logs/


## Secure Shell (SSH)

Correlate with successful logon events.

| Log | Event ID | Description |
|-----|----------|-------------|
| OpenSSH/Operational | 4 | sshd: Accepted <LogonType> for <User> |

References:
- https://ogmini.github.io/2025/03/25/David-Cowen-Sunday-Funday-SSH-Windows.html
- https://learn.microsoft.com/fi-fi/windows-server/administration/OpenSSH/openssh-overview
