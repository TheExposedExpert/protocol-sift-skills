# Skill: Host Report

## Overview
Use this skill to create a system report from all investigated hosts.<br>
ALWAYS write full report first as a markdown file.<br>
NEVER include information related to the security incident in the host report.<br>
Then create an easy to digest .HTML report based on the .md file.

## Windows Hosts

Include the following information for all Windows systems under investigation.


### Host information

| Information | Artefact |
|-------------|----------|
| Hostname | HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\HostName |
| Domain | HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Domain |


### Hardware information

| Information | Artefact |
|-------------|----------|
| Manufacturer | HKLM\System\HardwareConfig{GUID}\SystemManufacturer |
| Model name| HKLM\System\HardwareConfig{GUID}\SystemFamily |
| Model code | HKLM\System\HardwareConfig{GUID}\SystemProductName |
| UEFI/BIOS version | HKLM\System\HardwareConfig{GUID}\SystemBiosVersion |
| UEFI/BIOS version | HKLM\System\HardwareConfig{GUID}\BIOSVersion |
| UEFI/BIOS release date | HKLM\System\HardwareConfig{GUID}\BIOSReleaseDate |


### Operating system information

| Information | Artefact |
|-------------|----------|
| Windows SKU | HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProductName |
| Windows build number | HKLM\Software\Microsoft\Windows NT\CurrentVersion\CurrentBuild |
| Windows build name | HKLM\Software\Microsoft\Windows NT\CurrentVersion\DisplayVersion |
| Windows version number | HKLM\Software\Microsoft\Windows NT\CurrentVersion\LCUVer |
| Windows revision (Update Build Revision) | HKLM\Software\Microsoft\Windows NT\CurrentVersion\UBR |
| Windows last installation date | HKLM\Software\Microsoft\Windows NT\CurrentVersion\InstallDate |
| Windows last installation time | HKLM\Software\Microsoft\Windows NT\CurrentVersion\InstallTime |
| Windows original installation time | HKLM\Software\Setup\Source OS\InstallTime |

Windows last installation time is in LDAP time.

Verify the actual release date for the operating system based on Major, Minor, Build & Revision version via Microsoft documentation:
- Windows 11: https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
- Windows 10: https://learn.microsoft.com/en-us/windows/release-health/release-information


### Timezone information

| Information | Artefact |
|-------------|----------|
| Timezone | HKLM\System\CurrentControlSet\Control\TimeZoneInformation\TimeZoneKeyName |

Verify the actual timezone value for the operating system based on the name via Microsoft documentation:
- Windows: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-time-zones?view=windows-11


### Networking information

List local IP-address or IP-addresses of the system


### User accounts

#### Local user accounts

List all local user accounts under the SAM registry hive.<br>
RegRipper tool can be used to parse SAM registry hive if necessary:
- https://github.com/keydet89/RegRipper3.0

| Information |
|-------------|
| Account SID |
| Account name |
| Last logon date |
| Last password reset date |
| Account local group memberships |


#### User profiles

List all created local and domain user profiles under the C:\Users\ directory.


### Installed applications

| Information | Artefact |
|-------------|----------|
| System wide 64-bit applications | HKLM\Software\Microsoft\CurrentVersion\Uninstall\ |
| System wide 32-bit applications | HKLM\Software\WOW6432Node\Microsoft\CurrentVersion\Uninstall\ |
| Per user account 64-bit applications | HKCU\<AccountSID>\Software\Microsoft\CurrentVersion\Uninstall\ |
| Per user account 32-bit applications | HKCU\<AccountSID>\Software\WOW6432NodeMicrosoft\CurrentVersion\Uninstall\ |

Applications installed for each user account are located in user profile registry hives:
- Per user: C:\Users\<AccountName>\NTUSER.dat

Also list applications which are not included in system wide registry, but are only available directly under Program Files directories: 
- 64-bit applications: C:\Program Files\<ApplicationName>\
- 32-bit applications: C:\Program Files (x86)\<ApplicationName>\
  
Some old applications are only copied to local disk without installation through separate setup .exe or .msi files.


### Event log retention time

Verify oldest and newest event time for the below event logs:

| Channel | EVTX File Name |
|---------|-----------|
| Application | Application.evtx |
| Security | Security.evtx |
| Setup | Setup.evtx |
| System | System.evtx |
| Microsoft-Windows-Sysmon/Operational | Microsoft-Windows-Sysmon%4Operational.evtx |

Calculate an approximate retention time period for each log either in minutes, hours, days, weeks, or months.


### Firewall configuration

Verify if Domain, Public, and Private firewall profiles are enabled locally or via GPO.<br>
List all active inbound firewall rules for each profile.

| Information | Artefact |
|-------------|----------|
| Local Domain profile | HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall |
| Local Public profile | HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall |
| Local Private profile | HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall |
| Local rules | HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules |
| GPO Domain profile | HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall |
| GPO Public profile | HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall |
| GPO Private profile | HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall |
| GPO rules | HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules |



### Advanced Audit Policy configuration

Verify Advanced Audit Policy settings from local HKLM\Security hive.<br>
RegRipper tool can be used to parse Advanced Audit Policy configuration from Security registry hive if necessary:
- https://github.com/keydet89/RegRipper3.0

Compare current Advanced Audit Policy configuration against Microsoft System audit policy recommendations documentation:
- Windows Workstation: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations?tabs=winclient
- Windows Server: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations?tabs=winserver
  
User Stronger recommendation settings for the comparison.
