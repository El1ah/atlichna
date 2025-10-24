## 1. Domain Discovery

| Command | Description |
|----------|--------------|
| `Import-Module ActiveDirectory` | Imports the Active Directory PowerShell module. |
| `Get-ADDomain` | Displays information about the current AD domain (SID, functional level, DCs). |
| `Get-ADForest` | Displays forest-wide information, including trusts. |
| `nltest /dclist:domain` | Lists all domain controllers. |
| `nltest /dsgetdc:domain` | Finds a domain controller or global catalog server. |

> If the AD module is missing:
> ```powershell
> Add-WindowsFeature RSAT-AD-PowerShell
> # or (on Windows 10/11)
> Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
> ```

---

## 2. User, Group, and Computer Enumeration

| Command | Description |
|----------|--------------|
| `Get-ADUser -Filter * -Properties Name,SamAccountName,EmailAddress,LastLogonDate` | Lists all users and their basic attributes. |
| `Get-ADGroup -Filter *` | Lists all domain groups. |
| `Get-ADGroupMember -Identity "Domain Admins"` | Shows members of the Domain Admins group. |
| `net user /domain` | Lists domain users (CMD version). |
| `Get-ADComputer -Filter *` | Lists domain computers and OS information. |
| `net view \\target-machine` | Displays shared folders on a target machine. |
| `net localgroup` | Lists all local groups. |
| `net localgroup "Administrators"` | Lists members of the local Administrators group. |

---

## 3. Kerberos and SPN Enumeration

| Command | Description |
|----------|--------------|
| `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` | Finds accounts with SPNs (useful for Kerberos research). |
| `klist` | Displays Kerberos ticket cache information. |

---

## 4. AD Replication and Domain Controller Info

| Command | Description |
|----------|--------------|
| `repadmin /replsummary` | Summarizes replication status. |
| `repadmin /showrepl` | Shows detailed replication info per DC. |

---

## 5. GPO and Policy Enumeration

| Command | Description |
|----------|--------------|
| `Get-GPO -All` | Lists all Group Policy Objects. |
| `Get-GPResultantSetOfPolicy -User domain\username -ReportType Html -Path C:\gporeport.html` | Generates a GPO report for a user. |
| `gpresult /r /SCOPE COMPUTER` | Displays applied GPOs for the computer. |

---

## 6. Event Logs and Local Audit

| Command | Description |
|----------|--------------|
| `Get-EventLog -LogName Security -Newest 100` | Displays the last 100 security events. |
| `wevtutil qe Security /c:100 /f:text` | Reads the latest 100 Security events in text format. |

---

## 7. Network and Infrastructure Info

| Command | Description |
|----------|--------------|
| `ipconfig /all` | Displays network adapter settings. |
| `nltest /dsgetsite` | Shows the site associated with the computer. |
| `Get-DnsServerZone` | Lists DNS zones (requires permissions). |
| `Get-DnsServerResourceRecord -ZoneName "domain.local"` | Lists DNS records in a specific zone. |
| `(Get-CimInstance Win32_OperatingSystem).OSArchitecture` | Displays OS architecture (x64/x86). |

---

## 8. Privileges and Delegation Checks

| Command | Description |
|----------|--------------|
| `Get-ADUser -Filter {TrustedForDelegation -eq $true}` | Finds accounts with delegation enabled. |
| `Get-ADComputer -Filter {TrustedForDelegation -eq $true}` | Lists computers allowed for delegation. |
| `Get-ADUser -Filter {AdminCount -eq 1}` | Lists administrative accounts. |

---

## 9. Password Policy and LAPS

| Command | Description |
|----------|--------------|
| `Find-AdmPwdExtendedRights -Identity "OU=Computers,DC=domain,DC=com"` | Checks LAPS permissions. |
| `Get-ADDefaultDomainPasswordPolicy` | Displays the default password policy. |
| `Get-ADFineGrainedPasswordPolicy` | Displays fine-grained password policies. |

---

## 10. Registry, Services, and Tasks (Read-Only Checks)

| Command | Description |
|----------|--------------|
| `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Lists auto-start programs. |
| `schtasks /query /s target-machine` | Lists scheduled tasks on a remote machine. |
| `sc \\target-machine query` | Lists services on a remote system. |

---

## 11. Useful Windows Admin Tools

| Command | Description |
|----------|--------------|
| `net localgroup Administrators` | Lists local administrators. |
| `net group "Domain Admins" /domain` | Lists domain administrators. |
| `quser /server:ComputerName` | Shows logged-in users on a remote system. |
| `qwinsta /server:DCName` | Displays user sessions on a remote system. |
| `vssadmin list shadows` | Lists existing shadow copies. |

---

## 12. Sysinternals Utilities

| Tool | Description |
|-------|-------------|
| `PsExec \\target cmd` | Run a remote shell on a target system. |
| `PsLoggedOn \\target` | Show who is logged on to a system. |
| `AccessChk -uws "DOMAIN\user"` | Check user or group access rights. |
| `PsInfo \\target` | Get detailed system info remotely. |
| `PsService \\target query` | List and control services on a remote system. |

---

## 13. PowerShell Remoting and Credentials

### PowerShell Remoting
```powershell
Enable-PSRemoting -Force
Enter-PSSession -ComputerName Server01 -Credential (Get-Credential)
Invoke-Command -ComputerName Server01 -ScriptBlock { Get-Service }
```

### Secure Credential Variables
```powershell
$Password = Read-Host "Enter Password" -AsSecureString
$Cred = New-Object System.Management.Automation.PSCredential ("DOMAIN\User", $Password)
Enter-PSSession -ComputerName Server01 -Credential $Cred
```
