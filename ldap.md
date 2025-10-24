> Use these LDAP filters with `Get-ADUser -LDAPFilter "<filter>"`, `Get-ADObject -LDAPFilter "<filter>"`, `dsquery * -filter "<filter>" -limit 0`, `ldapsearch -b "DC=domain,DC=com" "<filter>"`, `ldifde -r "<filter>"`, etc.

---

## Basic object classes
- `(objectClass=user)` — All user objects  
- `(objectClass=computer)` — All computer objects  
- `(objectClass=group)` — All groups  
- `(objectClass=organizationalUnit)` — OUs

## Presence / attribute exists
- `(mail=*)` — Objects with an email address  
- `(servicePrincipalName=*)` — Accounts that have SPNs (service accounts)  
- `(memberOf=*)` — Objects that are members of at least one group  
- `(msDS-AllowedToDelegateTo=*)` — Objects with constrained-delegation targets

## Wildcard / substring searches
- `(cn=Alex*)` — CN starts with "Alex"  
- `(sAMAccountName=*admin*)` — sAMAccountName contains "admin"  
- `(displayName=*John*)` — displayName contains "John"

## Exact match
- `(sAMAccountName=jdoe)` — Exact sAMAccountName match

## Bitwise / boolean checks (userAccountControl)
> Use OID `1.2.840.113556.1.4.803` for bitwise tests.
- `(userAccountControl:1.2.840.113556.1.4.803:=2)` — Disabled accounts  
- `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` — Enabled accounts (NOT disabled)  
- `(userAccountControl:1.2.840.113556.1.4.803:=65536)` — Password never expires (bit test)

## Delegation & Kerberos-related
- `(TrustedForDelegation=TRUE)` — Unconstrained delegation (legacy attribute)  
- `(msDS-AllowedToActOnBehalfOfOtherIdentity=*)` — Resource-based constrained delegation targets  
- `(servicePrincipalName=*)` — SPN-bearing accounts (Kerberos targets)

## Privileged / admin discovery
- `(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com)` — Members of Domain Admins (use correct DN)  
- `(adminCount=1)` — Accounts marked as administrative by ACL protection  
- `(primaryGroupID=512)` — Objects with primaryGroupID 512 (typical for domain users in some contexts)

## Activity / logon related
- `(lastLogonTimestamp>=1)` — Objects with a lastLogonTimestamp present (use carefully)  
- `(|(lastLogonTimestamp>=<timestamp>)(lastLogon>=<timestamp>))` — Combine attributes to find recent logons (tool dependent)

## Complex combinations (examples)
- `(& (objectClass=user) (mail=*) (!(userAccountControl:1.2.840.113556.1.4.803:=2)))`  
  Enabled users with email addresses.

- `(| (servicePrincipalName=*) (memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com))`  
  Users that have SPNs OR are Domain Admins.
