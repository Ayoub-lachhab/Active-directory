# Domain Admin Security Audit

PowerShell read-only audit for user accounts that are effective members of the Active Directory **Domain Admins** group, including users reached through nested group membership.

## Features

- Finds the Domain Admins group by its well-known domain SID (RID 512).
- Enumerates recursive user members.
- Reviews account enabled/locked status and account expiration.
- Reviews password flags, password age and computed password expiry.
- Checks replicated last-logon timestamp and highlights accounts with no recent recorded logon.
- Reviews Kerberos pre-authentication, encryption flags, SPNs and delegation settings.
- Checks Protected Users membership, smart-card requirement and `adminCount`.
- Produces CSV and HTML reports with findings and recommendations.

## Requirements

- Windows PowerShell 5.1 or later.
- Active Directory PowerShell module (RSAT).
- Domain-joined computer or a suitable AD management host.
- Read access to the queried AD attributes.

## Run

Open PowerShell in the folder and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-DomainAdminSecurityAudit.ps1
```

Reports are created automatically in a timestamped folder under `Reports`.

To choose another output location:

```powershell
.\Invoke-DomainAdminSecurityAudit.ps1 -OutputPath "C:\Temp\DomainAdminAudit"
```

## Output

- `DomainAdmin-Security-Audit.csv` — suitable for Excel and further analysis.
- `DomainAdmin-Security-Audit.html` — readable summary with risk levels, findings and recommendations.

## Important limitations

- **Read-only:** the script does not change users, groups, passwords, GPOs or other AD settings.
- `LastLogonDate` is based on replicated `lastLogonTimestamp`; it is approximate and can lag. Verify across domain controllers before disabling or removing an account.
- On-premises AD does not expose cloud MFA enforcement status through this script. MFA is therefore **not verified**.
- Kerberos encryption flags on a user object do not, by themselves, prove which encryption types were negotiated at runtime.
- Protected Users and smart-card controls can affect legacy applications and service compatibility. Treat findings as review prompts, not automatic remediation instructions.
- The risk level is a simple indicator based on the number of findings, not a formal security certification or complete privileged-access assessment.
- `adminCount` can be stale; interpret it with group membership and AdminSDHolder behavior.

Review all findings with the AD/security team before making changes.
