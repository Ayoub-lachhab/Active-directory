# Active Directory User Security Audit

A read-only PowerShell script to audit Active Directory user accounts and export a CSV report.

## Features

The report includes:

- Enabled / disabled account status
- Locked-out accounts
- Last logon date and days since last logon
- Inactive-account flag based on a configurable threshold
- Password last-set date and password age
- Password policy-related flags (`PasswordNeverExpires`, `PasswordNotRequired`, `CannotChangePassword`)
- Account expiration date
- Department, title, company, manager, email and telephone
- Account creation/modification dates
- Distinguished Name (OU/location)

## Requirements

- Windows PowerShell 5.1 or later
- RSAT: Active Directory Domain Services and Lightweight Directory Tools
- Network connectivity to a domain controller
- An account with permission to read the required Active Directory attributes

## Usage

Open PowerShell with an account that can read Active Directory.

```powershell
# Default: export to C:\AD-Audit and flag accounts inactive for 90 days
.\Invoke-ADUserAudit.ps1

# Choose an export folder and use a 180-day inactivity threshold
.\Invoke-ADUserAudit.ps1 -ExportPath "D:\Reports\AD" -InactivityThresholdDays 180

# Query a specific domain controller
.\Invoke-ADUserAudit.ps1 -Server "DC01.contoso.local"

# Combine parameters
.\Invoke-ADUserAudit.ps1 `
    -ExportPath "D:\Reports\AD" `
    -InactivityThresholdDays 60 `
    -Server "DC01.contoso.local"
```

The script creates a timestamped CSV file, for example:

`C:\AD-Audit\AD_User_Audit_20261122_143000.csv`

## Important notes

- **Read-only:** the script does not enable, disable, delete, unlock, or otherwise modify accounts.
- **Last logon accuracy:** `LastLogonDate` is based on the replicated `lastLogonTimestamp` attribute. Replication/update intervals mean it can be several days behind. It is suitable for general hygiene reviews, not forensic proof of the exact last logon.
- **Never logged on:** accounts with no recorded `LastLogonDate` are flagged as inactive. Review service, newly created, and special-purpose accounts before taking action.
- **Manager lookup:** unresolved manager references are exported as their distinguished name.
- Protect the CSV report: it contains personal and organizational information. Store it in an access-controlled location and follow your organization's retention policy.

## Parameters

| Parameter | Default | Description |
|---|---:|---|
| `ExportPath` | `C:\AD-Audit` | Output folder for the CSV |
| `InactivityThresholdDays` | `90` | Allowed values: 30, 60, 90, 180 |
| `Server` | Automatic | Optional domain controller FQDN |

## License

MIT. See [LICENSE](LICENSE).
