
#requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Read-only security audit of Domain Admin accounts.
.DESCRIPTION
    Audits effective members of the Domain Admins group.
    Exports CSV and HTML reports. Makes no AD changes.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\DomainAdmin-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)

Import-Module ActiveDirectory -ErrorAction Stop

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$Domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName

Write-Host "Starting Domain Admin Security Audit..." -ForegroundColor Cyan
Write-Host "Domain: $($Domain.DNSRoot)" -ForegroundColor Gray

# Find Domain Admins group using its well-known RID 512
$DomainAdminsSID = "$($Domain.DomainSID.Value)-512"

$DomainAdminsGroup = Get-ADGroup -Identity $DomainAdminsSID

# Retrieve direct and nested members
$Members = Get-ADGroupMember -Identity $DomainAdminsGroup -Recursive |
    Where-Object { $_.objectClass -eq "user" }

# Protected Users group (SID well-known RID 525)
$ProtectedUsersSID = "$($Domain.DomainSID.Value)-525"
$ProtectedUsers = @()

try {
    $ProtectedUsers = Get-ADGroupMember -Identity $ProtectedUsersSID -Recursive |
        Where-Object { $_.objectClass -eq "user" } |
        Select-Object -ExpandProperty SID
}
catch {
    Write-Warning "Could not read Protected Users membership."
}

$ProtectedSIDList = @($ProtectedUsers | ForEach-Object { $_.Value })

$Results = foreach ($Member in $Members) {

    try {
        $User = Get-ADUser -Identity $Member.DistinguishedName -Properties `
            Enabled,LockedOut,LastLogonDate,PasswordLastSet,PasswordNeverExpires, `
            PasswordNotRequired,PasswordExpired,AccountExpirationDate, `
            adminCount,ServicePrincipalName,TrustedForDelegation, `
            TrustedToAuthForDelegation,AllowedToDelegateTo, `
            DoesNotRequirePreAuth,SmartcardLogonRequired, `
            msDS-SupportedEncryptionTypes,msDS-UserPasswordExpiryTimeComputed, `
            whenCreated,whenChanged,Description,Department,Title,Manager, `
            SID,UserAccountControl

        $Issues = [System.Collections.Generic.List[string]]::new()
        $Recommendations = [System.Collections.Generic.List[string]]::new()

        # Account status
        if (-not $User.Enabled) {
            $Issues.Add("Account disabled but still member of Domain Admins")
            $Recommendations.Add("Review and remove unnecessary privileged membership")
        }

        if ($User.LockedOut) {
            $Issues.Add("Account is locked out")
        }

        # Password checks
        if ($User.PasswordNeverExpires) {
            $Issues.Add("PasswordNeverExpires enabled")
            $Recommendations.Add("Apply an appropriate password rotation policy")
        }

        if ($User.PasswordNotRequired) {
            $Issues.Add("PasswordNotRequired enabled")
            $Recommendations.Add("Require a password for this account")
        }

        if ($User.PasswordExpired) {
            $Issues.Add("Password is expired")
        }

        if (-not $User.PasswordLastSet) {
            $Issues.Add("Password last-set date unavailable")
        }
        elseif ($User.PasswordLastSet -lt (Get-Date).AddDays(-180)) {
            $Issues.Add("Password not changed for more than 180 days")
            $Recommendations.Add("Review password age and authentication policy")
        }

        # Password expiration timestamp
        $PasswordExpiry = $null
        if ($User.'msDS-UserPasswordExpiryTimeComputed' -and
            $User.'msDS-UserPasswordExpiryTimeComputed' -lt [Int64]::MaxValue) {

            try {
                $PasswordExpiry = [DateTime]::FromFileTime(
                    [Int64]$User.'msDS-UserPasswordExpiryTimeComputed'
                )
            }
            catch {}
        }

        # Last logon checks (replicated timestamp, may lag)
        $DaysSinceLogon = $null

        if ($User.LastLogonDate) {
            $DaysSinceLogon = [math]::Floor(
                ((Get-Date) - $User.LastLogonDate).TotalDays
            )

            if ($DaysSinceLogon -gt 90) {
                $Issues.Add("No recorded logon for more than 90 days")
                $Recommendations.Add("Validate account ownership and business need")
            }
        }
        else {
            $Issues.Add("No replicated last-logon timestamp available")
        }

        # Delegation checks
        if ($User.TrustedForDelegation) {
            $Issues.Add("Unconstrained Kerberos delegation enabled")
            $Recommendations.Add("Review and disable unconstrained delegation if unnecessary")
        }

        if ($User.TrustedToAuthForDelegation) {
            $Issues.Add("Protocol transition delegation enabled")
            $Recommendations.Add("Review constrained delegation configuration")
        }

        if ($User.AllowedToDelegateTo) {
            $Issues.Add("Kerberos delegation targets configured")
        }

        # Kerberos checks
        if ($User.DoesNotRequirePreAuth) {
            $Issues.Add("Kerberos pre-authentication disabled")
            $Recommendations.Add("Enable Kerberos pre-authentication")
        }

        $EncryptionTypes = $User.'msDS-SupportedEncryptionTypes'
        $AESConfigured = $false

        if ($null -ne $EncryptionTypes) {
            # AES128 = 0x08, AES256 = 0x10
            $AESConfigured = (($EncryptionTypes -band 0x18) -ne 0)
        }

        if ($null -eq $EncryptionTypes -or $EncryptionTypes -eq 0) {
            $Issues.Add("Kerberos encryption types not explicitly configured")
        }
        elseif (-not $AESConfigured) {
            $Issues.Add("AES Kerberos encryption not configured")
            $Recommendations.Add("Review Kerberos encryption compatibility and enable AES")
        }

        # SPN check
        $HasSPN = @($User.ServicePrincipalName).Count -gt 0

        if ($HasSPN) {
            $Issues.Add("Privileged account has Service Principal Names")
            $Recommendations.Add("Review SPNs and consider a dedicated service identity")
        }

        # Privileged account protections
        $IsProtectedUser = $ProtectedSIDList -contains $User.SID.Value

        if (-not $IsProtectedUser) {
            $Issues.Add("Not a member of Protected Users group")
            $Recommendations.Add("Evaluate Protected Users group compatibility")
        }

        if ($User.SmartcardLogonRequired) {
            $SmartcardStatus = "Required"
        }
        else {
            $SmartcardStatus = "Not required"
            $Issues.Add("Smart card logon not required")
            $Recommendations.Add("Consider stronger authentication for privileged accounts")
        }

        if ($User.adminCount -ne 1) {
            $Issues.Add("adminCount is not 1 - review protected account status")
        }

        # Account age
        $AccountAgeDays = [math]::Floor(
            ((Get-Date) - $User.whenCreated).TotalDays
        )

        # Result
        $IssueCount = $Issues.Count

        if ($IssueCount -eq 0) {
            $Risk = "Low"
        }
        elseif ($IssueCount -le 2) {
            $Risk = "Medium"
        }
        else {
            $Risk = "High"
        }

        [PSCustomObject]@{
            Name                    = $User.Name
            SamAccountName          = $User.SamAccountName
            Enabled                 = $User.Enabled
            LockedOut               = $User.LockedOut
            RiskLevel               = $Risk
            IssueCount              = $IssueCount
            SecurityIssues          = ($Issues -join " | ")
            Recommendations         = ($Recommendations -join " | ")
            LastLogon               = $User.LastLogonDate
            DaysSinceLastLogon      = $DaysSinceLogon
            PasswordLastSet         = $User.PasswordLastSet
            PasswordExpiry          = $PasswordExpiry
            PasswordNeverExpires    = $User.PasswordNeverExpires
            PasswordNotRequired     = $User.PasswordNotRequired
            PasswordExpired         = $User.PasswordExpired
            AccountExpirationDate   = $User.AccountExpirationDate
            SmartcardRequired       = $SmartcardStatus
            ProtectedUsersMember    = $IsProtectedUser
            HasSPN                  = $HasSPN
            SPNs                    = ($User.ServicePrincipalName -join "; ")
            UnconstrainedDelegation = $User.TrustedForDelegation
            ProtocolTransition      = $User.TrustedToAuthForDelegation
            DelegationTargets       = ($User.AllowedToDelegateTo -join "; ")
            KerberosPreAuthDisabled = $User.DoesNotRequirePreAuth
            KerberosEncryptionTypes = $EncryptionTypes
            AESConfigured           = $AESConfigured
            AdminCount              = $User.adminCount
            AccountAgeDays          = $AccountAgeDays
            Department              = $User.Department
            Title                   = $User.Title
            Description             = $User.Description
            Manager                 = $User.Manager
            Created                 = $User.whenCreated
            Modified                = $User.whenChanged
            DistinguishedName      = $User.DistinguishedName
        }
    }
    catch {
        Write-Warning "Could not audit $($Member.Name): $_"
    }
}

# Export CSV
$CsvPath = Join-Path $OutputPath "DomainAdmin-Security-Audit.csv"
$Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

# Summary
$Total = @($Results).Count
$High = @($Results | Where-Object RiskLevel -eq "High").Count
$Medium = @($Results | Where-Object RiskLevel -eq "Medium").Count
$Low = @($Results | Where-Object RiskLevel -eq "Low").Count

# HTML report
$HtmlPath = Join-Path $OutputPath "DomainAdmin-Security-Audit.html"

$Rows = $Results | ForEach-Object {
    $Color = switch ($_.RiskLevel) {
        "High"   { "#f8d7da" }
        "Medium" { "#fff3cd" }
        default  { "#d1e7dd" }
    }

    $Name = [System.Net.WebUtility]::HtmlEncode($_.Name)
    $Login = [System.Net.WebUtility]::HtmlEncode($_.SamAccountName)
    $Issues = [System.Net.WebUtility]::HtmlEncode($_.SecurityIssues)
    $Recommendations = [System.Net.WebUtility]::HtmlEncode($_.Recommendations)

    "<tr style='background:$Color'>
        <td>$Name</td>
        <td>$Login</td>
        <td>$($_.Enabled)</td>
        <td><b>$($_.RiskLevel)</b></td>
        <td>$($_.IssueCount)</td>
        <td>$Issues</td>
        <td>$Recommendations</td>
    </tr>"
}

$Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$Html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Domain Admin Security Audit</title>
<style>
body { font-family: Arial; margin: 30px; background: #f4f6f9; color: #222; }
h1 { color: #172b4d; }
.cards { display: flex; gap: 15px; margin: 20px 0; }
.card { background: white; padding: 18px; border-radius: 8px; min-width: 120px; }
table { border-collapse: collapse; width: 100%; background: white; }
th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
th { background: #172b4d; color: white; }
.small { color: #666; font-size: 12px; }
</style>
</head>
<body>
<h1>Domain Admin Security Audit</h1>
<p><b>Domain:</b> $($Domain.DNSRoot)</p>
<p><b>Generated:</b> $Generated</p>

<div class="cards">
<div class="card"><b>Total accounts</b><h2>$Total</h2></div>
<div class="card"><b>High risk</b><h2>$High</h2></div>
<div class="card"><b>Medium risk</b><h2>$Medium</h2></div>
<div class="card"><b>Low risk</b><h2>$Low</h2></div>
</div>

<table>
<thead>
<tr>
<th>Name</th><th>Login</th><th>Enabled</th><th>Risk</th>
<th>Issues</th><th>Security findings</th><th>Recommendations</th>
</tr>
</thead>
<tbody>
$($Rows -join "`n")
</tbody>
</table>

<p class="small">
Read-only audit. LastLogonDate uses the replicated lastLogonTimestamp
and may not reflect the exact last logon time. Risk levels are indicative
and require administrator review. MFA status is not verified by this
on-premises Active Directory audit.
</p>
</body>
</html>
"@

$Html | Out-File -FilePath $HtmlPath -Encoding UTF8

Write-Host "`n========== AUDIT SUMMARY ==========" -ForegroundColor Cyan
Write-Host "Domain: $($Domain.DNSRoot)"
Write-Host "Total accounts: $Total"
Write-Host "High risk: $High" -ForegroundColor Red
Write-Host "Medium risk: $Medium" -ForegroundColor Yellow
Write-Host "Low risk: $Low" -ForegroundColor Green
Write-Host "`nReports generated:"
Write-Host $CsvPath -ForegroundColor Green
Write-Host $HtmlPath -ForegroundColor Green

