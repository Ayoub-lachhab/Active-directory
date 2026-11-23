#requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Read-only security audit of effective Domain Admin user accounts.
.DESCRIPTION
    Audits user accounts returned as recursive members of the Domain Admins
    group. Exports CSV and HTML reports. Does not modify Active Directory.
.NOTES
    Run from a domain-joined computer with the ActiveDirectory PowerShell
    module and permission to read the relevant AD attributes.
    LastLogonDate is based on replicated lastLogonTimestamp and is approximate.
    MFA status is not verified by this on-premises AD script.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot ("Reports\{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$domain = Get-ADDomain
$domainAdminsSid = '{0}-512' -f $domain.DomainSID.Value
$protectedUsersSid = '{0}-525' -f $domain.DomainSID.Value

Write-Host "Domain Admin Security Audit" -ForegroundColor Cyan
Write-Host "Domain: $($domain.DNSRoot)"

$members = @(
    Get-ADGroupMember -Identity $domainAdminsSid -Recursive |
        Where-Object { $_.objectClass -eq 'user' }
)

$protectedUserSids = @()
try {
    $protectedUserSids = @(
        Get-ADGroupMember -Identity $protectedUsersSid -Recursive |
            Where-Object { $_.objectClass -eq 'user' } |
            ForEach-Object { $_.SID.Value }
    )
}
catch {
    Write-Warning "Could not read Protected Users membership: $($_.Exception.Message)"
}

$results = foreach ($member in $members) {
    try {
        $user = Get-ADUser -Identity $member.DistinguishedName -Properties @(
            'Enabled', 'LockedOut', 'LastLogonDate', 'PasswordLastSet',
            'PasswordNeverExpires', 'PasswordNotRequired', 'PasswordExpired',
            'AccountExpirationDate', 'adminCount', 'ServicePrincipalName',
            'TrustedForDelegation', 'TrustedToAuthForDelegation',
            'AllowedToDelegateTo', 'DoesNotRequirePreAuth',
            'SmartcardLogonRequired', 'msDS-SupportedEncryptionTypes',
            'msDS-UserPasswordExpiryTimeComputed', 'whenCreated', 'whenChanged',
            'Description', 'Department', 'Title', 'Manager', 'SID'
        )

        $issues = [System.Collections.Generic.List[string]]::new()
        $recommendations = [System.Collections.Generic.List[string]]::new()

        if (-not $user.Enabled) {
            $issues.Add('Account is disabled but remains in Domain Admins')
            $recommendations.Add('Review and remove privileged membership if no longer required')
        }
        if ($user.LockedOut) {
            $issues.Add('Account is currently locked out')
            $recommendations.Add('Investigate the lockout source')
        }
        if ($user.PasswordNeverExpires) {
            $issues.Add('PasswordNeverExpires is enabled')
            $recommendations.Add('Review password policy and privileged-account controls')
        }
        if ($user.PasswordNotRequired) {
            $issues.Add('PasswordNotRequired is enabled')
            $recommendations.Add('Require a password for this account')
        }
        if ($user.PasswordExpired) {
            $issues.Add('Password is expired')
            $recommendations.Add('Verify the account owner and remediate the expired credential')
        }

        if ($null -eq $user.PasswordLastSet) {
            $issues.Add('Password last-set timestamp is unavailable')
        }
        elseif ($user.PasswordLastSet -lt (Get-Date).AddDays(-180)) {
            $issues.Add('Password has not been changed for more than 180 days')
            $recommendations.Add('Review credential age against the organisation policy')
        }

        $passwordExpiry = $null
        $expiryFileTime = $user.'msDS-UserPasswordExpiryTimeComputed'
        if ($null -ne $expiryFileTime -and [Int64]$expiryFileTime -gt 0 -and
            [Int64]$expiryFileTime -lt [Int64]::MaxValue) {
            try { $passwordExpiry = [DateTime]::FromFileTime([Int64]$expiryFileTime) } catch {}
        }

        $daysSinceLogon = $null
        if ($user.LastLogonDate) {
            $daysSinceLogon = [int][math]::Floor(((Get-Date) - $user.LastLogonDate).TotalDays)
            if ($daysSinceLogon -gt 90) {
                $issues.Add('No replicated logon timestamp for more than 90 days')
                $recommendations.Add('Confirm account ownership and business need')
            }
        }
        else {
            $issues.Add('No replicated last-logon timestamp is available')
            $recommendations.Add('Check logon activity on domain controllers before taking action')
        }

        if ($user.TrustedForDelegation) {
            $issues.Add('Unconstrained Kerberos delegation is enabled')
            $recommendations.Add('Review and remove unconstrained delegation where not essential')
        }
        if ($user.TrustedToAuthForDelegation) {
            $issues.Add('Protocol transition delegation is enabled')
            $recommendations.Add('Review the delegation configuration and business justification')
        }
        if (@($user.AllowedToDelegateTo).Count -gt 0) {
            $issues.Add('Kerberos delegation targets are configured')
            $recommendations.Add('Review each configured delegation target')
        }

        if ($user.DoesNotRequirePreAuth) {
            $issues.Add('Kerberos pre-authentication is disabled')
            $recommendations.Add('Enable Kerberos pre-authentication unless a documented exception exists')
        }

        $encryptionTypes = $user.'msDS-SupportedEncryptionTypes'
        $aesConfigured = $null
        if ($null -ne $encryptionTypes -and [int]$encryptionTypes -ne 0) {
            $aesConfigured = (([int]$encryptionTypes -band 0x18) -ne 0)
            if (-not $aesConfigured) {
                $issues.Add('AES Kerberos encryption flags are not present on the account')
                $recommendations.Add('Review Kerberos encryption compatibility before enabling AES')
            }
        }

        $hasSpn = @($user.ServicePrincipalName).Count -gt 0
        if ($hasSpn) {
            $issues.Add('Privileged user account has one or more SPNs')
            $recommendations.Add('Review SPNs; use a dedicated service identity where appropriate')
        }

        $isProtectedUser = $protectedUserSids -contains $user.SID.Value
        if (-not $isProtectedUser) {
            $issues.Add('Account is not a member of Protected Users')
            $recommendations.Add('Evaluate Protected Users compatibility; membership is not suitable for every account')
        }

        $smartcardStatus = if ($user.SmartcardLogonRequired) { 'Required' } else { 'Not required' }
        if (-not $user.SmartcardLogonRequired) {
            $issues.Add('Smart-card logon is not required')
            $recommendations.Add('Consider phishing-resistant authentication for privileged access')
        }

        if ($user.adminCount -ne 1) {
            $issues.Add('adminCount is not 1')
            $recommendations.Add('Review AdminSDHolder/protected-group status; this attribute alone is not conclusive')
        }

        $issueCount = $issues.Count
        $risk = if ($issueCount -ge 5) { 'High' } elseif ($issueCount -ge 2) { 'Medium' } else { 'Low' }

        [PSCustomObject]@{
            Name                    = $user.Name
            SamAccountName          = $user.SamAccountName
            Enabled                 = $user.Enabled
            LockedOut               = $user.LockedOut
            RiskLevel               = $risk
            IssueCount              = $issueCount
            SecurityIssues          = ($issues -join ' | ')
            Recommendations         = ($recommendations -join ' | ')
            LastLogon               = $user.LastLogonDate
            DaysSinceLastLogon      = $daysSinceLogon
            PasswordLastSet         = $user.PasswordLastSet
            PasswordExpiry          = $passwordExpiry
            PasswordNeverExpires    = $user.PasswordNeverExpires
            PasswordNotRequired     = $user.PasswordNotRequired
            PasswordExpired         = $user.PasswordExpired
            AccountExpirationDate   = $user.AccountExpirationDate
            SmartcardRequired       = $smartcardStatus
            ProtectedUsersMember    = $isProtectedUser
            HasSPN                  = $hasSpn
            SPNs                    = (@($user.ServicePrincipalName) -join '; ')
            UnconstrainedDelegation = $user.TrustedForDelegation
            ProtocolTransition      = $user.TrustedToAuthForDelegation
            DelegationTargets       = (@($user.AllowedToDelegateTo) -join '; ')
            KerberosPreAuthDisabled = $user.DoesNotRequirePreAuth
            KerberosEncryptionTypes = $encryptionTypes
            AESConfigured           = $aesConfigured
            AdminCount              = $user.adminCount
            AccountAgeDays          = [int][math]::Floor(((Get-Date) - $user.whenCreated).TotalDays)
            Department              = $user.Department
            Title                   = $user.Title
            Description             = $user.Description
            Manager                 = $user.Manager
            Created                 = $user.whenCreated
            Modified                = $user.whenChanged
            DistinguishedName      = $user.DistinguishedName
        }
    }
    catch {
        Write-Warning "Could not audit '$($member.Name)': $($_.Exception.Message)"
    }
}

$csvPath = Join-Path $OutputPath 'DomainAdmin-Security-Audit.csv'
$htmlPath = Join-Path $OutputPath 'DomainAdmin-Security-Audit.html'

$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$total = @($results).Count
$high = @($results | Where-Object RiskLevel -eq 'High').Count
$medium = @($results | Where-Object RiskLevel -eq 'Medium').Count
$low = @($results | Where-Object RiskLevel -eq 'Low').Count

$rows = foreach ($item in $results) {
    $background = switch ($item.RiskLevel) {
        'High'   { '#f8d7da' }
        'Medium' { '#fff3cd' }
        default  { '#d1e7dd' }
    }
    $name = [System.Net.WebUtility]::HtmlEncode([string]$item.Name)
    $login = [System.Net.WebUtility]::HtmlEncode([string]$item.SamAccountName)
    $issuesText = [System.Net.WebUtility]::HtmlEncode([string]$item.SecurityIssues)
    $recommendationsText = [System.Net.WebUtility]::HtmlEncode([string]$item.Recommendations)

    "<tr style='background:$background'><td>$name</td><td>$login</td><td>$($item.Enabled)</td><td><b>$($item.RiskLevel)</b></td><td>$($item.IssueCount)</td><td>$issuesText</td><td>$recommendationsText</td></tr>"
}

$generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Domain Admin Security Audit</title>
<style>
body{font-family:Arial,sans-serif;margin:28px;background:#f4f6f9;color:#202938}
h1{color:#172b4d}.cards{display:flex;flex-wrap:wrap;gap:14px;margin:20px 0}
.card{background:#fff;padding:16px 22px;border-radius:8px;min-width:110px;box-shadow:0 1px 4px #0001}
.card h2{margin:8px 0 0}table{border-collapse:collapse;width:100%;background:#fff}
th,td{border:1px solid #ddd;padding:9px;text-align:left;vertical-align:top}
th{background:#172b4d;color:#fff} .note{color:#5c6675;font-size:12px;margin-top:20px}
</style>
</head>
<body>
<h1>Domain Admin Security Audit</h1>
<p><b>Domain:</b> $([System.Net.WebUtility]::HtmlEncode($domain.DNSRoot))</p>
<p><b>Generated:</b> $generated</p>
<div class="cards">
<div class="card"><b>Total accounts</b><h2>$total</h2></div>
<div class="card"><b>High risk</b><h2>$high</h2></div>
<div class="card"><b>Medium risk</b><h2>$medium</h2></div>
<div class="card"><b>Low risk</b><h2>$low</h2></div>
</div>
<table>
<thead><tr><th>Name</th><th>Login</th><th>Enabled</th><th>Risk</th><th>Findings</th><th>Security findings</th><th>Recommendations</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody>
</table>
<p class="note">Read-only report. LastLogonDate uses replicated lastLogonTimestamp and may lag. MFA is not verified by this on-premises Active Directory audit. Risk levels are indicative and require administrator review. Protected Users and smart-card recommendations must be checked for compatibility with your environment.</p>
</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host "`n========== AUDIT SUMMARY ==========" -ForegroundColor Cyan
Write-Host "Domain: $($domain.DNSRoot)"
Write-Host "Total accounts: $total"
Write-Host "High risk: $high" -ForegroundColor Red
Write-Host "Medium risk: $medium" -ForegroundColor Yellow
Write-Host "Low risk: $low" -ForegroundColor Green
Write-Host "`nReports generated:"
Write-Host $csvPath -ForegroundColor Green
Write-Host $htmlPath -ForegroundColor Green
