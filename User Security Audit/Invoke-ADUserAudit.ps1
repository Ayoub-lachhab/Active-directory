<#
.SYNOPSIS
    Generates a read-only security and hygiene audit of Active Directory user accounts.

.DESCRIPTION
    Exports selected user-account attributes to a timestamped CSV file.
    The script does not modify Active Directory.

.PARAMETER ExportPath
    Folder where the CSV report will be saved. Default: C:\AD-Audit

.PARAMETER InactivityThresholdDays
    Number of days after which an account is considered inactive.
    Allowed values: 30, 60, 90, 180. Default: 90.

.PARAMETER Server
    Optional domain controller to query. If omitted, AD module discovery is used.

.EXAMPLE
    .\Invoke-ADUserAudit.ps1

.EXAMPLE
    .\Invoke-ADUserAudit.ps1 -ExportPath "D:\Reports\AD" -InactivityThresholdDays 180

.EXAMPLE
    .\Invoke-ADUserAudit.ps1 -Server "DC01.contoso.local"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportPath = 'C:\AD-Audit',

    [Parameter()]
    [ValidateSet(30, 60, 90, 180)]
    [int]$InactivityThresholdDays = 90,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server
)

$ErrorActionPreference = 'Stop'

try {
    # Verify and load the ActiveDirectory module.
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "The ActiveDirectory PowerShell module is not installed. Install RSAT: Active Directory Domain Services tools."
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    # Build common parameters for AD cmdlets.
    $adParams = @{}
    if ($PSBoundParameters.ContainsKey('Server')) {
        $adParams['Server'] = $Server
    }

    # Resolve domain information.
    $domain = Get-ADDomain @adParams
    $domainController = if ($Server) { $Server } else { (Get-ADDomainController -Discover -Service PrimaryDC).HostName }

    # Ensure export directory exists.
    if (-not (Test-Path -LiteralPath $ExportPath)) {
        New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
    }

    $now = Get-Date
    $thresholdDate = $now.AddDays(-$InactivityThresholdDays)

    Write-Host "Collecting user accounts from $($domain.DNSRoot)..." -ForegroundColor Cyan

    $properties = @(
        'Enabled',
        'LockedOut',
        'LastLogonDate',
        'PasswordLastSet',
        'PasswordNeverExpires',
        'PasswordNotRequired',
        'CannotChangePassword',
        'AccountExpirationDate',
        'whenCreated',
        'whenChanged',
        'Department',
        'Title',
        'Company',
        'Manager',
        'mail',
        'telephoneNumber',
        'Description',
        'DistinguishedName'
    )

    $users = Get-ADUser -Filter * -Properties $properties @adParams

    $report = foreach ($user in $users) {
        $lastLogon = $user.LastLogonDate
        $daysSinceLogon = if ($lastLogon) {
            [int][Math]::Floor(($now - $lastLogon).TotalDays)
        } else {
            $null
        }

        $inactive = if ($lastLogon) {
            $lastLogon -lt $thresholdDate
        } else {
            $true
        }

        $passwordAgeDays = if ($user.PasswordLastSet) {
            [int][Math]::Floor(($now - $user.PasswordLastSet).TotalDays)
        } else {
            $null
        }

        $managerName = $null
        if ($user.Manager) {
            try {
                $managerName = (Get-ADUser -Identity $user.Manager @adParams).SamAccountName
            } catch {
                $managerName = $user.Manager
            }
        }

        [PSCustomObject]@{
            SamAccountName          = $user.SamAccountName
            UserPrincipalName       = $user.UserPrincipalName
            DisplayName             = $user.Name
            Enabled                 = $user.Enabled
            AccountStatus           = if ($user.Enabled) { 'Enabled' } else { 'Disabled' }
            LockedOut               = $user.LockedOut
            Inactive                = $inactive
            InactivityThresholdDays = $InactivityThresholdDays
            LastLogonDate           = $lastLogon
            DaysSinceLastLogon      = $daysSinceLogon
            PasswordLastSet         = $user.PasswordLastSet
            PasswordAgeDays         = $passwordAgeDays
            PasswordNeverExpires    = $user.PasswordNeverExpires
            PasswordNotRequired     = $user.PasswordNotRequired
            CannotChangePassword    = $user.CannotChangePassword
            AccountExpirationDate   = $user.AccountExpirationDate
            Department              = $user.Department
            Title                   = $user.Title
            Company                 = $user.Company
            Manager                 = $managerName
            Email                   = $user.mail
            Telephone               = $user.telephoneNumber
            Description             = $user.Description
            Created                 = $user.whenCreated
            Modified                = $user.whenChanged
            DistinguishedName       = $user.DistinguishedName
        }
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $filePath = Join-Path -Path $ExportPath -ChildPath "AD_User_Audit_$timestamp.csv"

    $report |
        Sort-Object -Property SamAccountName |
        Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8

    $totalUsers = @($report).Count
    $enabledUsers = @($report | Where-Object Enabled).Count
    $disabledUsers = @($report | Where-Object { -not $_.Enabled }).Count
    $inactiveUsers = @($report | Where-Object Inactive).Count
    $lockedUsers = @($report | Where-Object LockedOut).Count

    Write-Host ''
    Write-Host 'Active Directory User Audit completed.' -ForegroundColor Green
    Write-Host "Domain:          $($domain.DNSRoot)"
    Write-Host "Domain controller: $domainController"
    Write-Host "Total users:     $totalUsers"
    Write-Host "Enabled users:   $enabledUsers"
    Write-Host "Disabled users:  $disabledUsers"
    Write-Host "Inactive users:  $inactiveUsers"
    Write-Host "Locked accounts: $lockedUsers"
    Write-Host "CSV report:      $filePath" -ForegroundColor Yellow
}
catch {
    Write-Error "AD User Audit failed: $($_.Exception.Message)"
    exit 1
}
