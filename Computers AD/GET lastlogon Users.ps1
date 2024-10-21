Search-ADAccount –AccountInActive –UsersOnly –TimeSpan 180.00:00:00 –ResultPageSize 2000 –ResultSetSize $null | 
    Where-Object { $_.Enabled -eq $True } | 
    Get-ADUser -Properties LastLogonDate |
    Select-Object Name, SamAccountName, DistinguishedName, LastLogonDate |
    Export-Csv -Path "C:\lastLogon-user.csv" -NoTypeInformation
