Search-ADAccount –AccountInActive –ComputersOnly –TimeSpan 180.00:00:00 –ResultPageSize 2000 –ResultSetSize $null | 
    Where-Object { $_.Enabled -eq $True } | 
    Select-Object Name, SamAccountName, DistinguishedName, LastLogonDate |
    Export-Csv -Path "C:\lastlogon.csv" -NoTypeInformation
