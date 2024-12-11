#Replace "COMPUTERNAME" with the specific name of your computer.

$computer = Get-ADComputer COMPUTERNAME
Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' -SearchBase $computer.DistinguishedName -Properties whenCreated, msFVE-RecoveryPassword | `
  Sort whenCreated -Descending | Select whenCreated, msFVE-RecoveryPassword