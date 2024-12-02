# Import the CSV file with the list of computers
$computers = Import-Csv -Path "c:\computerList.csv"

# Specify the target OU
$targetOU = "OU=Computer,OU=Ordinateurs,DC=domaine,DC=com"

# Loop through each computer in the CSV and move it to the specified OU
foreach ($computer in $computers) {
    try {
        # Get the computer object in Active Directory
        $computerObject = Get-ADComputer -Identity $computer.ComputerName

        # Move the computer to the new OU
        Move-ADObject -Identity $computerObject.DistinguishedName -TargetPath $targetOU

        Write-Host "Successfully moved $($computer.ComputerName) to $targetOU"
    } catch {
        Write-Host "Failed to move $($computer.ComputerName): $_"
    }
}
