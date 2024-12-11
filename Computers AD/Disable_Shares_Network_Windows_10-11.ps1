# Set registry key and property name
$RegKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
$RegName = 'NC_ShowSharedAccessUI'

# Check if registry key exists
$exists = Test-Path $RegKey

if ($exists) {
    # Cr�er ou modifier la propri�t� NC_ShowSharedAccessUI avec la valeur 0 pour d�sactiver le partage de connexion
    New-ItemProperty -Path $RegKey -Name $RegName -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    # D�commenter la ligne suivante si un red�marrage est n�cessaire pour que la politique prenne effet
    # Restart-Computer -Force
}
else {
    Write-Host "La cl� de registre n'existe pas : $RegKey"
}

#To enable it, simply alter the value from 0 to 1.