# Set registry key and property name
$RegKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
$RegName = 'NC_ShowSharedAccessUI'

# Check if registry key exists
$exists = Test-Path $RegKey

if ($exists) {
    # Créer ou modifier la propriété NC_ShowSharedAccessUI avec la valeur 0 pour désactiver le partage de connexion
    New-ItemProperty -Path $RegKey -Name $RegName -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    # Décommenter la ligne suivante si un redémarrage est nécessaire pour que la politique prenne effet
    # Restart-Computer -Force
}
else {
    Write-Host "La clé de registre n'existe pas : $RegKey"
}

#To enable it, simply alter the value from 0 to 1.