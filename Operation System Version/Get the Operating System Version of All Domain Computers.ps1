Get-ADComputer -Filter {OperatingSystem -Like "Windows 10*"} -Property Name,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion | 
Select-Object Name,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion | 
Export-Csv -Path "C:\Ordinateurs_Windows10.csv" -NoTypeInformation -Encoding UTF8
