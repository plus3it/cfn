[CmdLetBinding()]
Param(
    $ServerFQDN,
    $DomainNetBiosName="DICELAB",
    $GroupName="Dicelab Remote Access Users"
    )

#Based on:
# * hhttps://s3.amazonaws.com/app-chemistry/scripts/configure-rdsh.ps1

if (-not $ServerFQDN) {
    $name = invoke-restmethod -uri http://169.254.169.254/latest/meta-data/public-hostname
    if (-not $name) {
        $name = [System.Net.DNS]::GetHostByName('').HostName
    }
    $ServerFQDN = $name 
}

$null = Install-WindowsFeature RDS-RD-Server
$null = Import-Module remotedesktopservices

([ADSI]"WinNT://$env:COMPUTERNAME/Remote Desktop Users,group").Add("WinNT://$DomainNetBiosName/$GroupName,group")

Powershell -command Restart-Computer
