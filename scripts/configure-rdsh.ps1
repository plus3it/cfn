[CmdLetBinding()]
Param(
    $ServerFQDN,
    $DomainNetBiosName,
    $GroupName
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
                  
if ($DomainNetBiosName -and $GroupName) {
   $group = [ADSI]"WinNT://$env:COMPUTERNAME/Remote Desktop Users,group"
   $groupmembers = @(@($group.Invoke("Members")) | `
    foreach {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)})

if ($groupmembers -notcontains $GroupName) {
    group.Add("WinNT://$DomainNetBiosName/$GroupName,group")
    
   }

}

Powershell -command Restart-Computer
