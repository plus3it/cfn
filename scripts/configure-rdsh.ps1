[CmdLetBinding()]
Param(
    $ServerFQDN,
    $DomainNetBiosName,
    $GroupName
    )

#Based on:
# * https://s3.amazonaws.com/app-chemistry/scripts/configure-rdsh.ps1

if (-not $ServerFQDN)
{
    try
    {
        $name = invoke-restmethod -uri http://169.254.169.254/latest/meta-data/public-hostname
    }
    catch
    {
        if (-not $name)
        {
            $name = [System.Net.DNS]::GetHostByName('').HostName
        }
    }
    $ServerFQDN = $name
}

$null = Install-WindowsFeature RDS-RD-Server,Search-Service
$null = Import-Module RemoteDesktop

if ($DomainNetBiosName -and $GroupName)
{
    $group = [ADSI]"WinNT://$env:COMPUTERNAME/Remote Desktop Users,group"
    $groupmembers = @(@($group.Invoke("Members")) | `
        foreach {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)})

    if ($groupmembers -notcontains $GroupName)
    {
        $group.Add("WinNT://$DomainNetBiosName/$GroupName,group")
    }
}

Restart-Computer -Force
