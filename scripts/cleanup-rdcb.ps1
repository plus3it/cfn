[CmdLetBinding()]

#Requires -Modules RemoteDesktop, P3RemoteAccess, P3Utils
#Requires -RunAsAdministrator

Param(
    [Parameter(Mandatory=$true)]
    [String]
    $UpdPath,

    [Parameter(Mandatory=$false)]
    [String]
    $ConnectionBroker = [System.Net.DNS]::GetHostByName('').HostName,

    [Parameter(Mandatory=$false)]
    [String]
    $CollectionName = "RDS Collection"
)
$SessionHosts = Get-RDSessionHost -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -ErrorAction Stop
$TestedSessionHosts = Test-RetryNetConnection -ComputerName $SessionHosts.SessionHost -Verbose:$VerbosePreference

if ($TestedSessionHosts.StaleComputers) {
    Clear-RDSessionHost -SessionHost ($SessionHosts | Where-Object { $_.SessionHost -in $TestedSessionHosts.StaleComputers}) -ConnectionBroker $ConnectionBroker -Verbose:$VerbosePreference
}

$Acl = Get-Acl $UpdPath -ErrorAction Stop

$IdentityReferences = @()
if ($TestedSessionHosts.ValidComputers) {
    $IdentityReferences = $TestedSessionHosts.ValidComputers | ForEach-Object { "${DomainNetBiosName}\{0}$" -f $_.Split(".")[0] }
}

$ValidAcl = Edit-AclIdentityReference -Acl $Acl -IdentityReference $IdentityReferences -Verbose:$VerbosePreference

if ($ValidAcl) {
    Invoke-RetryCommand -Command Set-Acl -ArgList @{Path=$UpdPath; AclObject=$ValidAcl} -CheckExpression '$?' -Verbose:$VerbosePreference
}
