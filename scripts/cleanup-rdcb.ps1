[CmdLetBinding()]

#Requires -Modules RemoteDesktop, P3RemoteAccess, P3Utils
#Requires -RunAsAdministrator

Param(
    [Parameter(Mandatory=$true)]
    [String]
    $UpdPath,

    [Parameter(Mandatory=$true)]
    [String]
    $DomainNetbiosName,

    [Parameter(Mandatory=$false)]
    [String]
    $ConnectionBroker = [System.Net.DNS]::GetHostByName('').HostName,

    [Parameter(Mandatory=$false)]
    [String]
    $CollectionName = "RDS Collection"
)

# Create a lock before doing work on the connection broker (a shared resource)
$LockFile = "${UpdPath}\cleanup-rdcb-${ConnectionBroker}.lock".ToLower()
$Lock = $false

# Get an exclusive lock on the lock file
Write-Verbose "Attempting to create exclusive lock on ${LockFile}"
while (-not $Lock) {
    try {
        $Lock = [System.IO.File]::Open($LockFile, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        Write-Verbose "Established lock!"
    }
    catch {
        # Sleep for 3 to 20 seconds - randomized to keep from hammering
        $Sleep = Get-Random -Minimum 3 -Maximum 20
        Write-Verbose "Detected existing lock, retrying in $Sleep seconds"
        $Sleep | Start-Sleep
    }
}

try {

    $SessionHosts = Get-RDSessionHost -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -ErrorAction Stop
    $TestedSessionHosts = Test-RetryNetConnection -ComputerName $SessionHosts.SessionHost -Verbose:$VerbosePreference

    if ($TestedSessionHosts.StaleComputers) {
        Clear-RDSessionHost -SessionHost ($SessionHosts | Where-Object { $_.SessionHost -in $TestedSessionHosts.StaleComputers}) -ConnectionBroker $ConnectionBroker -Verbose:$VerbosePreference
    }

    $Acl = Get-Acl $UpdPath -ErrorAction Stop

    $IdentityReferences = @()
    if ($TestedSessionHosts.ValidComputers) {
        $IdentityReferences = $TestedSessionHosts.ValidComputers | ForEach-Object { "${DomainNetbiosName}\{0}$" -f $_.Split(".")[0] }
    }

    $ValidAcl = Edit-AclIdentityReference -Acl $Acl -IdentityReference $IdentityReferences -Verbose:$VerbosePreference

    if ($ValidAcl) {
        Invoke-RetryCommand -Command Set-Acl -ArgList @{Path=$UpdPath; AclObject=$ValidAcl} -CheckExpression '$?' -Verbose:$VerbosePreference
    }
} catch {
    Write-Verbose $PSItem.ToString()
    $PSCmdlet.ThrowTerminatingError($PSitem)
} finally {
    # Release the lock on the shared resource
    $Lock.Close()
    Write-Verbose "Released lock on ${LockFile}"
}
