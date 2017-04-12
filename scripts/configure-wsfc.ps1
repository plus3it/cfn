[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $DomainNetbiosName
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $ClusterName
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $Node1Fqdn
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $Node2Fqdn
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $Node1ClusterIp
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $Node2ClusterIp
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $WitnessFqdn
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $SqlServiceAccount
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $SqlServiceAccountPassword
    ,
    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [ValidateScript({ $_ -match "^http[s]?://.*\.(zip)$" })]
    [string] $PsToolsUrl="https://download.sysinternals.com/files/PSTools.zip"
)
# Creates a new Windows Server Failover Cluster. Intended to run non-
# interactively as the system account on a single node in the cluster. This
# introduces a problem, as the New-Cluster commandlet requires permissions to
# the remote node and to the domain. Nor does the New-Cluster commandlet support
# being run via the built-in Invoke-Command, which accepts a credential object.
# The workaround in this script uses PSExec to launch a powershell process as
# the SQL Service Account, which will need permissions to create the cluster for
# this approach to work.

# Static params
$PsToolsFile = "${Env:Temp}\pstools.zip"
$PsToolsDir = "${Env:Temp}\PSTools"
$PsExec = "${PsToolsDir}\PsExec.exe"

# Download bits
Write-Verbose "Retrieving ${PsToolsUrl}"
Start-BitsTransfer -Source "${PsToolsUrl}" -Destination "${PsToolsFile}" -ErrorAction Stop

# Extract PSTools
$null = Remove-Item -Path "${PsToolsDir}" -Recurse -Force -ErrorAction SilentlyContinue
$null = New-Item -Path "${PsToolsDir}" -ItemType Directory -Force
$shell = new-object -com shell.application
Write-Verbose "Extracting ${PsToolsFile}"
$shell.namespace("${PsToolsDir}").copyhere($shell.namespace("$PsToolsFile").items(), 0x14)

# Create failover cluster
$PsExecArguments = @(
    "-accepteula"
    "-nobanner"
    "-h"
    "-u `"${DomainNetbiosName}\${SqlServiceAccount}`""
    "-p `"${SqlServiceAccountPassword}`""
    "powershell.exe"
    "-Command"
    "New-Cluster -Name `"${ClusterName}`" -Node `"${Node1Fqdn}`",`"${Node2Fqdn}`" -StaticAddress `"${Node1ClusterIp}`",`"${Node2ClusterIp}`""
)
Write-Verbose "Creating failover cluster"
$ret = Start-Process -FilePath "${PsExec}" -ArgumentList $PsExecArguments -NoNewWindow -PassThru -Wait

# Test the return
if ($ret.ExitCode -ne "0")
{
    throw "WSFC failed to configure cluster! Exit code was $($ret.ExitCode)"
}
else
{
    Write-Verbose "Cluster created!"
}

# Set cluster quorum
$Credential = New-Object System.Management.Automation.PSCredential(
    "${DomainNetbiosName}\${SqlServiceAccount}",
    (ConvertTo-SecureString "${SqlServiceAccountPassword}" -AsPlainText -Force)
)
Write-Verbose "Setting the cluster quorum to \\${WitnessFqdn}\witness"
Invoke-Command `
    -ComputerName "${Node2Fqdn}" `
    -Credential $Credential `
    -ArgumentList @(
        $WitnessFqdn,
        $VerbosePreference,
        $ErrorActionPreference
    ) `
    -Scriptblock {
        Param(
            $WitnessFqdn,
            $Verbose,
            $ErrorAction
        )
        $VerbosePreference = $Verbose
        $ErrorActionPreference = $ErrorAction
        Set-ClusterQuorum -NodeAndFileShareMajority "\\${WitnessFqdn}\witness"
    }
