[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $DomainNetbiosName
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string[]] $ClusterNodes
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $SqlServiceAccount
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $SqlServiceAccountPassword
)
# Enables SQL AlwaysOn on nodes in a WSFC cluster. Intended to be executed on
# only one node (typically the last node). Uses Invoke-Command to connect
# remotely to the all nodes.

# Get the PsCredential
Write-Verbose "Creating PSCredential object for ${DomainNetbiosName}\${SqlServiceAccount}"
$Credential = New-Object System.Management.Automation.PSCredential(
    "${DomainNetbiosName}\${SqlServiceAccount}",
    (ConvertTo-SecureString "${SqlServiceAccountPassword}" -AsPlainText -Force)
)

# Configure SQL AlwaysOn Group for Cluster Nodes
Invoke-Command `
    -ComputerName $ClusterNodes `
    -Credential $Credential `
    -ArgumentList @(
        $VerbosePreference,
        $ErrorActionPreference
    ) `
    -ScriptBlock {
        Param(
            $Verbose,
            $ErrorAction
        )
        $VerbosePreference = $Verbose
        $ErrorActionPreference = $ErrorAction
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
        Write-Verbose "Configuring SQL AlwaysOn group on ${Env:ComputerName}"
        Enable-SqlAlwaysOn -ServerInstance "${Env:ComputerName}" -Force
    }
