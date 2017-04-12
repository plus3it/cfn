[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $RemoteNodeFqdn
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $RemoteNodeIpAddress
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $WitnessFqdn
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $WitnessIpAddress
    ,
    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [ValidateScript({ $_ -match "^http[s]?://.*\.(zip)$" })]
    [string] $CarbonUrl="https://bitbucket.org/splatteredbits/carbon/downloads/Carbon-2.4.1.zip"
)
# Installs Windows Server Failover Cluster Service and updates the hosts file
# to ensure name resolution for the remote node and the witness server.
# Depends on the PowerShell module, Carbon, for the ability to modify the hosts
# file.

# Static params
$CarbonFile = "${Env:Temp}\carbon.zip"
$CarbonDir = "${Env:Temp}\Carbon"
$PsModuleDir = "${Env:SystemRoot}\system32\WindowsPowerShell\v1.0\Modules\"

# Install Windows features
Write-Verbose "Installing Windows Feature Failover-Clustering"
Install-WindowsFeature Failover-Clustering -IncludeManagementTools

# Download bits
Write-Verbose "Retrieving ${CarbonUrl}"
Start-BitsTransfer -Source "${CarbonUrl}" -Destination "${CarbonFile}" -ErrorAction Stop

# Extract Carbon
$null = Remove-Item -Path "${CarbonDir}" -Recurse -Force -ErrorAction SilentlyContinue
$null = New-Item -Path "${CarbonDir}" -ItemType Directory -Force
$shell = new-object -com shell.application
Write-Verbose "Extracting ${CarbonFile}"
$shell.namespace("${CarbonDir}").copyhere($shell.namespace("${CarbonFile}").items(), 0x14)

# Import Carbon
$null = Remove-Item -Path "${PsModuleDir}\Carbon" -Recurse -Force -ErrorAction SilentlyContinue
$null = Copy-Item "${CarbonDir}\Carbon" "${PsModuleDir}\Carbon" -Recurse -Force
Remove-Module Carbon -ErrorAction SilentlyContinue
Write-Verbose "Importing Carbon module"
Import-Module Carbon

# Add hosts entries for remote node and witness
Write-Verbose "Adding Hosts entry for ${RemoteNodeFqdn}/${RemoteNodeIpAddress}"
Set-HostsEntry -IPAddress "${RemoteNodeIpAddress}" -HostName "${RemoteNodeFqdn}"
Write-Verbose "Adding Hosts entry for ${WitnessFqdn}/${WitnessIpAddress}"
Set-HostsEntry -IPAddress "${WitnessIpAddress}" -HostName "${WitnessFqdn}"
