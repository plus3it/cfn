[CmdLetBinding()]
Param(
  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $DbHostFqdn,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $DbName,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $DbUser,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $DbPassword,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $RdClientAccessName
)
# Script must be run with a domain credential that has admin privileges on the local system

$RequiredFeatures = @(
    "RDS-Connection-Broker",
    "RDS-RD-Server",
    "RDS-Licensing"
)

# Validate required features are installed
$MissingFeatures = @()
foreach ($Feature in (Get-WindowsFeature $RequiredFeatures))
{
    if (-not $Feature.Installed)
    {
        $MissingFeatures += $Feature.Name
    }
}
if ($MissingFeatures)
{
    throw "Missing required Windows features: $($MissingFeatures -join ',')"
}

# Validate availability of RDS Licensing configuration
$null = Import-Module RemoteDesktop,RemoteDesktopServices -Verbose:$false
$TestPath = "RDS:\LicenseServer"
if (-not (Get-ChildItem $TestPath -ErrorAction SilentlyContinue))
{
    throw "System needs to reboot to create the path: ${TestPath}"
}

# Get the system name
$SystemName = [System.Net.DNS]::GetHostByName('').HostName

if (-not $RdClientAccessName)
{
    $RdClientAccessName = $SystemName
}

# Create RD Session Deployment
if (-not (Get-RDServer -ConnectionBroker $SystemName -ErrorAction SilentlyContinue))
{
    New-RDSessionDeployment -ConnectionBroker $SystemName -SessionHost $SystemName
    Write-Verbose "Created the RD Session Deployment!"
}
else
{
    Write-Warning "RD Session Deployment already exists, skipping"
}

# Configure RDCB HA
$RdcbDatabaseConnectionStringParts = @(
    "Driver={ODBC Driver 13 for SQL Server}",
    "Server=tcp:${DbHostFqdn},1433",
    "Database=${DbName}",
    "Uid=${DbUser}",
    "Pwd={${DbPassword}}",
    "Connection Timeout=30"
)
$RdcbDatabaseConnectionString = $RdcbDatabaseConnectionStringParts -join ";"

if (-not (Get-RDConnectionBrokerHighAvailability -ConnectionBroker $SystemName -ErrorAction SilentlyContinue))
{
    Set-RDConnectionBrokerHighAvailability -ConnectionBroker $SystemName -DatabaseConnectionString $RdcbDatabaseConnectionString -ClientAccessName $RdClientAccessName
    if (-not (Get-RDConnectionBrokerHighAvailability -ConnectionBroker $SystemName -ErrorAction SilentlyContinue))
    {
        throw "Failed to configure RD Connection Broker High Availability!"
    }
    else
    {
        Write-Verbose "Configured RD Connection Broker High Availability!"
    }
}
else
{
    Write-Warning "RD Connection Broker High Availability already configured, skipping"
}

# Configure RDS Licensing
Set-Item -path RDS:\LicenseServer\Configuration\Firstname -value "End" -Force
Set-Item -path RDS:\LicenseServer\Configuration\Lastname -value "User" -Force
Set-Item -path RDS:\LicenseServer\Configuration\Company -value "Company" -Force
Set-Item -path RDS:\LicenseServer\Configuration\CountryRegion -value "United States" -Force
$ActivationStatus = Get-Item -Path RDS:\LicenseServer\ActivationStatus
if ($ActivationStatus.CurrentValue -eq 0)
{
    Set-Item -Path RDS:\LicenseServer\ActivationStatus -Value 1 -ConnectionMethod AUTO -Reason 5 -ErrorAction Stop
}
$obj = gwmi -namespace "Root/CIMV2/TerminalServices" Win32_TerminalServiceSetting
$null = $obj.SetSpecifiedLicenseServerList("localhost")
$null = $obj.ChangeMode(2)

Write-Verbose "Configured RD Licensing!"
Write-Verbose "configure-rdcb.ps1 complete!"
