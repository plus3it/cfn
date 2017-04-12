[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $DomainNetbiosName
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $SqlAdminGroup
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $SqlServiceAccount
    ,
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $SqlServiceAccountPassword
    ,
    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [string] $SqlProductKey
    ,
    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [ValidateScript({ $_ -match "^http[s]?://.*\.(iso)$" })]
    [string] $SqlIsoUrl="http://download.microsoft.com/download/3/B/D/3BD9DD65-D3E3-43C3-BB50-0ED850A82AD5/SQLServer2012SP1-FullSlipstream-ENU-x64.iso"
    ,
    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [ValidateScript({ $_ -match "^http[s]?://.*\.(zip)$" })]
    [string] $SourcesSxsUrl
)
# Installs SQL Server Enterprise Edition and opens the required ports in the
# firewall.

# Static params
$SqlIsoFile = "${Env:Temp}\sqlinstall.iso"
$SourcesSxsFile = "${Env:Temp}\sources-sxs.zip"
$SourcesDir = "${Env:SystemDrive}\Sources"

# Define required SQL firewall rules for an AlwaysOn cluster
$SqlFirewallRuleObjects = @(
    @{
        Name = "SQL Server"
        DisplayName = "SQL Server"
        Description = "Allow inbound SQL Client connections"
        Protocol = "TCP"
        Enabled = "True"
        Profile = "Any"
        Action = "Allow"
        LocalPort = "1433"
    },
    @{
        Name = "SQL Admin Connection"
        DisplayName = "SQL Admin Connection"
        Description = "Allow inbound SQL Admin connections"
        Protocol = "TCP"
        Enabled = "True"
        Profile = "Any"
        Action = "Allow"
        LocalPort = "1434"
    },
    @{
        Name = "SQL Service Broker"
        DisplayName = "SQL Service Broker"
        Description = "Allow inbound SQL Service Broker connections"
        Protocol = "TCP"
        Enabled = "True"
        Profile = "Any"
        Action = "Allow"
        LocalPort = "4022"
    },
    @{
        Name = "SQL AlwaysOn TCPIP End Point"
        DisplayName = "SQL AlwaysOn TCPIP End Point"
        Description = "Allow inbound SQL AlwaysOn TCPIP End Point"
        Protocol = "TCP"
        Enabled = "True"
        Profile = "Any"
        Action = "Allow"
        LocalPort = "5022"
    },
    @{
        Name = "SQL AlwaysOn AG Listener"
        DisplayName = "SQL AlwaysOn AG Listener"
        Description = "Allow inbound SQL AlwaysOn AG Listener"
        Protocol = "TCP"
        Enabled = "True"
        Profile = "Any"
        Action = "Allow"
        LocalPort = "5023"
    },
    @{
        Name = "SQL Transact-SQL Debugger"
        DisplayName = "SQL Transact-SQL Debugger"
        Description = "Allow inbound SQL Transact-SQL Debugger"
        Protocol = "TCP"
        Enabled = "True"
        Profile = "Any"
        Action = "Allow"
        LocalPort = "135"
    }
)

# Install Windows features
if ( "${SourcesSxsUrl}" )
{
    # Download sources
    Write-Verbose "Retrieving ${SourcesSxsUrl}"
    Start-BitsTransfer -Source "${SourcesSxsUrl}" -Destination "${SourcesSxsFile}" -ErrorAction Stop

    # Extract sources
    $null = Remove-Item -Path "${SourcesDir}\SxS" -Recurse -Force -ErrorAction SilentlyContinue
    $null = New-Item -Path "${SourcesDir}" -ItemType Directory -Force
    $shell = new-object -com shell.application
    Write-Verbose "Extracting ${SourcesSxsFile}"
    $shell.namespace($SourcesDir).copyhere($shell.namespace("$SourcesSxsFile").items(), 0x14)

    # Install Feature
    Write-Verbose "Installing Windows Feature NET-Framework-Core"
    Install-WindowsFeature NET-Framework-Core -Source "${SourcesDir}\SxS"
}
else
{
    Write-Verbose "Installing Windows Feature NET-Framework-Core"
    Install-WindowsFeature NET-Framework-Core
}

# Download bits
Write-Verbose "Retrieving ${SqlIsoUrl}"
Start-BitsTransfer -Source "${SqlIsoUrl}" -Destination "${SqlIsoFile}" -ErrorAction Stop

# Create Firewall rules
Write-Verbose "Adding firewall rules"
$SqlFirewallRuleObjects | % {
    Try
    {
        New-NetFirewallRule @_ -ErrorAction Stop
    }
    Catch [Microsoft.Management.Infrastructure.CimException]
    {
        # 11 is rule already exists; not a fatal error
        if ($_.Exception.StatusCode -ne "11")
        {
            # Any statuscode other than 11 is fatal
            throw $_
        }
    }
}

# Add SQL service account as a local admin
$group = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
$groupmembers = @( @( $group.Invoke("Members") ) | foreach {
        $_.GetType().InvokeMember("Name",
        "GetProperty", $null, $_, $null)
      });
if ( $groupmembers -notcontains "${SqlServiceAccount}" )
      {
        try
        {
          Write-Verbose "Adding ${DomainNetbiosName}/${SqlServiceAccount} as a local administrator"
          $group.Add("WinNT://${DomainNetbiosName}/${SqlServiceAccount},group")
        }
        catch
        {
          throw "Failed to add [${SqlServiceAccount}] as a local administrator.`n$Error[0]"
        }
      }

# Mount the SQL iso
Write-Verbose "Mounting the iso file, ${SqlIsoFile}"
$mount = Mount-DiskImage -ImagePath "${SqlIsoFile}" -PassThru
$drive = ($mount | Get-Volume).DriveLetter
Write-Verbose "Drive letter is ${drive}"

# Define SQL Install Arguments
$SqlInstallArguments = @(
    "/Q"
    "/Action=Install"
    "/Features=SQLEngine,Replication,FullText,AS,IS,Conn,BC,BOL,ADV_SSMS"
    "/INSTANCENAME=MSSQLSERVER"
    "/SQLSYSADMINACCOUNTS=`"${DomainNetbiosName}\${SqlAdminGroup}`""
    "/ASSYSADMINACCOUNTS=`"${DomainNetbiosName}\${SqlAdminGroup}`""
    "/SQLUSERDBDIR=`"D:\MSSQL\DATA`""
    "/SQLUSERDBLOGDIR=`"E:\MSSQL\LOG`""
    "/SQLBACKUPDIR=`"F:\MSSQL\Backup`""
    "/SQLTEMPDBDIR=`"F:\MSSQL\TempDB`""
    "/SQLTEMPDBLOGDIR=`"F:\MSSQL\TempDB`""
    "/IACCEPTSQLSERVERLICENSETERMS"
)

# Add the SQL product key, if specified
if ($SqlProductKey)
{
    $SqlInstallArguments += "/PID=`"${SqlProductKey}`""
}

# Install SQL
Write-Verbose "Beginning MS SQL Server install"
$ret = Start-Process -FilePath "${drive}:\Setup.exe" -ArgumentList $SqlInstallArguments -NoNewWindow -PassThru -Wait

# Test the return
if ($ret.ExitCode -ne 0)
{
    throw "SQL install failed! Exit code was $($ret.ExitCode)"
}
else
{
    Write-Verbose "SQL install complete!"
}

# Unmount the SQL ISO
Write-Verbose "Unmounting iso file, ${SqlIsoFile}"
DisMount-DiskImage -ImagePath "${SqlIsoFile}"

# Set services to use the service account
$ServiceNames = @("MSSQLSERVER","SQLSERVERAGENT","MSSQLServerOLAPService")
[reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")
$ManagedComputer = New-Object Microsoft.SQLServer.Management.SMO.WMI.ManagedComputer
foreach ($ServiceName in $ServiceNames)
{
    Write-Verbose "Setting $ServiceName to start as ${DomainNetbiosName}\${SqlServiceAccount}"
    $Service = $ManagedComputer.Services["${ServiceName}"]
    $Service.SetServiceAccount(
        "${DomainNetbiosName}\${SqlServiceAccount}",
        "${SqlServiceAccountPassword}"
    )
    $Service.Alter()
}
