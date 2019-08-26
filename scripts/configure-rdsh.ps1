[CmdLetBinding()]
Param(
  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $DomainNetBiosName,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $ConnectionBroker,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $UpdPath,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $CollectionName = "RDS Collection",

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $GroupName = "Domain Users",

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [Int] $MaxUpdSizeGB = 50,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $PrivateKeyPfx,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $PrivateKeyPassword,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [Switch] $HealthCheckEndPoint,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $HealthCheckDir = "${Env:SystemDrive}\inetpub\wwwroot",

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $HealthCheckSiteName = "Default Web Site",

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $HealthCheckPort = "8091"
)

#Based on:
# * https://s3.amazonaws.com/app-chemistry/scripts/configure-rdsh.ps1

function global:Download-File
{
    param (
    [Parameter(Mandatory=$true)]
    [string]$Source,

    [Parameter(Mandatory=$true)]
    [string]$Destination,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Ssl3","SystemDefault","Tls","Tls11","Tls12")]
    [string]$SecurityProtocol = "Tls12"
    )
    Write-Verbose "Downloading file --"
    Write-Verbose "    Source = ${Source}"
    Write-Verbose "    Destination = ${Destination}"
    try
    {
        Write-Verbose "Attempting to retrieve file using .NET method..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::$SecurityProtocol
        (New-Object Net.WebClient).DownloadFile("${Source}","${Destination}")
        Write-Output (Get-ChildItem "$Destination")
    }
    catch
    {
        try
        {
            Write-Verbose $PSItem.ToString()
            Write-Verbose ".NET method failed, attempting BITS transfer method..."
            Start-BitsTransfer -Source "${Source}" -Destination "${Destination}"
            Write-Output (Get-ChildItem "$Destination")
        }
        catch
        {
            Write-Verbose $PSItem.ToString()
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
    }
}

$RequiredFeatures = @(
    "RDS-RD-Server"
    "RDS-Licensing"
)

$ExtraFeatures = @(
  "Search-Service"
  "RSAT-ADDS-Tools"
  "GPMC"
)

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

# Import the P3Utils module
$null = Import-Module P3Utils -Verbose:$false

# Validate availability of RDS Licensing configuration
$null = Import-Module RemoteDesktop,RemoteDesktopServices -Verbose:$false
$TestPath = "RDS:\LicenseServer"
if (-not (Get-ChildItem $TestPath -ErrorAction SilentlyContinue))
{
    throw "System needs to reboot to create the path: ${TestPath}"
}

# Get the system name
$SystemName = [System.Net.DNS]::GetHostByName('').HostName

# Install extra Windows features
if ($ExtraFeatures)
{
    Install-WindowsFeature $ExtraFeatures
}

$RequiredRoles = @(
    "RDS-RD-SERVER"
)

# Create a lock before doing work on the connection broker (a shared resource)
$LockFile = "${UpdPath}\cleanup-rdcb-${ConnectionBroker}.lock".ToLower()
$Lock = $false

# Get an exclusive lock on the lock file
Write-Verbose "Attempting to create exclusive lock on ${LockFile}"
while (-not $Lock)
{
    try {
        $Lock = [System.IO.File]::Open($LockFile, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        Write-Verbose "Established lock!"
    }
    catch {
        # Sleep for 3 to 20 seconds.  Randomized to keep multiple scripts from hammering
        $Sleep = Get-Random -Minimum 3 -Maximum 20
        Write-Verbose "Detected existing lock, retrying in $Sleep seconds"
        $Sleep | Start-Sleep
    }
}

# Do work on shared resource (the connection broker)
try
{
    $RDServers = Get-RDServer -ConnectionBroker $ConnectionBroker -ErrorAction SilentlyContinue
    if (-not $RDServers)
    {
        # Create RD Session Deployment
        New-RDSessionDeployment -ConnectionBroker $ConnectionBroker -SessionHost $SystemName -ErrorAction Stop
        Write-Verbose "Created the RD Session Deployment!"
    }

    $CurrentRoles = @(Get-RDServer -ConnectionBroker $ConnectionBroker | Where-Object { $_.Server -eq $SystemName })
    foreach ($Role in $RequiredRoles)
    {
        if (-not ($Role -in $CurrentRoles.Roles))
        {
            Invoke-RetryCommand -Command Add-RDServer -ArgList @{Server=$SystemName; Role=$Role; ConnectionBroker=$ConnectionBroker}
            Write-Verbose "Configured system with role, ${Role}"
        }
    }

    # Create new session collection, or on error add system to existing collection
    try
    {
        New-RDSessionCollection -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -SessionHost $SystemName  -ErrorAction Stop
        Write-Verbose "Created the RD Session Collection!"

        Set-RDSessionCollectionConfiguration -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -UserGroup $GroupName -ErrorAction Stop
        Write-Verbose "Granted user group access to the RD Session Collection, ${GroupName}"

        Set-RDSessionCollectionConfiguration -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -EnableUserProfileDisk -DiskPath "${UpdPath}" -MaxUserProfileDiskSizeGB $MaxUpdSizeGB -ErrorAction Stop
        Write-Verbose "Enabled user profile disks for the RD Session Collection, ${UpdPath}"
    }
    catch [Microsoft.PowerShell.Commands.WriteErrorException]
    {
        Invoke-RetryCommand -Command Add-RDSessionHost -ArgList @{CollectionName=$CollectionName; SessionHost=$SystemName; ConnectionBroker=$ConnectionBroker} -CheckExpression '$?'
        Write-Verbose "Added system to RD Session Collection"
        Write-Verbose "*    SessionHost=${SystemName}"
        Write-Verbose "*    CollectionName=${CollectionName}"
    }

    # Disable new sessions until reboot
    Set-RDSessionHost -SessionHost $SystemName -NewConnectionAllowed "NotUntilReboot" -ConnectionBroker $ConnectionBroker
    Write-Verbose "Disabled new sessions until the host reboots"

    # Get access rules
    $UpdAcl = Get-Acl $UpdPath -ErrorAction Stop
    Write-Verbose "Current ACL on ${UpdPath}:"
    Write-Verbose ($UpdAcl.Access | Out-String)

    # Ensure this host is in the UPD share ACL
    $Identities = ($UpdAcl.Access | Select-Object IdentityReference).IdentityReference.Value
    $Identity = "${DomainNetBiosName}\$((Get-WmiObject Win32_ComputerSystem).Name)$"
    if (-not ($Identity -in $Identities))
    {
        Write-Verbose "Adding missing access rule for this host to UPD share."
        Write-Verbose "*    Rule Identity: $Identity"
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("${Identity}", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        $updAcl.AddAccessRule($Rule)

        # Write the new ACL
        Write-Verbose "Setting updated ACL on ${UpdPath}:"
        Write-Verbose ($UpdAcl.Access | Out-String)
        Invoke-RetryCommand -Command Set-Acl -ArgList @{Path=$UpdPath; AclObject=$UpdAcl} -CheckExpression '$?'
    }
}
catch
{
    Write-Verbose $PSItem.ToString()
    $PSCmdlet.ThrowTerminatingError($PSitem)
}
finally
{
    # Release the lock on the shared resource
    $Lock.Close()
    Write-Verbose "Released lock on ${LockFile}"
}

# Configure RDP certificate
if ($PrivateKeyPfx)
{
    $Cert = (Get-PfxData -Password (ConvertTo-SecureString ${PrivateKeyPassword} -AsPlainText -Force) -FilePath $PrivateKeyPfx).EndEntityCertificates[0]
    Get-ChildItem 'Cert:\LocalMachine\My\' | ? { $_.Subject -eq $Cert.Subject } | % { Remove-Item  $_.PSPath }
    Write-Verbose "Ensured no certificate exists with the same subject name, $($Cert.Subject)"

    Import-PfxCertificate -Password (ConvertTo-SecureString ${PrivateKeyPassword} -AsPlainText -Force) -CertStoreLocation 'Cert:\LocalMachine\My\' -FilePath $PrivateKeyPfx
    Write-Verbose "Imported the certificate to the local computer personal store"

    $tsgs = Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
    Set-WmiInstance -path $tsgs.__path -argument @{SSLCertificateSHA1Hash=$Cert.Thumbprint}
    Write-Verbose "Set the thumbprint for the RDP certificate, $($Cert.Thumbprint)"
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

# Configure DNS registration
$adapters = get-wmiobject -class Win32_NetworkAdapterConfiguration -filter "IPEnabled=TRUE"
$null = $adapters | foreach-object { $_.SetDynamicDNSRegistration($TRUE, $TRUE) }
Write-Verbose "Configured network adapters for dynamic DNS registration"

# Enable SmartScreen
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -ErrorAction Stop -Value "RequireAdmin" -Force
Write-Verbose "Enabled SmartScreen"

# Set the Audio Service to start automatically, without failing if the service name cannot be found
@(Get-Service -Name "audiosrv" -ErrorAction SilentlyContinue) | % { Set-Service -Name $_.Name -StartupType "Automatic" }
Write-Verbose "Enabled the audio service"

# Create public desktop shortcut for Windows Security
$WindowsSecurityPath = "${env:SYSTEMDRIVE}\Users\Public\Desktop\Windows Security.lnk"
$WindowsSecurityShortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("${WindowsSecurityPath}")
$WindowsSecurityShortcut.TargetPath = "Powershell"
$WindowsSecurityShortcut.Arguments = '-noprofile -nologo -noninteractive -command "(new-object -ComObject shell.application).WindowsSecurity()"'
$WindowsSecurityShortcut.Description = "Windows Security"
$WindowsSecurityShortcut.IconLocation = "${env:SYSTEMROOT}\System32\imageres.dll,1"
$WindowsSecurityShortcut.Save()
Write-Verbose "Created the windows security shortcut"

# Create public desktop shortcut for Sign Out
$SignoffPath = "${env:SYSTEMDRIVE}\Users\Public\Desktop\Sign Out.lnk"
$SignOffShortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("${SignoffPath}")
$SignOffShortcut.TargetPath = "logoff.exe"
$SignOffShortcut.Description = "Sign Out"
$SignOffShortcut.IconLocation = "${env:SYSTEMROOT}\System32\imageres.dll,81"
$SignOffShortcut.Save()
Write-Verbose "Created the logoff shortcut"

# Install Git for Windows
$GitUrl = "https://github.com/git-for-windows/git/releases/download/v2.22.0.windows.1/Git-2.22.0-64-bit.exe"
$GitInstaller = "${Env:Temp}\$(($GitUrl -split('/'))[-1])"
Invoke-RetryCommand -Command Download-File -ArgList @{Source=$GitUrl; Destination=$GitInstaller}
$GitParams = "/SILENT /NOCANCEL /NORESTART /SAVEINF=${Env:Temp}\git_params.txt"
$null = Start-Process -FilePath ${GitInstaller} -ArgumentList ${GitParams} -PassThru -Wait
Write-Verbose "Installed git for windows"

# Update git system config, aws credential helper needs to be listed first
$GitCmd = "C:\Program Files\Git\cmd\git.exe"
& "$GitCmd" config --system --unset credential.helper
& "$GitCmd" config --system --add 'credential.https://git-codecommit.us-east-1.amazonaws.com.helper' '!aws codecommit credential-helper $@'
& "$GitCmd" config --system --add 'credential.https://git-codecommit.us-east-1.amazonaws.com.usehttppath' 'true'
& "$GitCmd" config --system --add 'credential.helper' 'manager'
Write-Verbose "Configured git for windows"

# Install Python 3.6
$Py36Url = "https://www.python.org/ftp/python/3.6.8/python-3.6.8-amd64.exe"
$Py36Installer = "${Env:Temp}\$(($Py36Url -split('/'))[-1])"
Invoke-RetryCommand -Command Download-File -ArgList @{Source=$Py36Url; Destination=$Py36Installer}
$Py36Params = "/log ${env:temp}\python.log /quiet InstallAllUsers=1 PrependPath=1"
$null = Start-Process -FilePath ${Py36Installer} -ArgumentList ${Py36Params} -PassThru -Wait
Write-Verbose "Installed python 3.6"

# Install Haskell Platform (with cabal)
$HaskellVersion = "8.0.2"
$HaskellUrl = "https://downloads.haskell.org/~platform/${HaskellVersion}/HaskellPlatform-${HaskellVersion}-minimal-x86_64-setup.exe"
$HaskellInstaller = "${Env:Temp}\$(($HaskellUrl -split('/'))[-1])"
Invoke-RetryCommand -Command Download-File -ArgList @{Source=$HaskellUrl; Destination=$HaskellInstaller}
$HaskellParams = "/S"
$null = Start-Process -FilePath ${HaskellInstaller} -ArgumentList ${HaskellParams} -PassThru -Wait
Write-Verbose "Installed haskell platform"

# Update paths, prep for cabal-based installs
$HaskellPaths = @(
    "C:\Program Files\Haskell\bin"
    "C:\Program Files\Haskell Platform\${HaskellVersion}\lib\extralibs\bin"
    "C:\Program Files\Haskell Platform\${HaskellVersion}\bin"
    "C:\Program Files\Haskell Platform\${HaskellVersion}\mingw\bin"
)
$Env:Path += ";$($HaskellPaths -join ';')"

# Update cabal
$CabalExe = "cabal.exe"
$CabalUpdateParams = "update"
$null = Start-Process -FilePath ${CabalExe} -ArgumentList ${CabalUpdateParams} -PassThru -Wait -NoNewWindow
Write-Verbose "Updated cabal"

# Install cabal packages
$CabalPackages = @(
    "shellcheck"
)
$CabalInstallParams = "install --global ${CabalPackages}"
$null = Start-Process -FilePath ${CabalExe} -ArgumentList ${CabalInstallParams} -PassThru -Wait -NoNewWindow
Write-Verbose "Installed shellcheck"

# Install PsGet, a PowerShell Module
(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/psget/psget/master/GetPsGet.ps1") | iex
Write-Verbose "Installed psget"

# Install nuget, a PowerShell Module provider
# Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
# Write-Verbose "Installed nuget"

if ($HealthCheckEndPoint)
{
    Write-Verbose "Setting up the RDSH Health Check End Point..."

    # Install IIS
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools
    Import-Module WebAdministration
    Write-Verbose "Installed IIS to service health check requests"

    # Create the health check ping file
    $HealthCheckPing = "${HealthCheckDir}\ping.html"
    $null = New-Item -Path $HealthCheckPing -ItemType File -Value "OK" -Force
    Write-Verbose "Created the health check ping file: ${HealthCheckPing}"

    # Restrict the acl on the health check directory
    $Acl = Get-Acl $HealthCheckDir
    $Acl.SetAccessRuleProtection($True, $False)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('IIS_IUSRS', 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('IUSR', 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('NT SERVICE\TrustedInstaller', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('CREATOR OWNER', 'FullControl', 'ContainerInherit, ObjectInherit', 'InheritOnly', 'Allow')
    $Acl.AddAccessRule($Rule)
    Set-Acl $HealthCheckDir $Acl -ErrorAction Stop
    Write-Verbose "Restricted the acl on the health check directory: ${HealthCheckDir}"

    if (-not (Get-Website -Name $HealthCheckSiteName))
    {
        New-WebSite -Name $HealthCheckSiteName -PhysicalPath $HealthCheckDir -Port $HealthCheckPort
        Write-Verbose "Created new health check site:"
        Write-Verbose "    Name: ${HealthCheckSiteName}"
        Write-Verbose "    Path: ${HealthCheckDir}"
        Write-Verbose "    Port: ${HealthCheckPort}"
    }
    else
    {
        Get-WebBinding -Name $HealthCheckSiteName | % {Remove-WebBinding}
        New-WebBinding -Name $HealthCheckSiteName -Port $HealthCheckPort
        Write-Verbose "Configured the health check site to listen on ${HealthCheckPort}"
    }

    # Open the firewall for the health check endpoint
    $Rule = @{
        Name = "RDSH Health Check End Point"
        DisplayName = "RDSH Health Check End Point"
        Description = "Allow inbound access to RDSH Health Check End Point"
        Protocol = "TCP"
        Enabled = "True"
        Profile = "Any"
        Action = "Allow"
        LocalPort = $HealthCheckPort
    }
    Try
    {
        New-NetFirewallRule @Rule -ErrorAction Stop
    }
    Catch [Microsoft.Management.Infrastructure.CimException]
    {
        # 11 is rule already exists; not a fatal error
        if ($PSItem.Exception.StatusCode -ne "11")
        {
            # Any statuscode other than 11 is fatal
            Write-Verbose $PSItem.ToString()
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
    Write-Verbose "Opened firewall port ${HealthCheckPort} for RDSH Health Check End Point"
}

Write-Verbose "Completed configure-rdsh.ps1!"
