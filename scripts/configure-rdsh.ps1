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
  [Int] $MaxUpdSizeGB = 50
)

#Based on:
# * https://s3.amazonaws.com/app-chemistry/scripts/configure-rdsh.ps1

$RequiredFeatures = @(
    "RDS-Connection-Broker"
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
    "RDS-CONNECTION-BROKER"
)

# Create RD Session Deployment
if (-not (Get-RDServer -ConnectionBroker $ConnectionBroker -ErrorAction SilentlyContinue))
{
    New-RDSessionDeployment -ConnectionBroker $ConnectionBroker -SessionHost $SystemName -ErrorAction Stop
    Write-Verbose "Created the RD Session Deployment!"
}

$CurrentRoles = @(Get-RDServer -ConnectionBroker $ConnectionBroker | Where { $_.Server -eq $SystemName })
foreach ($Role in $RequiredRoles)
{
    if (-not ($Role -in $CurrentRoles.Roles))
    {
        Add-RDServer -Server $SystemName -Role $Role -ConnectionBroker $ConnectionBroker -ErrorAction Stop
        Write-Verbose "Configured system with role, ${Role}"
    }
}

# Create RD Session Collection or add system to existing collection
if (-not (Get-RDSessionCollection -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -ErrorAction SilentlyContinue))
{
    New-RDSessionCollection -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -SessionHost $SystemName  -ErrorAction Stop
    Write-Verbose "Created the RD Session Collection!"

    Set-RDSessionCollectionConfiguration -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -UserGroup $GroupName -ErrorAction Stop
    Write-Verbose "Granted user group access to the RD Session Collection, ${UserGroup}"

    Set-RDSessionCollectionConfiguration -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -EnableUserProfileDisk -DiskPath "${UpdPath}" -MaxUserProfileDiskSizeGB $MaxUpdSizeGB -ErrorAction Stop
    Write-Verbose "Enabled user profile disks for the RD Session Collection, \\${SystemName}\${UpdShareName}"
}
else
{
    Add-RDSessionHost -CollectionName "RDS Collection" -SessionHost $SystemName -ConnectionBroker $ConnectionBroker -ErrorAction Stop
    Write-Verbose "Added system to RD Session Collection; SessionHost=${SystemName}, CollectionName=${CollectionName}"
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
$GitUrl = "https://github.com/git-for-windows/git/releases/download/v2.12.2.windows.2/Git-2.12.2.2-64-bit.exe"
$GitInstaller = "${Env:Temp}\Git-2.12.2.2-64-bit.exe"
(new-object net.webclient).DownloadFile("${GitUrl}","${GitInstaller}")
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

# Install Python 3.5
$Py35Url = "https://www.python.org/ftp/python/3.5.2/python-3.5.2-amd64.exe"
$Py35Installer = "${Env:Temp}\python-3.5.2-amd64.exe"
(new-object net.webclient).DownloadFile("${Py35Url}","${Py35Installer}")
$Py35Params = "/log ${env:temp}\python.log /quiet InstallAllUsers=1 PrependPath=1"
$null = Start-Process -FilePath ${Py35Installer} -ArgumentList ${Py35Params} -PassThru -Wait
Write-Verbose "Installed python 3.5"

# Install Haskell Platform (with cabal)
$HaskellVersion = "8.0.2"
$HaskellUrl = "https://www.haskell.org/platform/download/${HaskellVersion}/HaskellPlatform-${HaskellVersion}-minimal-x86_64-setup.exe"
$HaskellInstaller = "${Env:Temp}\HaskellPlatform-${HaskellVersion}-minimal-x86_64-setup.exe"
(new-object net.webclient).DownloadFile("${HaskellUrl}","${HaskellInstaller}")
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
(new-object Net.WebClient).DownloadString("http://psget.net/GetPsGet.ps1") | iex
Write-Verbose "Installed psget"

Write-Verbose "Completed configure-rdsh.ps1!"
