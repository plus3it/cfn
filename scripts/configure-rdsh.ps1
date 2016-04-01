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

# Add Windows features
$null = Install-WindowsFeature @(
    "RDS-RD-Server"
    "RDS-Licensing"
    "Search-Service"
    "Desktop-Experience"
    "RSAT-ADDS-Tools"
    "GPMC"
)
$null = Import-Module RemoteDesktop,RemoteDesktopServices

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

# Grant remote access privileges to domain group
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

# Configure DNS registration
$adapters = get-wmiobject -class Win32_NetworkAdapterConfiguration -filter "IPEnabled=TRUE"
$null = $adapters | foreach-object { $_.SetDynamicDNSRegistration($TRUE, $TRUE) }

# Enable SmartScreen
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -ErrorAction Stop -Value "RequireAdmin" -Force

# Set the Audio Service to start automatically, without failing if the service name cannot be found
@(Get-Service -Name "audiosrv" -ErrorAction SilentlyContinue) | % { Set-Service -Name $_.Name -StartupType "Automatic" }

# Create public desktop shortcut for Windows Security
$WindowsSecurityPath = "${env:SYSTEMDRIVE}\Users\Public\Desktop\Windows Security.lnk"
$WindowsSecurityShortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("${WindowsSecurityPath}")
$WindowsSecurityShortcut.TargetPath = "Powershell"
$WindowsSecurityShortcut.Arguments = '-noprofile -nologo -noninteractive -command "(new-object -ComObject shell.application).WindowsSecurity()"'
$WindowsSecurityShortcut.Description = "Windows Security"
$WindowsSecurityShortcut.IconLocation = "${env:SYSTEMROOT}\System32\imageres.dll,1"
$WindowsSecurityShortcut.Save()

# Create public desktop shortcut for Sign Out
$SignoffPath = "${env:SYSTEMDRIVE}\Users\Public\Desktop\Sign Out.lnk"
$SignOffShortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("${SignoffPath}")
$SignOffShortcut.TargetPath = "logoff.exe"
$SignOffShortcut.Description = "Sign Out"
$SignOffShortcut.IconLocation = "${env:SYSTEMROOT}\System32\imageres.dll,81"
$SignOffShortcut.Save()

# Install Chrome
$ChromeUrl = "https://s3.amazonaws.com/app-chemistry/scripts/googlechromestandaloneenterprise64.msi"
$ChromeInstaller = "${Env:Temp}\googlechromestandaloneenterprise64.msi"
(new-object net.webclient).DownloadFile("${ChromeUrl}","${ChromeInstaller}")
$ChromeParams = "/i `"${ChromeInstaller}`" /quiet /qn /norestart"
$null = Start-Process -FilePath msiexec -ArgumentList ${ChromeParams} -NoNewWindow -PassThru -Wait

# Restart
Restart-Computer -Force
