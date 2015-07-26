[CmdletBinding()]
param(
    [string]
    $DomainAdminUsername,

    [string]
    $DomainAdminPw,

    [string]
    $RestoreModePw,

    [string]
    $DomainDnsName,

    [ValidateSet("Primary DC","Replica DC")]
    [string]
    $DcRole
)

<#
    Requires xActiveDirectory DSC Resource (v2.3 or later):

    https://gallery.technet.microsoft.com/scriptcenter/xActiveDirectory-f2d573f3
    https://github.com/PowerShell/xActiveDirectory

    Requires xNetworking DSC Resource (v2.2.0.0 or later):
    https://github.com/PowerShell/xNetworking

#>

# Location used to save dsc mof config
$ConfigStore = "$env:systemroot\system32\DSC\AssertHADC"

# Generate PS Credentials
$SecureDomainAdminPw = ConvertTo-SecureString $DomainAdminPw -AsPlainText -Force
$SecureRestoreModePw = ConvertTo-SecureString $RestoreModePw -AsPlainText -Force
$DomainAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList "$DomainAdminUsername@$DomainDnsName", $SecureDomainAdminPw
$RestoreModeCredential = New-Object System.Management.Automation.PSCredential -ArgumentList '(Password Only)', $SecureRestoreModePw

# Grab the current network info, which will be DHCP initially
# Expecting DSC will convert it to a static address, see:
# https://github.com/PowerShell/xNetworking/issues/9
$netip = Get-NetIPConfiguration

$ConfigData = @{
    AllNodes = @(
        @{
            Nodename = 'localhost'
            Role = $DcRole
            DomainName = $DomainDnsName
            RetryCount = 20
            RetryIntervalSec = 30
            PsDscAllowPlainTextPassword = $true
            InterfaceAlias = 'Ethernet'
            IPAddress = $netip.IPv4Address.IpAddress
            SubnetMask = $netip.IPv4Address.PrefixLength
            DefaultGateway = $netip.IPv4DefaultGateway.NextHop
            AddressFamily = 'IPv4'
        }
    )
}


Configuration AssertHADC
{
    Import-DscResource -ModuleName xActiveDirectory, xNetworking

    Node $AllNodes.Where{$_.Role -eq "Primary DC"}.Nodename
    {
        LocalConfigurationManager
        {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        xIPAddress SetIP {
            IPAddress = $Node.IPAddress
            InterfaceAlias = $Node.InterfaceAlias
            DefaultGateway = $Node.DefaultGateway
            SubnetMask = $Node.SubnetMask
            AddressFamily = $Node.AddressFamily
        }

        WindowsFeature ADDSInstall
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        # Optional GUI tools
        WindowsFeature ADDSTools
        {
            Ensure = "Present"
            Name = "RSAT-ADDS"
        }

        xADDomain FirstDS
        {
            DomainName = $Node.DomainName
            DomainAdministratorCredential = $DomainAdminCredential
            SafemodeAdministratorPassword = $RestoreModeCredential
            DependsOn = '[xIPAddress]SetIP','[WindowsFeature]ADDSInstall'
        }

        xWaitForADDomain DscForestWait
        {
            DomainName = $Node.DomainName
            DomainUserCredential = $DomainAdminCredential
            RetryCount = $Node.RetryCount
            RetryIntervalSec = $Node.RetryIntervalSec
            DependsOn = '[xADDomain]FirstDS'
        }

        # Remove ConfigStore as last step, as it will contain sensitive info
        File RemoveConfigStore
        {
            DestinationPath = $ConfigStore
            Ensure = 'Absent'
            Type = 'Directory'
            Recurse = $true
            Force = $true
            DependsOn '[xWaitForADDomain]DscForestWait'
        }
    }

    Node $AllNodes.Where{$_.Role -eq "Replica DC"}.Nodename
    {
        LocalConfigurationManager
        {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        xIPAddress SetIP {
            IPAddress = $Node.IPAddress
            InterfaceAlias = $Node.InterfaceAlias
            DefaultGateway = $Node.DefaultGateway
            SubnetMask = $Node.SubnetMask
            AddressFamily = $Node.AddressFamily
        }

        WindowsFeature ADDSInstall
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        # Optional GUI tools
        WindowsFeature ADDSTools
        {
            Ensure = "Present"
            Name = "RSAT-ADDS"
        }

        xWaitForADDomain DscForestWait
        {
            DomainName = $Node.DomainName
            DomainUserCredential = $DomainAdminCredential
            RetryCount = $Node.RetryCount
            RetryIntervalSec = $Node.RetryIntervalSec
            DependsOn = '[WindowsFeature]ADDSInstall'
        }

        xADDomainController AdditionalDC
        {
            DomainName = $Node.DomainName
            DomainAdministratorCredential = $DomainAdminCredential
            SafemodeAdministratorPassword = $RestoreModeCredential
            DependsOn = '[xIPAddress]SetIP','[xWaitForADDomain]DscForestWait'
        }

        # Remove ConfigStore as last step, as it will contain sensitive info
        File RemoveConfigStore
        {
            DestinationPath = $ConfigStore
            Ensure = 'Absent'
            Type = 'Directory'
            Recurse = $true
            Force = $true
            DependsOn '[xADDomainController]AdditionalDC'
        }
    }
}

AssertHADC -ConfigurationData $ConfigData

# Make sure that LCM is set to continue configuration after reboot
Set-DSCLocalConfigurationManager -Path $ConfigStore -Verbose

# Build the domain
Start-DscConfiguration -Wait -Force -Path $ConfigStore -Verbose
