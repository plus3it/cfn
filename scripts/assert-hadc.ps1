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
#>

# Generate PS Credentials
$SecureDomainAdminPw = ConvertTo-SecureString $DomainAdminPw -AsPlainText -Force
$SecureRestoreModePw = ConvertTo-SecureString $RestoreModePw -AsPlainText -Force
$DomainAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList "$DomainAdminUsername@$DomainDnsName", $SecureDomainAdminPw
$RestoreModeCredential = New-Object System.Management.Automation.PSCredential -ArgumentList '(Password Only)', $SecureRestoreModePw


$ConfigData = @{
    AllNodes = @(
        @{
            Nodename = "localhost"
            Role = $DcRole
            DomainName = $DomainDnsName
            RetryCount = 20
            RetryIntervalSec = 30
            PsDscAllowPlainTextPassword = $true
        }
    )
}


Configuration AssertHADC
{
    Import-DscResource -ModuleName xActiveDirectory

    Node $AllNodes.Where{$_.Role -eq "Primary DC"}.Nodename
    {
        LocalConfigurationManager
        {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
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
            DependsOn = "[WindowsFeature]ADDSInstall"
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
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        xADDomainController AdditionalDC
        {
            DomainName = $Node.DomainName
            DomainAdministratorCredential = $DomainAdminCredential
            SafemodeAdministratorPassword = $RestoreModeCredential
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }
    }
}

AssertHADC -ConfigurationData $ConfigData

# Make sure that LCM is set to continue configuration after reboot
Set-DSCLocalConfigurationManager -Path .\AssertHADC -Verbose

# Build the domain
Start-DscConfiguration -Wait -Force -Path .\AssertHADC -Verbose

# Delete .mof files as they contain sensitive information
Get-ChildItem .\AssertHADC *.mof -ErrorAction SilentlyContinue | Remove-Item -Confirm:$false -ErrorAction SilentlyContinue
