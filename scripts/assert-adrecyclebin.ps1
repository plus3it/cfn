[CmdletBinding()]
param(
    [string]
    $EntAdminUsername,

    [string]
    $EntAdminPw,

    [string]
    $ForestFqdn
)

<#
    Requires xActiveDirectory DSC Resource (v2.3 or later):

    https://gallery.technet.microsoft.com/scriptcenter/xActiveDirectory-f2d573f3
    https://github.com/PowerShell/xActiveDirectory

#>

# Location used to save dsc mof config
$ConfigStore = "$env:systemroot\system32\DSC\AssertAdRecycleBin"

# Generate PS Credentials
$SecureEntAdminPw = ConvertTo-SecureString $EntAdminPw -AsPlainText -Force
$EntAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList "$EntAdminUsername@$ForestFqdn", $SecureEntAdminPw


$ConfigData = @{
    AllNodes = @(
        @{
            Nodename = 'localhost'
            ForestFqdn = $ForestFqdn
            EnterpriseAdministratorCredential = $EntAdminCredential
            RetryCount = 20
            RetryIntervalSec = 30
        }
    )
}


Configuration AssertAdRecycleBin
{
    Import-DscResource -ModuleName xActiveDirectory

    Node $AllNodes.Nodename
    {
        LocalConfigurationManager
        {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        xWaitForADDomain DscForestWait
        {
            DomainName = $Node.ForestFqdn
            DomainUserCredential = $Node.EnterpriseAdministratorCredential
            RetryCount = $Node.RetryCount
            RetryIntervalSec = $Node.RetryIntervalSec
        }

        xADRecycleBin RecycleBin
        {
            EnterpriseAdministratorCredential = $Node.EnterpriseAdministratorCredential
            ForestFQDN = $Node.ForestFqdn
            DependsOn = '[xWaitForADDomain]DscForestWait'
        }

        # Remove ConfigStore as last step, as it will contain sensitive info
        File RemoveConfigStore
        {
            DestinationPath = $ConfigStore
            Ensure = 'Absent'
            Type = 'Directory'
            Recurse = $true
            Force = $true
            DependsOn = '[xADRecycleBin]RecycleBin'
        }
    }
}

AssertAdRecycleBin -ConfigurationData $ConfigData

New-Item -Path $ConfigStore -ItemType Directory -Force
Move-Item -Path .\AssertAdRecycleBin\*.mof -Destination $ConfigStore -Force
Remove-Item -Path .\AssertAdRecycleBin -Recurse -Force

# Make sure that LCM is set to continue configuration after reboot
Set-DSCLocalConfigurationManager -Path $ConfigStore -Verbose

# Build the domain
Start-DscConfiguration -Wait -Force -Path $ConfigStore -Verbose
