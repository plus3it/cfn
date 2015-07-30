[CmdletBinding()]
param(
    [string]
    $ComputerName

    [string]
    $DomainDnsName,

    [string]
    $DomainAdminUsername,

    [string]
    $DomainAdminPw,
)

<#
    Requires xComputerManagement DSC Resource (v1.3.0 or later):

    https://github.com/PowerShell/xComputerManagement

#>

# Location used to save dsc mof config
$ConfigStore = "$env:systemroot\system32\DSC\AssertJoinDomain"

# Generate PS Credentials
$SecureDomainAdminPw = ConvertTo-SecureString $DomainAdminPw -AsPlainText -Force
$DomainAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList "$DomainAdminUsername@$DomainDnsName", $SecureDomainAdminPw


$ConfigData = @{
    AllNodes = @(
        @{
            Nodename = 'localhost'
            ComputerName = $ComputerName
            DomainName = $DomainDnsName
            Credential = $DomainAdminCredential
        }
    )
}


Configuration AssertJoinDomain
{
    Import-DscResource -ModuleName xComputerManagement

    Node $AllNodes.Nodename
    {
        LocalConfigurationManager
        {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        xComputer SetName
        {
            Name = $Node.ComputerName
            DomainName = $Node.DomainName
            Credential = $Node.Credential
        }

        # Remove ConfigStore as last step, as it will contain sensitive info
        File RemoveConfigStore
        {
            DestinationPath = $ConfigStore
            Ensure = 'Absent'
            Type = 'Directory'
            Recurse = $true
            Force = $true
            DependsOn = '[xComputer]SetName'
        }
    }
}

AssertJoinDomain -ConfigurationData $ConfigData

New-Item -Path $ConfigStore -ItemType Directory -Force
Move-Item -Path .\AssertJoinDomain\*.mof -Destination $ConfigStore -Force
Remove-Item -Path .\AssertJoinDomain -Recurse -Force

# Make sure that LCM is set to continue configuration after reboot
Set-DSCLocalConfigurationManager -Path $ConfigStore -Verbose

# Start the configuration
Start-DscConfiguration -Wait -Force -Path $ConfigStore -Verbose
