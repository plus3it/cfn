[CmdletBinding()]
param(
    [string]
    $ComputerName
)

<#
    Requires xComputerManagement DSC Resource (v1.3.0 or later):

    https://github.com/PowerShell/xComputerManagement

#>

# Location used to save dsc mof config
$ConfigStore = "$env:systemroot\system32\DSC\AssertComputerName"

$ConfigData = @{
    AllNodes = @(
        @{
            Nodename = 'localhost'
            ComputerName = $ComputerName
        }
    )
}


Configuration AssertComputerName
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

AssertComputerName -ConfigurationData $ConfigData

New-Item -Path $ConfigStore -ItemType Directory -Force
Move-Item -Path .\AssertComputerName\*.mof -Destination $ConfigStore -Force
Remove-Item -Path .\AssertComputerName -Recurse -Force

# Make sure that LCM is set to continue configuration after reboot
Set-DSCLocalConfigurationManager -Path $ConfigStore -Verbose

# Build the domain
Start-DscConfiguration -Wait -Force -Path $ConfigStore -Verbose
