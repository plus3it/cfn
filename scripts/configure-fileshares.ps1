[CmdLetBinding()]
Param(
    [Parameter(Mandatory=$false,ValueFromPipeLine=$true,ValueFromPipeLineByPropertyName=$false)]
    [String[]] $Shares = @("Users$", "Profiles$"),

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $ShareRoot = "D:\Shares",

    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $DomainNetBiosName,

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $GroupName = "Domain Users"
)
BEGIN
{
    $RequiredFeatures = @("FS-FileServer")
    Install-WindowsFeature $RequiredFeatures
    Write-Verbose "Installed Windows features: $($RequiredFeatures -join ',')"
}
PROCESS
{
    ForEach ($Share in $Shares)
    {
        $Folder = "${ShareRoot}\${Share}"
        $SetAcl = $false

        if (-not (Test-Path $Folder))
        {
            New-Item -ItemType directory -Path "$Folder" -Force -ErrorAction $ErrorActionPreference
            Write-Verbose "Created folder: ${Folder}"
            $SetAcl = $true
        }
        else
        {
            Write-Verbose "Folder already exists, ${Folder}, skipping"
        }

        if (-not (Get-SmbShare -Name $Share -ErrorAction SilentlyContinue))
        {
            New-SmbShare -Name $Share -Path "$Folder" -FullAccess Everyone -EncryptData $true -FolderEnumerationMode AccessBased -ErrorAction $ErrorActionPreference
            Write-Verbose "Created SMB share: ${Share}"
        }
        else
        {
            Write-Verbose "Share already exists, ${Share}, skipping"
        }

        if ($SetAcl)
        {
            $Acl = Get-Acl $Folder
            $Acl.SetAccessRuleProtection($True, $False)
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "None", "None", "Allow")
            $Acl.AddAccessRule($Rule)
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
            $Acl.AddAccessRule($Rule)
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", "ContainerInherit, ObjectInherit", "InheritOnly", "Allow")
            $Acl.AddAccessRule($Rule)
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("${DomainNetBiosName}\${GroupName}", "ListDirectory, Read, CreateDirectories, AppendData", "None", "None", "Allow")
            $Acl.AddAccessRule($Rule)
            Set-Acl $Folder $Acl -ErrorAction $ErrorActionPreference
            Write-Verbose "Set ACL on folder: $Folder"
        }
    }
}
