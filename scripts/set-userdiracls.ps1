[CmdLetBinding()]
Param(
    [String] $RedirectedBase
)
<#
    Resets restrictive ownership and permissions on a roaming profile path and,
    optionally, on another file path. The optional file path is intended to be
    used against a base share for redirected folders.

    This script must be executed by the user directly, or by a logon script
    that runs in the context of the user.

    Example Usage:
    .\set-userdiracls.ps1 -RedirectedBase \\home.example.com\users$
#>

$Owner = New-Object System.Security.Principal.NTAccount($Env:USERDOMAIN, $Env:USERNAME)
$UserProfile = gwmi win32_userprofile | ? { $_.LocalPath -eq $Env:USERPROFILE }

$ControlPaths = @()
if ($RedirectedBase)
{
    $ControlPaths += Join-Path -Path $RedirectedBase -ChildPath $Env:USERNAME
}

if ($UserProfile.RoamingPath)
{
    $ControlPaths += $UserProfile.RoamingPath
}

# Create a Base ACL for comparison tests
$BaseAcl = New-Object System.Security.AccessControl.DirectorySecurity
$BaseAcl.SetOwner($Owner)
$BaseRules = @(
    New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    New-Object System.Security.AccessControl.FileSystemAccessRule($Owner, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
)
$BaseRules | % {$BaseAcl.AddAccessRule($_)}

foreach ($Path in $ControlPaths)
{
    # For each control path:
    # - Set owner to user on parent container, subcontainers, and objects
    # - Disable inheritance on parent container, remove inherited permissions
    # - Grant full permissions _only_ to user and SYSTEM, propagate permissions to subcontainers and objects

    # Set the ACL on the parent container
    Write-Verbose "Processing ${Path}..."
    $Acl = Get-Acl -LiteralPath $Path
    $TestOwner = -not (Compare-Object -ReferenceObject $Acl -DifferenceObject $BaseAcl -Property Owner)
    $TestAccess = -not (Compare-Object -ReferenceObject $Acl -DifferenceObject $BaseAcl -Property Access)
    $TestProtection = $Acl.AreAccessRulesProtected
    if ($TestOwner -and $TestAccess -and $TestProtection)
    {
        Write-Verbose "ACL already correct on ${Path}, skipped"
    }
    else
    {
        $Acl.SetOwner($Owner)
        $Acl.SetAccessRuleProtection($True, $False)
        @($Acl.Access) | % { $Acl.RemoveAccessRule($_) | out-null }
        $BaseRules | % { $Acl.AddAccessRule($_) }

        # Set ACL on parent
        Write-Verbose "Setting ACL on ${Path}"
        (Get-Item $Path).SetAccessControl($Acl)

        # Set ACLs on children
        Write-Verbose "Taking ownership of all files in ${Path}"
        takeown /F $Path /R /D Y /SKIPSL

        Write-Verbose "Resetting ACL and enforcing inheritance of all files in ${Path}"
        icacls "${Path}\*" /q /l /c /t /reset
    }
}
