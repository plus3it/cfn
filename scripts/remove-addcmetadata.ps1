[CmdletBinding()]
param(
    [string]
    $DeadDcName,

    [string]
    $ExistingDcName,
    
    [string]
    $DomainDnsName,

    [string]
    $DomainAdminUsername,

    [string]
    $DomainAdminPw
)


# Generate PS Credentials
$SecureDomainAdminPw = ConvertTo-SecureString $DomainAdminPw -AsPlainText -Force
$DomainAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList "$DomainAdminUsername@$DomainDnsName", $SecureDomainAdminPw

# Connect to existing DC to check for metadata for the dead DC
$ServerFqdn = "$ExistingDcName.$DomainDnsName"

# Get the default naming context
$NamingContext = (Get-ADobject -Filter { ObjectClass -eq 'domainDNS' } -Credential $DomainAdminCredential -Server $ServerFqdn).DistinguishedName

# Remove DC Metadata from AD
# This should result in the same state as deleting the DC computer object from ADUC
# Any FSMO roles that were on the DC will need to be transferred with 'Move-ADDirectoryServerOperationMasterRole'

Get-ADobject -Filter * | where { $_.DistinguishedName -match $DeadDcName } -Credential $DomainAdminCredential -Server $ServerFqdn | Remove-ADobject -Force
Get-ADobject -Filter { ObjectClass -eq 'nTDSDSA' } -SearchBase "CN=Configuration,$NamingContext" | where { $_.DistinguishedName -match $DeadDcName } -Credential $DomainAdminCredential -Server $ServerFqdn | Remove-ADobject -Force
