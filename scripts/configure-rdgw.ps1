[CmdLetBinding()]
Param(
    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $ServerFQDN = "",

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $DomainNetBiosName = "BUILTIN",

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $GroupName = "Administrators",

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [ValidateSet("Password","Smartcard")]
    [String] $AuthenticationMethod = "Password",

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [Switch] $HealthCheckEndPoint,

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $HealthCheckDir = "${Env:SystemDrive}\inetpub\wwwroot",

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $HealthCheckSiteName = "Default Web Site",

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $HealthCheckPort = "8091"
    )

#Based on:
# * https://s3.amazonaws.com/microsoft_windows/scripts/Configure-RDGW.ps1

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

$null = Install-WindowsFeature RDS-Gateway,RSAT-RDS-Gateway
$null = Import-Module RemoteDesktopServices

$AuthMethods = @{
    "Password" = 1
    "Smartcard" = 2
}

$SslBridging = @{
    "Password" = 1
    "Smartcard" = 2
}

# Remove self-signed certs from the personal store before creating a new one
dir cert:\localmachine\my | ? { $_.Issuer -eq $_.Subject } | % { Remove-Item  $_.PSPath }

# Remove root certs where the subject matches the ServerFQDN
dir cert:\localmachine\root | ? { $_.Subject -eq "CN=$ServerFQDN" } | % { Remove-Item  $_.PSPath }

$name = new-object -com "X509Enrollment.CX500DistinguishedName.1"
$name.Encode("CN=$ServerFQDN", 0)

$key = new-object -com "X509Enrollment.CX509PrivateKey.1"
$key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
$key.ExportPolicy = 2
$key.KeySpec = 1
$key.Length = 4096
$key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
$key.MachineContext = 1
$key.Create()

$serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
$serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
$ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
$ekuoids.add($serverauthoid)
$ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
$ekuext.InitializeEncode($ekuoids)

$sigoid = New-Object -ComObject X509Enrollment.CObjectId
$sigoid.InitializeFromValue(([Security.Cryptography.Oid]"SHA256").Value)

$cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
$cert.InitializeFromPrivateKey(2, $key, "")
$cert.Subject = $name
$cert.Issuer = $cert.Subject
$cert.NotBefore = get-date
$cert.NotAfter = $cert.NotBefore.AddDays(730)
$cert.X509Extensions.Add($ekuext)
$cert.SignatureInformation.HashAlgorithm = $sigoid
$cert.Encode()

$enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
$enrollment.InitializeFromRequest($cert)
$certdata = $enrollment.CreateRequest(0)
$enrollment.InstallResponse(2, $certdata, 0, "")

dir cert:\localmachine\my | ? { $_.Subject -eq "CN=$ServerFQDN" } | % { [system.IO.file]::WriteAllBytes("c:\$ServerFQDN.cer", ($_.Export('CERT', 'secret')) ) }

& "certutil" -addstore "Root" "C:\$ServerFQDN.cer"

if (test-path RDS:\GatewayServer\CAP\Default-CAP) {
  remove-item -path RDS:\GatewayServer\CAP\Default-CAP -Recurse
}

$null = new-item -path RDS:\GatewayServer\CAP -Name Default-CAP -UserGroups "$GroupName@$DomainNetBiosName" -AuthMethod $AuthMethods[$AuthenticationMethod]

if (test-path RDS:\GatewayServer\RAP\Default-RAP) {
  remove-item -Path RDS:\GatewayServer\RAP\Default-RAP -Recurse
}

$null = new-item -Path RDS:\GatewayServer\RAP -Name Default-RAP -UserGroups "$GroupName@$DomainNetBiosName" -ComputerGroupType 2

$null = set-item -Path RDS:\GatewayServer\SSLBridging $SslBridging[$AuthenticationMethod]

$null = Set-Item -Path RDS:\GatewayServer\SSLCertificate\Thumbprint -Value $((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("c:\$ServerFQDN.cer")).Thumbprint)

Restart-Service tsgateway

if ($HealthCheckEndPoint)
{
    Write-Verbose "Setting up the RDSH Health Check End Point..."

    # Install IIS
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools
    Import-Module WebAdministration
    Write-Verbose "Installed IIS to service health check requests"

    # Create the health check ping file
    $HealthCheckPing = "${HealthCheckDir}\ping.html"
    $null = New-Item -Path $HealthCheckPing -ItemType File -Value "OK" -Force
    Write-Verbose "Created the health check ping file: ${HealthCheckPing}"

    # Restrict the acl on the health check directory
    $Acl = Get-Acl $HealthCheckDir
    $Acl.SetAccessRuleProtection($True, $False)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('IIS_IUSRS', 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('IUSR', 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('NT SERVICE\TrustedInstaller', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule('CREATOR OWNER', 'FullControl', 'ContainerInherit, ObjectInherit', 'InheritOnly', 'Allow')
    $Acl.AddAccessRule($Rule)
    Set-Acl $HealthCheckDir $Acl -ErrorAction Stop
    Write-Verbose "Restricted the acl on the health check directory: ${HealthCheckDir}"

    if (-not (Get-Website -Name $HealthCheckSiteName))
    {
        New-WebSite -Name $HealthCheckSiteName -PhysicalPath $HealthCheckDir -Port $HealthCheckPort
        Write-Verbose "Created new health check site:"
        Write-Verbose "    Name: ${HealthCheckSiteName}"
        Write-Verbose "    Path: ${HealthCheckDir}"
        Write-Verbose "    Port: ${HealthCheckPort}"
    }
    else
    {
        Get-WebBinding -Name $HealthCheckSiteName | % {Remove-WebBinding}
        New-WebBinding -Name $HealthCheckSiteName -Port $HealthCheckPort
        Write-Verbose "Configured the health check site to listen on ${HealthCheckPort}"
    }

    # Open the firewall for the health check endpoint
    $Rule = @{
        Name = "${HealthCheckSiteName}"
        DisplayName = "${HealthCheckSiteName}"
        Description = "Allow inbound access to ${HealthCheckSiteName}"
        Protocol = "TCP"
        Enabled = "True"
        Profile = "Any"
        Action = "Allow"
        LocalPort = $HealthCheckPort
    }
    Try
    {
        New-NetFirewallRule @Rule -ErrorAction Stop
    }
    Catch [Microsoft.Management.Infrastructure.CimException]
    {
        # 11 is rule already exists; not a fatal error
        if ($PSItem.Exception.StatusCode -ne "11")
        {
            # Any statuscode other than 11 is fatal
            Write-Verbose $PSItem.ToString()
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
    Write-Verbose "Opened firewall port ${HealthCheckPort} for ${HealthCheckSiteName}"
}

Write-Verbose "Completed configure-rdgw.ps1!"
