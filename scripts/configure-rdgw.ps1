[CmdLetBinding()]
Param(
    $ServerFQDN,
    $DomainNetBiosName = "BUILTIN",
    $GroupName = "Administrators"
    )

#Based on:
# * https://s3.amazonaws.com/microsoft_windows/scripts/Configure-RDGW.ps1

if (-not $ServerFQDN) {
    $name = invoke-restmethod -uri http://169.254.169.254/latest/meta-data/public-hostname
    if (-not $name) {
        $name = [System.Net.DNS]::GetHostByName('').HostName
    }
    $ServerFQDN = $name
}

$null = Install-WindowsFeature RDS-Gateway,RSAT-RDS-Gateway
$null = Import-Module remotedesktopservices

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

$cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
$cert.InitializeFromPrivateKey(2, $key, "")
$cert.Subject = $name
$cert.Issuer = $cert.Subject
$cert.NotBefore = get-date
$cert.NotAfter = $cert.NotBefore.AddDays(730)
$cert.X509Extensions.Add($ekuext)
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

$null = new-item -path RDS:\GatewayServer\CAP -Name Default-CAP -UserGroups "$GroupName@$DomainNetBiosName" -AuthMethod 1

if (test-path RDS:\GatewayServer\RAP\Default-RAP) {
  remove-item -Path RDS:\GatewayServer\RAP\Default-RAP -Recurse
}

$null = new-item -Path RDS:\GatewayServer\RAP -Name Default-RAP -UserGroups "$GroupName@$DomainNetBiosName" -ComputerGroupType 2

$null = set-item -Path RDS:\GatewayServer\SSLBridging 1

$null = Set-Item -Path RDS:\GatewayServer\SSLCertificate\Thumbprint -Value $((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("c:\$ServerFQDN.cer")).Thumbprint)

Restart-Service tsgateway
