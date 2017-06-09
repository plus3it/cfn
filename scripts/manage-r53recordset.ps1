[CmdLetBinding()]
Param(
  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [String] $HostedZoneId,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [ValidateSet("CNAME","A","AAAA","MX","TXT","PTR","SRV","SPF","NS","SOA")]
  [String] $Type,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [String[]] $Value,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [String] $Name,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [Switch] $AliasRecord,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [Long] $Weight,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [String] $HealthCheckId,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [ValidateSet("PRIMARY","SECONDARY")]
  [String] $Failover,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [String] $TrafficPolicyInstanceId,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [String] $SetIdentifier,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [Amazon.Route53.Model.GeoLocation] $GeoLocation,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [Long] $Ttl = "300",

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [Bool] $EvaluateTargetHealth = $false,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [ValidateSet("CREATE","DELETE","UPSERT")]
  [String] $Action = "UPSERT",

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [String] $Comment = "",

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [Int] $Timeout = 90,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$true)]
  [Switch] $Force
)
# http://docs.aws.amazon.com/sdkfornet/v3/apidocs/items/Route53/TRoute53ResourceRecordSet.html

$Zone = Get-R53HostedZones | ? {$_.Id -match "${HostedZoneId}"}
if (-not $Zone)
{
    throw "Could not find zone, ${HostedZoneId}"
}

$RecordSetsResponse = (Get-R53ResourceRecordSet -HostedZoneId $HostedZoneId -StartRecordName $Name -StartRecordType $Type).ResourceRecordSets
if ($RecordSetsResponse -and -not $Force)
{
    throw "Found matching Resource Record, use `$Force to proceed: name='${Name}'; type='${Type}'"
}

$Name_ = if (-not $Name) { "" } else { "${Name}." }

$Change = New-Object Amazon.Route53.Model.Change
$Change.Action = $Action
$Change.ResourceRecordSet = New-Object Amazon.Route53.Model.ResourceRecordSet
$Change.ResourceRecordSet.Name = "${Name_}$($Zone.Name)"
$Change.ResourceRecordSet.TTL = $Ttl
$Change.ResourceRecordSet.Type = $Type
if ($AliasRecord)
{
    $Change.ResourceRecordSet.AliasTarget = New-Object Amazon.Route53.Model.AliasTarget
    $Change.ResourceRecordSet.AliasTarget.HostedZoneId = $HostedZoneId
    $Change.ResourceRecordSet.AliasTarget.DNSName =
    $Change.ResourceRecordSet.AliasTarget.EvaluateTargetHealth = $EvaluateTargetHealth
}
else
{
    ForEach ($Val in $Value)
    {
        $Change.ResourceRecordSet.ResourceRecords.Add(@{Value="$Val"})
    }
}
if ($Failover)
{
    $Change.ResourceRecordSet.Failover = $Failover
}
if ($GeoLocation)
{
    $Change.ResourceRecordSet.GeoLocation = $GeoLocation
}
if ($HealthCheckId)
{
    $Change.ResourceRecordSet.HealthCheckId = $HealthCheckId
}
if ($SetIdentifier)
{
    $Change.ResourceRecordSet.SetIdentifier = $SetIdentifier
}
if ($TrafficPolicyInstanceId)
{
    $Change.ResourceRecordSet.TrafficPolicyInstanceId = $TrafficPolicyInstanceId
}
if ($Weight)
{
    $Change.ResourceRecordSet.Weight = $Weight
}

$Params = @{
    HostedZoneId = $HostedZoneId
    ChangeBatch_Comment = $Comment
    ChangeBatch_Change = $Change
    Force = $Force
}

Write-Verbose "Applying action ${Action} to Route53 Resource Set: name='$($Change.ResourceRecordSet.Name)'; type='$($Change.ResourceRecordSet.Type)'"
$ChangeInfo = Edit-R53ResourceRecordSet @Params

if (-not $ChangeInfo)
{
    throw "Action ${Action} failed on Route53 Record Set!"
}

if ($Timeout -gt 0)
{
    $Pause = 3
    $Timer = 0
    $ReadyStatus = "INSYNC"
    Write-Verbose "Testing Change ID, $($ChangeInfo.Id), every ${Pause} seconds until status is ${ReadyStatus}; will timeout in ${Timeout} seconds"
    do
    {
        sleep $Pause
        $Timer += $Pause
        $ChangeStatus = Get-R53Change $ChangeInfo.Id -Verbose:$False
        Write-Verbose "Change status is $($ChangeStatus.Status); timeout in $($Timeout-$Timer) seconds"
    }
    while ($ChangeStatus.Status -ne "$ReadyStatus" -and $Timer -le $Timeout)

    if ($Timer -ge $Timeout)
    {
        Write-Error "Timed out waiting $Timeout seconds; change status never became ${ReadyStatus}"
    }
    else
    {
        Write-Verbose "Route53 Record Set is ready: name='$($Change.ResourceRecordSet.Name)'; type='$($Change.ResourceRecordSet.Type)'"
        Write-Output $ChangeStatus
    }
}
else
{
    Write-Output $ChangeInfo
}
