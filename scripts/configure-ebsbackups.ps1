[CmdLetBinding()]
Param(
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [ValidateScript({Test-Path $_ -PathType Leaf })]
    [String] $SnapshotScript,

    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [ValidateScript({Test-Path $_ -PathType Leaf })]
    [String] $MaintenanceScript,

    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $ConsistencyGroup,

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [TimeSpan] $SnapShotFrequency = (New-TimeSpan -Hours 1),

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [TimeSpan] $SnapShotDelay = (New-TimeSpan -Minutes 10),

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String] $MaintenanceKeepDays = "30",

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [TimeSpan] $MaintenanceFrequency = (New-TimeSpan -Days 1),

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [TimeSpan] $MaintenanceDelay = (New-TimeSpan -Minutes 60),

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [Switch] $Force
)

Function Init-BackupJob
{
    [CmdLetBinding()]
    Param(
      [Parameter(Mandatory=$true)]
      [String] $Name,
      [Parameter(Mandatory=$true)]
      [String] $Command,
      [Parameter(Mandatory=$true)]
      [TimeSpan] $Frequency,
      [Parameter(Mandatory=$true)]
      [TimeSpan] $Delay,
      [Parameter(Mandatory=$false)]
      [Switch] $Force
    )
    $Job = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($Job)
    {
        if ($Force)
        {
            UnRegister-ScheduledTask -TaskName $Name -Confirm:$false
            Write-Verbose "Force-unregistered existing job, ${Name}"
        }
        else
        {
            throw "Task already exists, ${Name}. Use '-Force' to delete it"
        }
    }
    $When = (Get-Date).Date
    $Action = New-ScheduledTaskAction -Execute powershell.exe -Argument $Command
    $Trigger = New-JobTrigger -Once -At $When -RepeatIndefinitely -RepetitionInterval $Frequency -RandomDelay $Delay
    $Principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -MultipleInstances Parallel
    Register-ScheduledTask -TaskName $Name -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
    Write-Verbose "Created scheduled job, ${Name}"
    Start-ScheduledTask -TaskName $Name
    Write-Verbose "Triggered job, ${Name}"
}

$Jobs = @(
    @{
        Name = "Snapshot ${ConsistencyGroup}"
        Command = "${SnapshotScript} ${ConsistencyGroup}"
        Frequency = $SnapShotFrequency
        Delay = $SnapshotDelay
        Force = $Force
    },
    @{
        Name = "Snapshot Maintenance ${ConsistencyGroup}"
        Command = "${MaintenanceScript} -keepdays ${MaintenanceKeepDays} -snapgrp ${ConsistencyGroup}"
        Frequency = $MaintenanceFrequency
        Delay = $MaintenanceDelay
        Force = $Force
    }
)

foreach ($Job in $Jobs)
{
    Init-BackupJob @Job
}
