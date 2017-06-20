[CmdLetBinding()]
Param(
  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $Name,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String[]] $Arguments,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $User,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $Password,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $Command = "powershell.exe",

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [DateTime] $StartTime = (Get-Date).Date,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [TimeSpan] $RepetitionInterval = (New-TimeSpan -Hours 1),

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [TimeSpan] $RandomDelay = (New-TimeSpan -Minutes 10),

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [Switch] $Force
)

if (Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue)
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

$Action = New-ScheduledTaskAction -Execute $Command -Argument "$Arguments"
$Trigger = New-JobTrigger -Once -At $StartTime -RepeatIndefinitely -RepetitionInterval $RepetitionInterval -RandomDelay $RandomDelay
$Settings = New-ScheduledTaskSettingsSet -MultipleInstances Parallel
Register-ScheduledTask -TaskName $Name -Action $Action -Trigger $Trigger -User $User -Password $Password -RunLevel Highest -Settings $Settings
Write-Verbose "Created scheduled job, ${Name}"

if ($StartTime.CompareTo((Get-Date)) -le 0)
{
    # Start time is now or in the past, trigger job immediately
    Start-ScheduledTask -TaskName $Name
    Write-Verbose "Triggered job, ${Name}"
}
