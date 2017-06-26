[CmdLetBinding()]
Param(
  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $DomainNetBiosName,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $DomainSvcAccount,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $DomainSvcPassword,

  [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String[]] $Command,

  [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
  [String] $PsExec = "c:\cfn\files\pstools\psexec.exe"
)

$PsExecBaseArguments = @(
    "-accepteula"
    "-nobanner"
    "-h"
    "-u `"${DomainNetbiosName}\${DomainSvcAccount}`""
    "-p `"${DomainSvcPassword}`""
)

$PsExecArguments = $PsExecBaseArguments + $Command

$ret = Start-Process -FilePath "${PsExec}" -ArgumentList $PsExecArguments -NoNewWindow -PassThru -Wait

# Test the return
if ($ret.ExitCode -ne "0")
{
    throw "Failed to execute command! Exit code was $($ret.ExitCode)"
}
else
{
    Write-Verbose "Command completed successfully!"
}
