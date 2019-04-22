function global:Invoke-RetryCommand {
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $Command,

        [Parameter(Mandatory=$false)]
        $ArgList = @{},

        [Parameter(Mandatory=$false)]
        [string]
        $CheckExpression = '$? -and $Return.Result',

        [Parameter(Mandatory=$false)]
        [int]
        $Tries = 5,

        [Parameter(Mandatory=$false)]
        [int]
        $InitialDelay = 2,  # in seconds

        [Parameter(Mandatory=$false)]
        [int]
        $MaxDelay = 32  # in seconds
    )
    Begin {
        $TryCount = 0
        $Delay = $InitialDelay
        $Completed = $false
        $MsgFailed = "Command FAILED: {0}" -f $Command
        $MsgSucceeded = "Command SUCCEEDED: {0}" -f $Command
        $ArgString = if ($ArgList -is [Hashtable]) { $ArgList | Select-Object -Property * | Out-String } else { $ArgList -join " "}
        $Return = @{Result=$Null}

        Write-Verbose ("Tries: {0}" -f $Tries)
        Write-Verbose ("Command: {0}" -f $Command)
        Write-Verbose ("ArgList: {0}" -f $ArgString)
    }
    Process {
        while (-not $Completed)
        {
            try
            {
                $Return.Result = & $Command @ArgList
                if (-not (Invoke-Expression $CheckExpression))
                {
                    throw $MsgFailed
                }
                else
                {
                    Write-Verbose $MsgSucceeded
                    Write-Output $Return.Result
                    $Completed = $true
                }
            }
            catch
            {
                $TryCount++
                if ($TryCount -ge $Tries)
                {
                    $Completed = $true
                    Write-Output $Return.Result
                    Write-Warning ($PSItem | Select-Object -Property * | Out-String)
                    Write-Warning ("Command failed the maximum number of {0} time(s)." -f $Tries)
                    $PSCmdlet.ThrowTerminatingError($PSItem)
                }
                else
                {
                    $Msg = $PSItem.ToString()
                    if ($Msg -ne $MsgFailed) { Write-Warning $Msg }
                    Write-Warning ("Command failed. Retrying in {0} second(s)." -f $Delay)
                    Start-Sleep $Delay
                    $Delay *= 2
                    $Delay = [Math]::Min($MaxDelay, $Delay)
                }
            }
        }
    }
    End {}
}
