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

function global:Test-RetryNetConnection {
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        [string[]]
        $ComputerName,

        [Parameter(Mandatory=$false)]
        [string]
        $CheckExpression = '$? -and $Return.Result.TcpTestSucceeded',

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
    BEGIN {
        $ValidComputers = @()
        $StaleComputers = @()
    }
    PROCESS {
        ForEach ($computer in $ComputerName)
        {
            Write-Verbose ("Testing connectivity to server: {0}" -f $computer)
            try
            {
                $null = Invoke-RetryCommand -Command Test-NetConnection -ArgList @{ComputerName=$computer; CommonTCPPort="RDP"} -CheckExpression $CheckExpression -Tries $Tries
                Write-Verbose ("Successfully connected to server: {0}" -f $computer)
                Write-Output @{ ValidComputers = $computer }
                $ValidComputers += $computer
            }
            catch
            {
                Write-Verbose ("Server is not available, marked as stale: {0}" -f $computer)
                Write-Output @{ StaleComputers = $computer }
                $StaleComputers += $computer
            }
        }
    }
    END {
        Write-Verbose "Valid Computers:"
        $ValidComputers | ForEach-Object { Write-Verbose "*    $_" }
        Write-Verbose "Stale Computers:"
        $StaleComputers | ForEach-Object { Write-Verbose "*    $_" }
    }
}

function global:Edit-AclIdentityReference {
    Param(
        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.DirectorySecurity]
        $Acl,

        [Parameter(Mandatory=$false)]
        [string[]]
        $IdentityReference,

        [Parameter(Mandatory=$false)]
        [string]
        $IdentityFilter = "(?i).*\\.*[$]$",

        [Parameter(Mandatory=$false)]
        [string]
        $FileSystemRights = "FullControl",

        [Parameter(Mandatory=$false)]
        [string]
        $InheritanceFlags = "ContainerInherit, ObjectInherit",

        [Parameter(Mandatory=$false)]
        [string]
        $PropagationFlags = "None",

        [Parameter(Mandatory=$false)]
        [string]
        $AccessControlType = "Allow"
    )
    BEGIN {
        $AclIdentities = @($Acl.Access.IdentityReference.Value) | Where-Object { $_ -match $IdentityFilter }

        # Test if ACL contains only matching identity references
        $DiffIdentities = Compare-Object $IdentityReference $AclIdentities

        # Skip further processing if there are no differences
        if (-not $DiffIdentities)
        {
            Write-Verbose "ACL contains only matching identities, no changes needed..."
            return
        }

        # Identity in ACL but not in $IdentityReference; need to remove
        $RemoveIdentities = $DiffIdentities | Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object { $_.InputObject }

        # Identity in $IdentityReference but not in ACL; need to add
        $AddIdentities = $DiffIdentities | Where-Object { $_.SideIndicator -eq "<=" } | ForEach-Object { $_.InputObject }

        # Remove rules for identity references not present in $IdentityReference
        foreach ($Rule in $Acl.Access)
        {
            $Identity = $Rule.IdentityReference.Value

            if ($Identity -in $RemoveIdentities)
            {
                Write-Verbose "Identity is NOT VALID, removing rule:"
                Write-Verbose "*    Rule Identity: $Identity"
                $null = $Acl.RemoveAccessRule($Rule)
            }
        }

        # Add rules for identity references in $IdentityReference that are missing from the ACL
        foreach ($Identity in $AddIdentities)
        {
            Write-Verbose "Adding missing access rule to ACL:"
            Write-Verbose "*    Rule Identity: $Identity"
            $null = $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $Identity,
                $FileSystemRights,
                $InheritanceFlags,
                $PropagationFlags,
                $AccessControlType
            )))
        }

        # Output the new ACL
        Write-Verbose ($Acl.Access | Out-String)
        Write-Output $Acl
    }
}

function global:Get-File {
    Param (
        [Parameter(Mandatory=$true)]
        [System.URI]
        $Source,

        [Parameter(Mandatory=$true)]
        [System.IO.FileInfo]
        $Destination,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Ssl3","SystemDefault","Tls","Tls11","Tls12")]
        [String]
        $SecurityProtocol = "Tls12",

        [Parameter(Mandatory=$false)]
        [Switch]
        $MakeDir,

        [Parameter(Mandatory=$false)]
        [Switch]
        $OverWrite
    )
    try {
        $ResolvedDestination = [System.IO.FileInfo]$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
        $TempFile = New-TemporaryFile

        Write-Verbose "Retrieving file:"
        Write-Verbose "*    Source: ${Source}"
        Write-Verbose "*    Destination: ${ResolvedDestination}"
        Write-Verbose "*    Temporary Destination: ${TempFile}"

        try
        {
            Write-Verbose "Attempting to retrieve file using .NET method..."
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::$SecurityProtocol
            (New-Object Net.WebClient).DownloadFile("$Source","$TempFile")
        }
        catch
        {
            try
            {
                Write-Verbose $PSItem.ToString()
                Write-Verbose ".NET method failed, attempting BITS transfer method..."
                Start-BitsTransfer -Source $Source -Destination $TempFile -ErrorAction Stop
            }
            catch
            {
                Write-Verbose $PSItem.ToString()
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
        }

        If (-not $ResolvedDestination.Directory.Exists -and $MakeDir) {
            $null = New-Item -Path $ResolvedDestination.Directory -ItemType Directory
        }

        Move-Item $TempFile $ResolvedDestination -Force:$OverWrite -ErrorAction Stop
        Write-Verbose "Retrieved file successfully!"
        Write-Output (Get-ChildItem $ResolvedDestination)
    }
    finally
    {
        if (Test-Path $TempFile)
        {
            Remove-Item -Path $TempFile -Force
        }
    }
}

function global:New-RepeatingTask {
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String]
    $Name,

    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String[]]
    $Arguments,

    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String]
    $User,

    [Parameter(Mandatory=$true,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [SecureString]
    $SecurePassword,

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [String]
    $Command = "powershell.exe",

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [DateTime]
    $StartTime = (Get-Date).Date,

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [TimeSpan]
    $RepetitionInterval = (New-TimeSpan -Hours 1),

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [TimeSpan]
    $RandomDelay = (New-TimeSpan -Minutes 10),

    [Parameter(Mandatory=$false,ValueFromPipeLine=$false,ValueFromPipeLineByPropertyName=$false)]
    [Switch]
    $Force
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

    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $User, $SecurePassword
    $Password = $Credentials.GetNetworkCredential().Password
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
}
