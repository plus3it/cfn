# Credit: https://github.com/MSAdministrator/GetGithubRepository

function Get-FilesFromGitHost
{
    <#
    .SYNOPSIS
        This function will download files over HTTP from a remote git repository
        without using Git
    .DESCRIPTION
        This function will download files over HTTP from a remote git repository
        without using Git. At a minimum, you will need to provide the Source
        (https://github.com/owner/repo/path/to/dir). Optionally, you may specify
        Ref (default: $null, determined by remote git host), or Destination
        (default: current directory).
    .EXAMPLE
        # Get files from the root of a GitHub repository:

        Get-FilesFromGitHost -Source 'https://github.com/owner/repo'
    .EXAMPLE
        # Get files from a subdirectory within a GitHub repository:

        Get-FilesFromGitHost -Source 'https://github.com/owner/repo/path/to/directory'
    #>
    [CmdletBinding()]
    Param
    (
        # Please provide the remote git source (https://github.com/owner/repo/path/to/dir)
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0
        )]
        [string]$Source,

        # Please provide the git ref
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            Position=1
        )]
        [string]$Ref,

        # Please provide the destination directory (will be created)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            Position=2
        )]
        [string]$Destination = "."
    )
    Begin
    {
        $Uri = [System.Uri]$Source
        $RepoPath = ($Uri.Segments[3..($Uri.Segments.Length)] -Join "").TrimEnd('/')
        $Destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)

        Write-Verbose "Creating destination directory: ${Destination}"

        New-Item -Type Container -Force -Path $Destination | Out-Null

        Write-Verbose "Downloading files..."
        Write-Verbose ("{0,4}Source: {1}" -f "", $Source)
        Write-Verbose ("{0,4}Destination: {1}" -f "", $Destination)

        $wc = New-Object System.Net.WebClient
        $wc.Encoding = [System.Text.Encoding]::UTF8
    }
    Process
    {
        List-GitFiles -Source $Source -Ref $Ref | % {
            $FilePath, $DownloadUrl = $_.Path, $_.DownloadUrl
            if ($FilePath -eq $RepoPath)
            {
                # Source is a single file, we just need the leaf
                $FilePath = "${Destination}\$(Split-Path -Leaf $FilePath)"
            }
            else
            {
                # Strip the leading repo path from the file path
                $FilePath = "${Destination}\$($FilePath -replace "^$RepoPath/")"
            }

            Write-Verbose ("{0,4}Processing file: {1}" -f "", $DownloadUrl)

            Write-Debug ("{0,4}Attempting to create: {1}" -f "", $FilePath)

            $File = New-Item -ItemType File -Force -Path ${FilePath}

            Write-Debug ("{0,4}Attempting to download from: {1}" -f "", $DownloadUrl)

            ($wc.DownloadString("$DownloadUrl")) | Out-File $File

            $File
        }
    }
}

function Get-GitHostApiMethod
{
    [CmdletBinding()]
    Param
    (
        # Please provide the api method call
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0
        )]
        [string]$MethodType,

        # Please provide the remote git host
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            Position=1
        )]
        [string]$SourceHost
    )
    Begin
    {
        $ApiMethodMap = @{
            "github.com" = @{
                "ListFiles" = "List-GitHubFiles"
            }
        }

        $ApiMethodMap[$SourceHost][$MethodType]
    }
}

function List-GitFiles
{
    [CmdletBinding()]
    Param
    (
        # Please provide the remote git source
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0
        )]
        [string]$Source,

        # Please provide the git ref
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            Position=1
        )]
        [string]$Ref
    )
    Begin
    {
        $Uri = [System.Uri]$Source
        $SourceHost = $Uri.Host
        $MethodArgs = @{
            Owner = $Uri.Segments[1].TrimEnd('/')
            Repo = $Uri.Segments[2].TrimEnd('/')
            RepoPath = ($Uri.Segments[3..($Uri.Segments.Length)] -Join "").TrimEnd('/')
            Ref = $Ref
        }

        $Method = Get-GitHostApiMethod -MethodType "ListFiles" -SourceHost $SourceHost
    }
    Process
    {
        & $Method @MethodArgs
    }
}

function List-GitHubFiles
{
    [CmdletBinding()]
    Param
    (
        # Please provide the remote git api uri to a repo/path
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ApiUri",
            Position=0
        )]
        [string]$ApiUri,

        # Please provide the repo owner
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="NoApiUri",
            Position=0
        )]
        [string]$Owner,

        # Please provide the repo name
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="NoApiUri",
            Position=1
        )]
        [string]$Repo,

        # Please provide the repo path
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="NoApiUri",
            Position=2
        )]
        [string]$RepoPath,

        # Please provide the api host
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="NoApiUri",
            Position=3
        )]
        [string]$ApiHost = "api.github.com",

        # Please provide the git ref
        [Parameter(
            Mandatory=$false,
            ParameterSetName="NoApiUri",
            ValueFromPipelineByPropertyName=$true,
            Position=4
        )]
        [string]$Ref
    )
    Begin
    {
        if ($PsCmdlet.ParameterSetName -eq "NoApiUri")
        {
            $ApiUri = "https://${ApiHost}/repos/${Owner}/${Repo}/contents/${RepoPath}"
            $ApiUri = if ($Ref) { "${ApiUri}?ref=${Ref}" } else { $ApiUri }
        }
        $Items = (Invoke-WebRequest -Uri $ApiUri).Content | ConvertFrom-JSON
    }
    Process
    {
        foreach ($Item in $Items)
        {
            switch ($Item.type)
            {
                "file"
                {
                    @{
                        Path = $Item.path
                        DownloadUrl = $Item.download_url
                    }
                }
                "dir"
                {
                    List-GitHubFiles -ApiUri $Item.url
                }
                default
                {
                    Write-Warning "Unknown item type: ${Item.type}"
                    Write-Warning "    Url: ${Item.html_url}"
                }
            }
        }
    }
}
