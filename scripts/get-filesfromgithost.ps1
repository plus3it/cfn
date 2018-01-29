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
       (owner/repo//path/to/dir), and FilePath. The FilePath will include any
       file paths (relative to $Source) that you want to download. Optionally,
       you may specify a Ref (default: master), Destination (default: current directory),
       or the GitHost (default: https://raw.githubusercontent.com)
    .EXAMPLE
       # Get files from the root of a remote git repository:

       Get-FilesFromGitHost -Source 'owner/repo' -FilePath 'foo.psm1', 'foo.psd1'
     .EXAMPLE
        # Get files from a subdirectory within a remote git repository (note the '//' separator):

        Get-FilesFromGitHost -Source 'owner/repo//path/to/directory' -FilePath 'foo.psm1', 'foo.psd1'
    #>
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Please provide the module source
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Source,

        # Please provide a list of filepaths to download, relative to $Source
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string[]]$FilePath,

        # Please provide the destination directory (will be created)
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [string]$Destination = ".",

        # Please provide a git ref
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=3)]
        [string]$Ref = 'master',

        # Please provide the remote git host url for downloading raw files
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=4)]
        [string]$GitHost = "https://raw.githubusercontent.com"
    )

    Begin
    {
        $Slug, $RepoPath = $Source -Split '//'
        $Owner, $Repo = $Slug -Split '/'
        $BaseUrl = "${GitHost}/${Slug}/${Ref}/${RepoPath}".TrimEnd('/')

        if (-not ($Owner) -or -not ($Repo))
        {
            throw "Malformed `$Source! Must at least include the owner and repo, formatted as: <owner>/<repo>"
        }

        Write-Verbose "Creating directory: ${Destination}"

        New-Item -Type Container -Force -Path $Destination | Out-Null

        Write-Verbose "Downloading files..."
        Write-Verbose ("{0,4}Source: {1}" -f "", $BaseUrl)
        Write-Verbose ("{0,4}Destination: {1}" -f "", $Destination)

        $wc = New-Object System.Net.WebClient

        $wc.Encoding = [System.Text.Encoding]::UTF8

    }
    Process
    {
        foreach ($File in $FilePath)
        {
            Write-Verbose ("{0,4}Processing file: {1}" -f "", $File)

            Write-Debug ("{0,4}Attempting to create: {1}\{2}" -f "", $Destination, $File)

            New-Item -ItemType File -Force -Path "${Destination}\${File}" | Out-Null

            $Url = "${BaseUrl}/${File}"

            Write-Debug ("{0,4}Attempting to download from: {1}" -f "", $Url)

            ($wc.DownloadString("$Url")) | Out-File "${Destination}\${File}"
        }
    }
    End
    {
    }
}
