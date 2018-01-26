function global:Update-RDMS {
    Begin{}
    Process{
        Write-Debug "Starting Update-RDMS"
        Write-Debug "Import RDS cmdlets"
        Import-Module RemoteDesktop
        $ConnectionBrokers = Get-RDServer | Where-Object {$_.Roles -contains "RDS-CONNECTION-BROKER"}
        $ServerManagerXML = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\ServerManager\Serverlist.xml"
                Write-Debug "Find active Connection Broker"
        $ActiveManagementServer = $null
        foreach($Broker in $ConnectionBrokers.Server){
            $ActiveManagementServer = (Test-NetConnection -ComputerName $Broker | Where-Object {$_.PingSucceeded -eq 'True'})
            if($ActiveManagementServer -eq $null){
                Write-Host "Unable to contact $Broker" -ForegroundColor Yellow
            } else {
                break
            }
        }
        if($ActiveManagementServer -eq $null){
            Write-Error "Unable to contact any Connection Broker"
        }else{
            if(Get-Process -Name ServerManager -ErrorAction SilentlyContinue){
                Write-Debug "Kill Server Manager"
                # Have to use tskill as stop-process gives an "Access Denied" with ServerManager
                Start-Process -FilePath "$env:systemroot\System32\tskill.exe" -ArgumentList "ServerManager"
            }
            Write-Debug "Get RD servers"
            $RDServers = Get-RDServer -ConnectionBroker $ActiveManagementServer.ComputerName
            Write-Debug "Get Server Manager XML"
            [XML]$SMXML = Get-Content -Path $ServerManagerXML
            foreach($RDServer in $RDServers){
                $Found = $false
                Write-Host ("Checking "+$RDServer.Server+" ") -NoNewline -ForegroundColor Gray
                foreach($Server in $SMXML.ServerList.ServerInfo){
                    if($RDServer.Server -eq $Server.name){
                        $Found = $true
                    }
                }
                if($Found -eq $true){
                    Write-Host "OK" -ForegroundColor Green
                }else{
                    Write-Host "Missing" -ForegroundColor Yellow
                    $NewServer = $SMXML.CreateElement("ServerInfo")
                    $SMXML.ServerList.AppendChild($NewServer) | Out-Null
                    $NewServer.SetAttribute("name",$RDServer.Server)
                    $NewServer.SetAttribute("status","1")
                    $NewServer.SetAttribute("lastUpdateTime",[string](Get-Date -Format s))
                    $NewServer.SetAttribute("locale","en-GB")
                }
            }
            # Remove xmlns attribute on any newly added servers, this is added automatically by PowerShell but causes Server Manager to reject the new server
            $SMXML = $SMXML.OuterXml.Replace(" xmlns=`"`"","")
            Write-Debug "Save XML file"
            $SMXML.Save($ServerManagerXML)
            Write-Debug "Start Server Manager"
            Start-Process -FilePath "$env:systemroot\System32\ServerManager.exe"
        }
    }
    End{}
}
