if (-not $MyInvocation.MyCommand.Path) {
    Invoke-WebRequest -Uri "http://IP_ADDR:8000/win" -OutFile "C:\openrun.ps1" -UseBasicParsing
    Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File C:\openrun.ps1" -WindowStyle Normal
    exit
}

# Requires: PowerShell 5.1+, admin rights
Stop-Transcript -ErrorAction SilentlyContinue | out-null
Start-Transcript -path C:\openrunlogs.log -append

# Check admin rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires admin rights. Please run as administrator."
    Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
}

# Check Powershell version:
if ($PSVersionTable.PSVersion -lt [Version]"5.1") {
    Write-Host "PowerShell 5.1 or higher is required, installing..."
    exit(1)
}

# --------- Test Loop ---------

# if ($args.Count -gt 0 -and $args[0] -eq "debug") {
#     while ($true) {
#         $newProcesses = SniffPrograms
#         if ($newProcesses) {
#             $newProcesses | ForEach-Object {
#                 $process = $_.InputObject
#                 $parentProcess = $null
#                 try {
#                     $wmiObj = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($process.Id)" -ErrorAction SilentlyContinue
#                     if ($wmiObj -and $wmiObj.ParentProcessId) {
#                         $parentProcess = Get-Process -Id $wmiObj.ParentProcessId -ErrorAction SilentlyContinue
#                     }
#                 }
#                 catch {}
                
#                 $parentInfo = if ($parentProcess) { "Started by: $($parentProcess.Name) (PID: $($parentProcess.Id))" } else { "Parent process not found" }
#                 Write-Host "New process detected: $($process.ProcessName) (PID: $($process.Id)). Path: $($process.Path). $parentInfo"
#             }
#         }
#         $newRegistryEntries = SniffRegistry
#         if ($newRegistryEntries) {
#             $newRegistryEntries | ForEach-Object {
#                 $entry = $_
#                 Write-Host "New or modified registry entry detected: $($entry.PSPath)\$($entry.Name) - : $($entry.Value)"
#             }
#         }
#         $newNetworkEntries = SniffNetwork
#         if ($newNetworkEntries) {
#             $newNetworkEntries | ForEach-Object {
#                 $entry = $_
#                 Write-Host "New or modified network entry detected: $($entry.LocalAddress):$($entry.LocalPort) - $($entry.RemoteAddress):$($entry.RemotePort) [$($entry.Protocol)]"
#             }
#         }
#         Start-Sleep -Seconds 1
#     }
# }

# if ($args.Count -gt 0 -and $args[0] -eq "net")
# {
#         $newNetworkEntries = SniffNetwork
#         if ($newNetworkEntries) {
#             $newNetworkEntries | ForEach-Object {
#                 $entry = $_
#                 $hostName = Resolve-DnsName $entry.RemoteAddress -ErrorAction SilentlyContinue
#                 $address = $hostName.NameHost
#                 $proc = Get-Process -Id $entry.OwningProcess

#                 Write-Host "Network entry detected: $($entry.LocalAddress):$($entry.LocalPort) - $($entry.RemoteAddress):$($entry.RemotePort) [$($entry.Protocol)]. $($proc.Name). Hostname: $address"
#             }
#         }

# }
# if ($args.Count -gt 0 -and $args[0] -eq "reg")
# {
# while ($true) {
#         $newRegistryEntries = SniffRegistry
#         if ($newRegistryEntries) {
#             $newRegistryEntries | ForEach-Object {
#                 $entry = $_
#                 Write-Host "New or modified registry entry detected: $($entry.PSPath)\$($entry.Name) - : $($entry.Value)"
#             }
#         }
#         Start-Sleep -Seconds 2

# }
# }

# if ($args.Count -gt 0 -and $args[0] -eq "proc")
# {
#     while ($true) {
#         $newProcesses = SniffPrograms
#         if ($newProcesses) {
#             $newProcesses | ForEach-Object {
#                 $process = $_.InputObject
#                 $parentProcess = $null
#                 try {
#                     $wmiObj = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($process.Id)" -ErrorAction SilentlyContinue
#                     if ($wmiObj -and $wmiObj.ParentProcessId) {
#                         $parentProcess = Get-Process -Id $wmiObj.ParentProcessId -ErrorAction SilentlyContinue
#                     }
#                 }
#                 catch {}
                
#                 $parentInfo = if ($parentProcess) { "Started by: $($parentProcess.Name) (PID: $($parentProcess.Id))" } else { "Parent process not found" }
#                 Write-Host "New process detected: $($process.ProcessName) (PID: $($process.Id)). Path: $($process.Path). $parentInfo"
#             }
#         }
#         "new"
#         Start-Sleep -Seconds 2
#     }
# }


# --------- Add in Startup apps ---------


if (-not (Test-Path "C:\nssm\nssm.exe")) {
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile "$HOME\Desktop\nssm.zip" -ErrorAction SilentlyContinue -UseBasicParsing
    if (-not (Test-Path "$HOME\Desktop\nssm.zip")) {
        Write-Host "Failed to download nssm.zip, the service WON'T be available!"
    }
    else {
        if (-not (Test-Path "C:\nssm")) {
            New-Item -Path "C:\nssm" -ItemType Directory -Force | Out-Null
        }
        Expand-Archive -Path "$HOME\Desktop\nssm.zip" -DestinationPath "C:\nssm" -Force
        Move-Item -Path "C:\nssm\nssm-2.24\win64\nssm.exe" -Destination "C:\nssm\nssm.exe" -Force
    }
}

if (-not (Get-Service -Name "OpenRunService" -ErrorAction SilentlyContinue)) {
    $serviceName = "OpenRunService"
    $nssmPath = "C:\nssm\nssm.exe"
    $scriptPath = $MyInvocation.MyCommand.Path
    
    if (-not [System.IO.Path]::IsPathRooted($scriptPath)) {
        $scriptPath = (Resolve-Path $scriptPath).Path
    }

    if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($scriptPath.Replace('\', '\\'))`""
        
        & $nssmPath install $serviceName "powershell.exe" $arguments
        & $nssmPath set $serviceName AppNoConsole 1
        & $nssmPath set $serviceName AppStdout "$PSScriptRoot\openrunogs.txt"
        & $nssmPath set $serviceName AppStderr "$PSScriptRoot\openrunogs_err.txt"
        & $nssmPath set $serviceName AppEnvironmentExtra "MAIN_HOME=$HOME"
        Start-Sleep -Seconds 5
        sc.exe config $serviceName start= auto
        Start-Service $serviceName
        Write-Host "Service '$serviceName' installed and started."
    }
}

# --------- Check for mitmproxy ---------
$mitmproxyPath = "C:\Program Files\mitmproxy\bin\mitmproxy.exe"
if (-not (Test-Path $mitmproxyPath)) {
    $mitmproxyUrl = "https://downloads.mitmproxy.org/12.1.1/mitmproxy-12.1.1-windows-x86_64-installer.exe"
    Invoke-WebRequest -Uri $mitmproxyUrl -OutFile "$HOME\Desktop\mitmproxy_installer.exe" -ErrorAction SilentlyContinue -UseBasicParsing
    if (Test-Path "$HOME\Desktop\mitmproxy_installer.exe") {
        Add-Type -AssemblyName PresentationFramework
        $result = [System.Windows.MessageBox]::Show("Please install mitmproxy using all default options. Click OK to continue once installation is complete.", "mitmproxy Installation", "OK", "Information")
        if ($result -eq [System.Windows.MessageBoxResult]::OK) {
            Start-Process -FilePath "$HOME\Desktop\mitmproxy_installer.exe" -Wait
            Stop-Process -Name "mitmproxy" -ErrorAction SilentlyContinue -Force
        }
        else {
            exit(1)
        }
    }
}

$ppid = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID").ParentProcessId
$parent = (Get-Process -Id $ppid -ErrorAction SilentlyContinue).Name
if ($parent -ne 'nssm') {
    Write-Host "Not running under NSSM"
    # exit(1)
}
else {



    # --------- Prod Loop ----------
    # 3 background jobs: proc, reg, net

    $mitmproxyPyScript = @"
import mitmproxy
import urllib.request
import json
import threading

class MitmproxySender:
    def __init__(self):
        self._pending_requests = []
        # Config
        self.url = "http://IP_ADDR:8000/api/post/httpdump"
        # self.url = "http://localhost:8000/t.php"
        self.update_interval = 2
        self._timer = threading.Timer(self.update_interval, self.update_requ)
        self._timer.start()

    def update_requ(self):
        self._timer = threading.Timer(self.update_interval, self.update_requ)
        self._timer.start()
        if self._pending_requests:
            data = json.dumps(self._pending_requests)
            try:
                req = urllib.request.Request(self.url, data.encode("utf-8"), {"Content-Type": "application/json"})
                response = urllib.request.urlopen(req)
                print(f"Response from server: {response.read()}")
            except Exception as e:
                print(f"Error sending data to {self.url}: {e}")
            self._pending_requests = []


    def request(self, flow: mitmproxy.http.HTTPFlow):
        if (flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://")) and not "IP_ADDR" in flow.request.pretty_url:
            try:
                self._pending_requests.append({
                    "Url": flow.request.pretty_url,
                    "Method": flow.request.method,
                    "Headers": dict(flow.request.headers),
                    "Body": flow.request.content.decode("utf-8", errors="ignore"),
                })
            except Exception as e:
                print(f"Error fetching URL {flow.request.url}: {e}")

addons = [MitmproxySender()]
"@

    if (-not (Test-Path "$env:MAIN_HOME\mitmproxy_py.py")) {
        Set-Content -Path "$env:MAIN_HOME\mitmproxy_py.py" -Value $mitmproxyPyScript -Force
    }

    # --------- Set up mitmproxy certs ---------
    if (Test-Path $mitmproxyPath) {
        Write-Host "mitmproxy found at $mitmproxyPath."
        if (-not (Test-Path -Path "$env:MAIN_HOME\cert_installed.yes")) {
            Remove-Item -Path "$env:MAIN_HOME\.mitmproxy" -Recurse -Force -ErrorAction SilentlyContinue
            Start-Process -FilePath "$mitmproxyPath" -ArgumentList "--mode local" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            Invoke-WebRequest -Uri "http://mitm.it/cert/cer" -OutFile "$env:MAIN_HOME\Desktop\mitmproxy-ca-cert.cer" -ErrorAction SilentlyContinue -UseBasicParsing
            Stop-Process -Name "mitmproxy" -ErrorAction SilentlyContinue -Force
            $certutilResult = certutil -addstore root "$env:MAIN_HOME\Desktop\mitmproxy-ca-cert.cer"
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Error: certutil failed to add certificate to the root store."
                Write-Host "Please install the certificate manually by double-clicking on it and following the prompts."
                Stop-Process -Name "mitmproxy" -ErrorAction SilentlyContinue -Force
                # Even if it fails, we still create the cert_installed.yes file to avoid repeated attempts
                New-Item -Path "$env:MAIN_HOME\cert_installed.yes" -ItemType File -Force | Out-Null
                break
                return
            }
            else {
                New-Item -Path "$env:MAIN_HOME\cert_installed.yes" -ItemType File -Force | Out-Null
            }
        }
    }

    while ($true) {
        $serverResponse = Invoke-WebRequest -Uri "http://IP_ADDR:8000/currentsession" -Method Get -ErrorAction SilentlyContinue -UseBasicParsing
        if ($serverResponse.StatusCode -eq 200 -and $serverResponse.Content -ne "no") {
            $fileUrl = "http://IP_ADDR:8000/download"
            Invoke-WebRequest -Uri $fileUrl -Method Get -OutFile "$env:MAIN_HOME\Desktop\temp.zip" -ErrorAction SilentlyContinue -UseBasicParsing
            Expand-Archive -Path "$env:MAIN_HOME\Desktop\temp.zip" -DestinationPath "$env:MAIN_HOME\Desktop\temp" -Force
            Remove-Item -Path "$env:MAIN_HOME\Desktop\temp.zip"
            $sessionId = $serverResponse.Content
            $sessionActive = $true
            $sync = [System.Collections.Concurrent.ConcurrentDictionary[string, bool]]::new()
            $sync["active"] = $true

            $jobIds = @()

            function Is-SessionActive { return $sync["active"] }

            Register-EngineEvent -SourceIdentifier "SessionEnd" -Action { $sync["active"] = $false } | Out-Null

            # ------- HTTPS Sniffing ---------

            Start-Process -FilePath "C:\Program Files\mitmproxy\bin\mitmdump.exe" -ArgumentList "--mode", "local", "-s", "$env:MAIN_HOME\mitmproxy_py.py" -NoNewWindow -ErrorAction SilentlyContinue

            $jobIds += (Start-Job  -ScriptBlock {
                    param($sync)
                    function Is-SessionActive { return $sync["active"] }
                    function Send-JsonData {
                        param (
                            [string]$Type,
                            [object]$Data
                        )
                        $uri = "http://IP_ADDR:8000/api/post/$Type"
                        $json = $Data | ConvertTo-Json -Depth 50
                        try {
                            Invoke-RestMethod -Uri $uri -Method Post -Body $json -ContentType "application/json" -TimeoutSec 5 | Out-Null
                        }
                        catch {}
                    }

                    Stop-Transcript

                    Start-Transcript -path C:\openrun_job2logs.log -append
                    # ------- Process hierarchy sniffing -------

                    function Get-ProcessTree {
                        $allProcs = Get-WmiObject -Class Win32_Process | Select-Object -Property ProcessId, ParentProcessId, Name, CommandLine
                        $procDict = @{}
                        foreach ($proc in $allProcs) {
                            $procDict[$proc.ProcessId] = @{
                                name    = $proc.Name
                                pid     = $proc.ProcessId
                                cmdline = $proc.CommandLine
                                childs  = @()
                            }
                        }
                        foreach ($proc in $allProcs) {
                            if ($proc.ParentProcessId -ne 0 -and $procDict.ContainsKey($proc.ParentProcessId)) {
                                $parent = $procDict[$proc.ParentProcessId]
                                $child = $procDict[$proc.ProcessId]
                                $parent.childs += $child
                            }
                        }
                        $rootProcs = $procDict.Values | Where-Object {
                            $_.name -eq "explorer.exe"
                        }
                        return $rootProcs
                    }

                    while (Is-SessionActive) {
                        $tree = Get-ProcessTree
                        Send-JsonData -Type "proctree" -Data $tree
                        Start-Sleep -Seconds 5
                    }
                } -ArgumentList $sync)

            $jobIds += (Start-Job -ScriptBlock {
                    param($sync)
                    function Is-SessionActive { return $sync["active"] }
                    function Send-JsonData {
                        param (
                            [string]$Type,
                            [object]$Data
                        )
                        $uri = "http://IP_ADDR:8000/api/post/$Type"
                        $json = $Data | ConvertTo-Json -Depth 5
                        try {
                            Invoke-RestMethod -Uri $uri -Method Post -Body $json -ContentType "application/json" -TimeoutSec 5 | Out-Null
                        }
                        catch {}
                    }


                    # --------- Process Sniffing ---------

                    $lastProcessList = @()

                    function SniffPrograms {
                        param (
                        )
                        $processList = Get-Process | Select-Object -Property Path, ProcessName, Id
                        $newProcesses = Compare-Object -ReferenceObject $script:lastProcessList -DifferenceObject $processList -Property Path, ProcessName, Id | Where-Object { $_.SideIndicator -eq "=>" }
                        if ($script:lastProcessList.Count -eq 0) {
                            $script:lastProcessList = $processList
                            return @()
                        }
                        $script:lastProcessList = $processList
                        return $newProcesses
                    }
                    while (Is-SessionActive) {
                        $procs = SniffPrograms
                        if ($procs) {
                            $procs | ForEach-Object {
                                $process = $_
                                $parentProcess = $null
                                $commandLine = $null
                                try {
                                    $wmiObj = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($process.Id)" -ErrorAction SilentlyContinue
                                    if ($wmiObj -and $wmiObj.ParentProcessId) {
                                        $parentProcess = Get-Process -Id $wmiObj.ParentProcessId -ErrorAction SilentlyContinue
                                        $commandLine = $wmiObj.CommandLine
                                    }
                                }
                                catch {}
                                $parentInfo = if ($parentProcess) { @{ ParentProcessName = $parentProcess.Name; ParentProcessId = $parentProcess.Id } } else { @{ ParentProcessName = $null; ParentProcessId = $null } }
                                $process | Add-Member -MemberType NoteProperty -Name "ParentProcessName" -Value $parentInfo.ParentProcessName -Force
                                $process | Add-Member -MemberType NoteProperty -Name "ParentProcessId" -Value $parentInfo.ParentProcessId -Force
                                $process | Add-Member -MemberType NoteProperty -Name "CommandLine" -Value $commandLine -Force
                            }
                            $payload = $procs | Where-Object { -not ($_.ProcessName -eq "WmiPrvSE" -and $_.ParentProcessName -eq "svchost") }
                            Send-JsonData -Type "proc" -Data $payload
                        }
                        Start-Sleep -Seconds 2
                    }
                } -ArgumentList $sync)

            $jobIds += (Start-Job -ScriptBlock {
                    param($sync)
                    function Is-SessionActive { return $sync["active"] }
                    function Send-JsonData {
                        param (
                            [string]$Type,
                            [object]$Data
                        )
                        $uri = "http://IP_ADDR:8000/api/post/$Type"
                        $json = $Data | ConvertTo-Json -Depth 5
                        try {
                            Invoke-RestMethod -Uri $uri -Method Post -Body $json -ContentType "application/json" -TimeoutSec 5 | Out-Null
                        }
                        catch {}
                    }


                    # --------- Registry Sniffing ---------
                    $script:lastRegistryEntries = @()

                    function SniffRegistry {
                        param (
                            [string]$Hive = "HKEY_LOCAL_MACHINE"
                        )
            
                        $registryPaths = @(
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SYSTEM\CurrentControlSet\Services",
                            "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"
                        )
            
                        $registryEntries = @()
            
                        foreach ($path in $registryPaths) {
                            if (Test-Path $path) {
                                $RegistryValues = Get-ItemProperty -Path $path | Select-Object -Property *
                                $ValuesArray = @($RegistryValues.PSObject.Properties | Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSDrive" -and $_.Name -ne "PSProvider" })
                                $registryEntries += $ValuesArray
                            }
                        }
            
                        $normalizedLastEntries = $script:lastRegistryEntries | ForEach-Object {
                            $_ | Select-Object PSPath, Name, Value
                        }
            
                        $normalizedEntries = $registryEntries | ForEach-Object {
                            $_ | Select-Object PSPath, Name, Value
                        }
            
                        if ($normalizedLastEntries -eq $null) {
                            $normalizedLastEntries = @()
                        }
            
                        $newOrModified = Compare-Object -ReferenceObject $normalizedLastEntries -DifferenceObject $normalizedEntries -Property PSPath, Name, Value | Where-Object { $_.SideIndicator -eq "=>" }
            
                        if ($script:lastRegistryEntries.Count -eq 0) {
                            $script:lastRegistryEntries = $registryEntries
                            Write-Host "1st run, no previous entries"
                            return @()
                        }
            
                        $script:lastRegistryEntries = $registryEntries
                        return $newOrModified
                    }
                    while (Is-SessionActive) {
                        $regs = SniffRegistry
                        if ($regs) {
                            Send-JsonData -Type "reg" -Data $regs
                        }
                        Start-Sleep -Seconds 2
                    }
                } -ArgumentList $sync)

            $jobIds += (Start-Job -ScriptBlock {
                    param($sync)
                    function Is-SessionActive { return $sync["active"] }
                    function Send-JsonData {
                        param (
                            [string]$Type,
                            [object]$Data
                        )
                        $uri = "http://IP_ADDR:8000/api/post/$Type"
                        $json = $Data | ConvertTo-Json -Depth 5
                        try {
                            Invoke-RestMethod -Uri $uri -Method Post -Body $json -ContentType "application/json" -TimeoutSec 5 | Out-Null
                        }
                        catch {}
                    }


                    # --------- Network Sniffing ---------

                    $script:lastNetworkEntries = @()

                    function SniffNetwork {
                        param ()
                        $networkEntries = Get-NetTCPConnection | 
                        Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name = "Protocol"; Expression = { "TCP" } }, OwningProcess | 
                        Where-Object { $_.LocalAddress -ne "::" -and $_.LocalAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::" -and $_.RemoteAddress -ne "IP_ADDR" }
                        foreach ($entry in $networkEntries) {
                            try {
                                $proc = Get-Process -Id $entry.OwningProcess -ErrorAction SilentlyContinue
                                if ($proc) {
                                    $entry | Add-Member -MemberType NoteProperty -Name "OwningProcessName" -Value $proc.Name -Force
                                }
                                else {
                                    $entry | Add-Member -MemberType NoteProperty -Name "OwningProcessName" -Value "Unknown" -Force
                                }
                            }
                            catch {
                                $entry | Add-Member -MemberType NoteProperty -Name "OwningProcessName" -Value "Unknown" -Force
                            }
                            try {
                                $dnsEntry = Get-DnsClientCache | Where-Object { $_.Data -eq $entry.RemoteAddress } | Select-Object -First 1 -Property Entry
                                $entry | Add-Member -MemberType NoteProperty -Name "HostName" -Value $dnsEntry.Entry -Force
                            }
                            catch {
                                $entry | Add-Member -MemberType NoteProperty -Name "HostName" -Value "Unknown" -Force
                            }
                        }

                        $newOrModified = Compare-Object -ReferenceObject $script:lastNetworkEntries -DifferenceObject $networkEntries -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, Protocol, OwningProcess, OwningProcessName, HostName | Where-Object { $_.SideIndicator -eq "=>" }

                        if ($script:lastNetworkEntries.Count -eq 0) {
                            $script:lastNetworkEntries = $networkEntries
                            Write-Host "1st run, no previous entries"
                            return @()
                        }
                        $script:lastNetworkEntries = $networkEntries
            
                        return $newOrModified
                    }
                    # Schema: { "LocalAddress": "192.168.1.1", "LocalPort": 12345, "RemoteAddress": "93.184.216.34", "RemotePort": 80, "State": "Established", "Protocol": "TCP", "OwningProcess": 1234 }

                    while (Is-SessionActive) {
                        $nets = SniffNetwork
                        if ($nets) {
                            Send-JsonData -Type "net" -Data $nets
                        }
                        Start-Sleep -Seconds 2
                    }
                } -ArgumentList $sync)


            Register-EngineEvent -SourceIdentifier "SessionEnd" -Action { $sync["active"] = $false } | Out-Null

            while ($sessionActive) {
                Start-Sleep -Seconds 5
                $serverResponse = Invoke-WebRequest -Uri "http://IP_ADDR:8000/currentsession" -Method Get -ErrorAction SilentlyContinue -UseBasicParsing
                if ($serverResponse.StatusCode -ne 200 -or $serverResponse.Content.Trim() -eq "no") {
                    $sessionActive = $false
                    Unregister-EngineEvent -SourceIdentifier "SessionEnd" | Out-Null
                    Stop-Process -Name "mitmdump" -ErrorAction SilentlyContinue -Force
                    $sync["active"] = $false
                    foreach ($id in $jobIds) {
                        Write-Host "Stopping job with ID: $id"
                        Stop-Job -Id $id.Id -Force
                        Remove-Job -Id $id.Id -Force
                    }
                }
            }
        }
        Start-Sleep -Seconds 4
    }
    Stop-Transcript
}