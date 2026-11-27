#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server, [switch]$UseSsl,
    [ValidateRange(1,65535)][int]$Port,
    [switch]$EndpointScan, [string]$LogDirectory, [uri]$ClientWsusUrl,
    [ValidateRange(1,1440)][int]$CacheMinutes=5,
    [ValidateRange(1,1440)][int]$ReportGraceMinutes=15
)
$ErrorActionPreference = 'Stop'

function StartDesktopPowerShell($path,$parameters) {
    $shell=Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
    if (![IO.File]::Exists($shell)) { throw 'Windows PowerShell 5.1 is required for the WSUS console.' }
    $policy=& $shell -NoProfile -NonInteractive -Command 'Get-ExecutionPolicy'
    if ($policy -eq 'Restricted') {
        throw 'Windows PowerShell 5.1 blocks script execution (Restricted). The GUI runs in 5.1. Ask your administrator for the permitted script launch method for this computer.'
    }
    if ($policy -eq 'AllSigned' -and (Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid') {
        throw 'Windows PowerShell 5.1 requires a signed script (AllSigned). Use an approved, signed copy of WSUS-Manager.'
    }
    $forwarded=@{}
    foreach ($key in $parameters.Keys) {
        $value=$parameters[$key]
        $forwarded[$key]=if ($value -is [Management.Automation.SwitchParameter]) { [bool]$value } else { $value }
    }
    $xml=[Management.Automation.PSSerializer]::Serialize(@{Path=$path; Parameters=$forwarded})
    $payload=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($xml))
    $command=@"
`$launch = [Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$payload')))
`$launchParameters = `$launch.Parameters
& `$launch.Path @launchParameters
"@
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    & $shell -NoProfile -STA -EncodedCommand $encoded
    if ($LASTEXITCODE) { throw "Windows PowerShell 5.1 exited with code $LASTEXITCODE." }
}
if ($PSVersionTable.PSEdition -eq 'Core' -and !$EndpointScan) {
    StartDesktopPowerShell $PSCommandPath $PSBoundParameters
    return
}

$folder = Join-Path $env:LOCALAPPDATA 'WSUS-Manager'
[void][IO.Directory]::CreateDirectory($folder)
$logSettingsPath=Join-Path $folder 'AuditLogSettings.json'
$fileLogName='WSUS-{0}-{1:yyyyMMdd-HHmmss}-{2}.jsonl' -f $env:COMPUTERNAME,(Get-Date),[guid]::NewGuid()
$localFileLog=Join-Path $folder $fileLogName
if (!$LogDirectory -and [IO.File]::Exists($logSettingsPath)) {
    try { $LogDirectory=[string](ConvertFrom-Json ([IO.File]::ReadAllText($logSettingsPath))).Directory }
    catch { Write-Warning "Audit log settings could not be read. Using the local log. $($_.Exception.Message)" }
}
if (!$LogDirectory) { $LogDirectory=$folder }
$LogDirectory=if ([IO.Path]::IsPathRooted($LogDirectory)) { [IO.Path]::GetFullPath($LogDirectory) }
    else { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogDirectory) }
$fileLog=[IO.Path]::Combine($LogDirectory,$fileLogName)
$script:auditServer = if ($Server) { $Server } else { $env:COMPUTERNAME }
function Write-Audit {
    param($path,$serverName,$operation,$action,$status,$details,$fallbackPath,$auditState)
    $entry = [ordered]@{utc=[datetime]::UtcNow.ToString('o'); user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
        workstation=$env:COMPUTERNAME; server=$serverName; operationId=$operation; action=$action; status=$status; details=$details}
    $utf8=[Text.UTF8Encoding]::new($false)
    if (!$auditState -or !$auditState.Error) {
        try {
            if (!$auditState -or !$auditState.DirectoryReady) {
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
                if ($auditState) { $auditState.DirectoryReady=$true }
            }
            [IO.File]::AppendAllText($path,(ConvertTo-Json $entry -Depth 8 -Compress)+[Environment]::NewLine,$utf8)
            return
        } catch {
            if (!$fallbackPath -or $fallbackPath -eq $path) { throw }
            if ($auditState) { $auditState.Error=$_.Exception.GetBaseException().Message }
            Write-Warning "Configured audit log is unavailable. Using $fallbackPath."
        }
    }
    $entry.preferredLog=$path
    [IO.File]::AppendAllText($fallbackPath,(ConvertTo-Json $entry -Depth 8 -Compress)+[Environment]::NewLine,$utf8)
}
$scanBlock = {
    param([string]$ExpectedUrl,[bool]$CheckOnly=$false,[bool]$RequestDetection=$false,
        [string]$ExpectedMachineGuid,[string]$ExpectedClientId)
    $ErrorActionPreference = 'Stop'
    $policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    if (!$policy.WUServer -or $au.UseWUServer -ne 1) { throw 'No active WSUS policy was found.' }
    if ($ExpectedUrl) {
        $expected = [uri]$ExpectedUrl
        foreach ($address in @($policy.WUServer,$policy.WUStatusServer)) {
            if (!$address) { throw 'The update server or reporting server is missing from the policy.' }
            $actual = [uri]$address
            if ($expected.AbsoluteUri.TrimEnd('/') -ne $actual.AbsoluteUri.TrimEnd('/')) {
                throw "WSUS policy mismatch: $actual (expected $expected)."
            }
        }
    }
    if ($CheckOnly -or $ExpectedMachineGuid -or $ExpectedClientId) {
        $identity = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography'
        $client = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate'
        $machineGuid=[string]$identity.MachineGuid
        $clientId=([string]$client.SusClientId).Trim('{}')
        if (($ExpectedMachineGuid -and $ExpectedMachineGuid -ne $machineGuid) -or
            ($ExpectedClientId -and $ExpectedClientId -ne $clientId)) { throw 'The endpoint identity changed before the scan.' }
        if ($CheckOnly) {
            return [pscustomobject]@{MachineGuid=$machineGuid; ClientId=$clientId; WsusUrl=[string]$policy.WUServer
                TargetingEnabled=($policy.TargetGroupEnabled -eq 1); TargetGroup=[string]$policy.TargetGroup}
        }
    }
    $detection='Not requested'; $detectionError=''; $searchError=''
    if ($RequestDetection) {
        $detection='Requested'
        try { [void](New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow() }
        catch {
            $errorDetail=$_.Exception.GetBaseException()
            $detection='Failed'; $detectionError='0x{0:X8} | {1}' -f $errorDetail.HResult,$errorDetail.Message
        }
    }
    $searchStatus='Succeeded'
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $search = $session.CreateUpdateSearcher()
        $search.ServerSelection = 1 # ssManagedServer
        $search.Online = $true
        $result = $search.Search('IsInstalled=0')
        if ([int]$result.ResultCode -ne 2) {
            $warnings=@(foreach ($warning in $result.Warnings) { '0x{0:X8} {1}' -f $warning.HResult,$warning.Message })
            throw "WUA result $($result.ResultCode) | $($warnings -join ', ')"
        }
        $summary="Update search completed on $env:COMPUTERNAME. Outstanding updates: $($result.Updates.Count)."
    } catch {
        $errorDetail=$_.Exception.GetBaseException(); $searchStatus='Failed'
        $searchError='0x{0:X8} | {1}' -f $errorDetail.HResult,$errorDetail.Message
        $summary="Update search failed: $searchError"
    }
    if ($detectionError) { $summary+=" | Detection request failed: $detectionError" }
    [pscustomobject]@{Detection=$detection; DetectionError=$detectionError; Search=$searchStatus; SearchError=$searchError; Message=$summary}
}
if ($EndpointScan) {
    $id = [guid]::NewGuid().ToString()
    $auditState=@{Error=''}
    Write-Audit $fileLog $script:auditServer $id 'Local scan' 'Started' $env:COMPUTERNAME $localFileLog $auditState
    try {
        $outcome = & $scanBlock ([string]$ClientWsusUrl)
        $message=$outcome.Message
        if ($outcome.Search -eq 'Failed') { throw $message }
    }
    catch { Write-Audit $fileLog $script:auditServer $id 'Local scan' 'Error' $_.Exception.Message $localFileLog $auditState; throw }
    Write-Audit $fileLog $script:auditServer $id 'Local scan' 'OK' $message $localFileLog $auditState
    Write-Host $message
    return
}

Add-Type -AssemblyName System.Windows.Forms,System.Drawing
if (!(Get-Module -ListAvailable -Name UpdateServices)) {
    throw 'The UpdateServices module is missing. Run the console on a computer with the WSUS management tools installed.'
}
[Windows.Forms.Application]::EnableVisualStyles()
[void][IO.Directory]::CreateDirectory($folder)
$fileRules = Join-Path $folder 'Ausschluesse.txt'
$encoding = New-Object Text.UTF8Encoding($false)
$connect = @{}
if ($Server -or $UseSsl -or $Port) {
    $connect.Name = if ($Server) { $Server } else { $env:COMPUTERNAME }
    $connect.UseSsl = [bool]$UseSsl
    $connect.PortNumber = if ($Port) { $Port } elseif ($UseSsl) { 8531 } else { 8530 }
}

# Each worker uses its own WSUS connection. Only the UI thread updates controls.
$worker = {
    param($job)
    $ErrorActionPreference = 'Stop'
    function SaveLocalText($path,$text) {
        $temp=Join-Path ([IO.Path]::GetDirectoryName($path)) ([guid]::NewGuid().ToString()+'.tmp')
        try {
            [IO.File]::WriteAllText($temp,$text,[Text.UTF8Encoding]::new($false))
            if ([IO.File]::Exists($path)) { [IO.File]::Replace($temp,$path,[NullString]::Value) }
            else { [IO.File]::Move($temp,$path) }
        } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
    }
    if ($job.Mode -eq 'Log location') {
        $directory=$job.Options.Path
        if ($directory -notmatch '^(?:[a-zA-Z]:[\\/]|\\\\[^\\]+\\[^\\]+)') {
            throw 'Enter an absolute local folder or UNC share path.'
        }
        $directory=[IO.Path]::GetFullPath($directory)
        $destination=[IO.Path]::Combine($directory,$job.LogName)
        Write-Audit $destination $job.Server $job.Operation 'Audit destination selected' 'OK' @{Directory=$directory}
        SaveLocalText $job.LogSettings (ConvertTo-Json @{Directory=$directory} -Compress)
        [pscustomobject]@{Directory=$directory; Log=$destination}
        return
    }
    if ($job.Mode -eq 'Save exclusions') {
        $previous=if ([IO.File]::Exists($job.Rules)) { [IO.File]::ReadAllLines($job.Rules) }
        $changes=@{File=$job.Rules; Before=@($previous); After=$job.Rows}
        Write-Audit $job.Log $job.Server $job.Operation $job.Mode 'Started' $changes $job.LocalLog $job.AuditState
        $contents=if ($job.Rows.Count) { ($job.Rows -join [Environment]::NewLine)+[Environment]::NewLine } else { '' }
        SaveLocalText $job.Rules $contents
        Write-Audit $job.Log $job.Server $job.Operation $job.Mode 'OK' $changes $job.LocalLog $job.AuditState
        return
    }
    if ($job.Mode -eq 'Audit log') {
        $bad = 0
        $needles=@($job.Query -split '\s+' | Where-Object { $_ } | ForEach-Object { $_ -replace '^KB(?=\d+$)','' })
        $directories=@($job.Directory,$job.Folder | Where-Object { $_ } | Sort-Object -Unique)
        foreach ($directory in $directories) {
            try { $files=@(Get-ChildItem -LiteralPath $directory -Filter 'WSUS-*.jsonl' -File) }
            catch {
                [pscustomobject]@{Warning="Could not read audit logs in $directory. $($_.Exception.GetBaseException().Message)"}
                continue
            }
            foreach ($file in $files) {
                $reader=$null; $stream=$null
                try {
                    $sharing=[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
                    $stream=[IO.FileStream]::new($file.FullName,'Open','Read',$sharing)
                    $reader=[IO.StreamReader]::new($stream)
                    while ($null -ne ($line=$reader.ReadLine())) {
                        try {
                            $e=ConvertFrom-Json $line
                            if (!$e.PSObject.Properties['user']) { $e | Add-Member -NotePropertyName user -NotePropertyValue $e.benutzer }
                            if (!$e.PSObject.Properties['action']) { $e | Add-Member -NotePropertyName action -NotePropertyValue $e.aktion }
                            $stamp=if ($e.utc -is [datetime]) { $e.utc.ToLocalTime() } else { [datetimeoffset]::Parse($e.utc).LocalDateTime }
                        } catch { $bad++; continue }
                        if ($stamp -lt $job.From -or $stamp -ge $job.Until) { continue }
                        if (([string]$e.user).IndexOf($job.UserFilter,[StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
                        $matched=$true
                        foreach ($needle in $needles) {
                            if ($line.IndexOf($needle,[StringComparison]::OrdinalIgnoreCase) -lt 0) { $matched=$false; break }
                        }
                        if ($matched) {
                            [pscustomobject]@{Time=$stamp; User=$e.user; Server=$e.server; Action=$e.action
                                Result=$e.status; Details=$line}
                        }
                    }
                } catch { $bad++ }
                finally { if ($reader) { $reader.Dispose() } elseif ($stream) { $stream.Dispose() } }
            }
        }
        if ($bad) { [pscustomobject]@{Warning="Skipped $bad unreadable log record(s)."} }
        return
    }
    Import-Module UpdateServices
    $connect = $job.Connect
    $ws = Get-WsusServer @connect
    $config=if ($job.Mode -notin @('Online check','Windows Update events','Scan sources')) { $ws.GetConfiguration() }
    $scheme = if ($ws.IsConnectionSecureForApiRemoting) { 'https' } else { 'http' }
    $endpoint = [UriBuilder]::new($scheme,$ws.Name,$ws.PortNumber).Uri.AbsoluteUri
    $expected = if ($job.ClientUrl) { $job.ClientUrl } else { $endpoint }
    $store = Join-Path $job.Folder 'Wiederanmeldung'
    [void][IO.Directory]::CreateDirectory($store)
    function ReadCase($path) {
        $record = ConvertFrom-Json ([IO.File]::ReadAllText($path))
        $legacy = @{Kind='Art'; Groups='Gruppen'; ScanResult='Suche'; Removed='Entfernt'}
        foreach ($field in $legacy.Keys) {
            if (!$record.PSObject.Properties[$field] -and $record.PSObject.Properties[$legacy[$field]]) {
                $record | Add-Member -NotePropertyName $field -NotePropertyValue $record.PSObject.Properties[$legacy[$field]].Value
            }
        }
        if ($record.Kind -eq 'Suchlauf') { $record.Kind='Scan' }
        $defaults = @{MachineGuid=''; RemovalState=''; RemovedUtc=''; ScanFinishedUtc=''; VerifiedId=''
            ExpectedGroups=@(); Timeline=@()}
        foreach ($field in $defaults.Keys) {
            if (!$record.PSObject.Properties[$field]) {
                $record | Add-Member -NotePropertyName $field -NotePropertyValue $defaults[$field]
            }
        }
        if ($record.Removed -and !$record.RemovalState) { $record.RemovalState='Removed' }
        return $record
    }
    function SaveCase($case) {
        $path = Join-Path $store ("{0}.json" -f ([guid]$case.Key))
        $tmp = Join-Path $store ([guid]::NewGuid().ToString()+'.tmp')
        try {
            [IO.File]::WriteAllText($tmp,(ConvertTo-Json $case -Depth 6),[Text.UTF8Encoding]::new($false))
            if ([IO.File]::Exists($path)) { [IO.File]::Replace($tmp,$path,[NullString]::Value) }
            else { [IO.File]::Move($tmp,$path) }
        } finally { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } }
    }
    function AddCaseEvent($case,$stage,$message,$utc=[datetime]::UtcNow.ToString('o')) {
        $case.Timeline=@($case.Timeline | Where-Object { $_ }) + [pscustomobject]@{Utc=$utc; Stage=$stage; Message=$message}
    }
    function NewCase($c,$mode,$identity='',$expectedGroups=@(),$preScan=$null) {
        $case = [pscustomobject]@{Key=[guid]::NewGuid().ToString(); Endpoint=$endpoint; Id=[string]$c.Id
            Name=$c.FullDomainName; IP=[string]$c.IPAddress; Kind=$mode; Start=[datetime]::UtcNow.ToString('o')
            Sync=$c.LastSyncTime.Ticks.ToString(); Report=$c.LastReportedStatusTime.Ticks.ToString()
            Groups=@($c.GetComputerTargetGroups() | ForEach-Object { [pscustomobject]@{Id=[string]$_.Id; Name=$_.Name} })
            ScanResult='Pending'; Removed=$false; MachineGuid=$identity; RemovalState=''
            RemovedUtc=''; ScanFinishedUtc=''; VerifiedId=''; ExpectedGroups=@($expectedGroups); Timeline=@()}
        if ($mode -eq 'Remove') {
            $case.RemovalState='Prepared'
            if ($preScan) { $case.Timeline=@($preScan.Timeline | Where-Object { $_ }) }
            AddCaseEvent $case 'Preflight passed' ("Groups: " + ($case.ExpectedGroups -join '; ')) $case.Start
            AddCaseEvent $case 'Removal prepared' 'Current WSUS memberships saved.' $case.Start
        }
        SaveCase $case
        $case
    }
    function Log($action,$status,$details) {
        Write-Audit $job.Log $ws.Name $job.Operation $action $status $details $job.LocalLog $job.AuditState
    }
    function ClientIdentity($name) {
        Invoke-Command -ComputerName $name -Authentication Kerberos -ScriptBlock ([scriptblock]::Create($job.Scan)) -ArgumentList $expected,$true -ErrorAction Stop
    }
    function RemoteScan($r,$case=$null,$preflight=$null) {
        Log 'Remote scan' 'Started' @{Computer=$r.Name; IP=$r.IP; ClientId=$r.Id}
        try {
            if (!$case -or !$case.Removed) {
                $c = $ws.GetComputerTarget([string]$r.Id)
                if ($c.FullDomainName -ne $r.Name -or [string]$c.IPAddress -ne $r.IP) { throw 'Client identity has changed.' }
                if (!(ResolveClientAddress $c).OK) { throw 'DNS and the WSUS IP address do not match.' }
                $identity = ClientIdentity $r.Name
                if (!$identity.MachineGuid -or $identity.ClientId -ne [string]$c.Id) { throw 'The endpoint WSUS client ID does not match the selected record.' }
                $case = NewCase $c 'Scan' $identity.MachineGuid $preflight.Groups
                if ($preflight) { AddCaseEvent $case 'Preflight passed' ("Groups: " + ($preflight.Groups -join '; ')) }
            }
            if (!$case.MachineGuid) { throw 'The removal case has no saved endpoint identity.' }
            AddCaseEvent $case 'Scan requested' $(if ($case.Removed) { 'Post-removal detection and scan.' } else { 'Scan before re-registration.' })
            SaveCase $case
            $command = [scriptblock]::Create($job.Scan)
            $clientId=if ($case.Removed) { [string]$case.VerifiedId } else { [string]$case.Id }
            $outcome = Invoke-Command -ComputerName $r.Name -Authentication Kerberos -ScriptBlock $command -ArgumentList $expected,$false,([bool]$case.Removed),$case.MachineGuid,$clientId -ErrorAction Stop
            if (!$outcome.Search) { throw 'The endpoint returned no scan outcome.' }
            if ($case.Removed) { AddCaseEvent $case "Detection: $($outcome.Detection)" $outcome.DetectionError }
            AddCaseEvent $case "Update search: $($outcome.Search)" $outcome.SearchError
            $message=$outcome.Message
            $state=if ($outcome.Search -eq 'Failed') { 'Error' } elseif ($outcome.Detection -eq 'Failed') { 'Partial' } else { 'OK' }
        } catch {
            $message = $_.Exception.GetBaseException().Message
            $state = 'Error'
        }
        if ($case) {
            $case.ScanResult = "$state | $message"
            $case.ScanFinishedUtc = [datetime]::UtcNow.ToString('o')
            AddCaseEvent $case "Scan $state" $message $case.ScanFinishedUtc
            if ($preflight -and $state -eq 'OK') {
                $until=(CaseTime $case.ScanFinishedUtc).AddMinutes($job.GraceMinutes).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                AddCaseEvent $case 'Report grace period' "Waiting for a WSUS report until $until."
            }
            SaveCase $case
        }
        Log 'Remote scan' $state @{Computer=$r.Name; ClientId=$r.Id; Message=$message}
        [pscustomobject]@{Action='Remote scan'; Target=$r.Name; Status=$state; Message=$message}
    }
    function Scope($groups) {
        $s = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
        $s.IncludeDownstreamComputerTargets = $false
        $s.IncludeSubgroups = $false
        foreach ($g in $groups) { [void]$s.ComputerTargetGroups.Add($g) }
        $s
    }
    function Chain($group) {
        while ($group) {
            $group
            if ($group.Id -eq [Microsoft.UpdateServices.Administration.ComputerTargetGroupId]::AllComputers) { break }
            $group = $group.GetParentTargetGroup()
        }
    }
    function State($approvals,$chain) {
        if ($approvals) {
            foreach ($g in $chain) {
                $actions=@(foreach ($approval in $approvals) {
                    if ($approval.ComputerTargetGroupId -eq $g.Id) { [string]$approval.Action }
                })
                if ($actions.Count -eq 1) { return $actions[0] }
                if ($actions.Count -gt 1) { return (($actions | Sort-Object -Unique) -join ',') }
            }
        }
        'No approval set'
    }
    function Latest($id) {
        $ws.GetUpdate([Microsoft.UpdateServices.Administration.UpdateRevisionId]::new([guid]$id))
    }
    function Exclusion($u,$rules) {
        foreach ($line in $rules) {
            $rule = $line.Trim()
            if (!$rule) { continue }
            if ($rule -match '^KB(\d+)$') {
                if ($u.KnowledgebaseArticles -contains $Matches[1]) { return $rule }
            } elseif ($rule -match '^(?:Title|Titel):(.+)$') {
                if ($u.Title -like $Matches[1].Trim()) { return $rule }
            } elseif ($rule -eq [string]$u.Id.UpdateId) { return $rule }
        }
    }
    function ReadRules {
        if ([IO.File]::Exists($job.Rules)) { [IO.File]::ReadAllLines($job.Rules) }
    }
    function StaleReport($c) {
        $c.LastReportedStatusTime -lt $job.ReportCutoff
    }
    function TimeText([datetime]$d) {
        if ($d.Year -lt 1900) { return 'never' }
        [datetime]::SpecifyKind($d,'Utc').ToLocalTime().ToString('yyyy-MM-dd HH:mm')
    }
    function ResolveClientAddress {
        param($c)
        $ips=@(); $ip=$null; $notes=@()
        $validIp=[ipaddress]::TryParse([string]$c.IPAddress,[ref]$ip) -and
            $ip -notin @([ipaddress]::Any,[ipaddress]::IPv6Any)
        if (!$validIp) { $ip=$null; $notes+='Invalid WSUS IP address' }
        if ([uri]::CheckHostName([string]$c.FullDomainName) -eq 'Dns') {
            try {
                $ips=@([Net.Dns]::GetHostAddresses($c.FullDomainName) | Sort-Object -Property { $_.ToString() } -Unique)
                if (!$ips.Count) { $notes+='DNS returned no address' }
                elseif ($ip -and $ip -notin $ips) { $notes+='DNS / WSUS IP mismatch' }
            } catch { $notes += "DNS: $($_.Exception.GetBaseException().Message)" }
        } else { $notes += 'Invalid DNS name' }
        [pscustomobject]@{Ip=$ip; Addresses=$ips; OK=($ip -and $ip -in $ips)
            Finding=$(if ($notes.Count) { $notes -join ' | ' } else { 'DNS matches WSUS IP' })}
    }
    function CheckReachability {
        param($c)
        $resolved=ResolveClientAddress $c
        $probes=@{}; $replies=@{}
        try {
            foreach ($address in (@($resolved.Ip) + $resolved.Addresses)) {
                if (!$address -or $probes.ContainsKey([string]$address)) { continue }
                $ping=[Net.NetworkInformation.Ping]::new()
                $probe=@{Ping=$ping; Task=$null}
                $probes[[string]$address]=$probe
                try { $probe.Task=$ping.SendPingAsync($address,1200) }
                catch { $replies[[string]$address]="Error: $($_.Exception.GetBaseException().Message)" }
            }
            foreach ($address in $probes.Keys) {
                if (!$probes[$address].Task) { continue }
                try {
                    $reply=$probes[$address].Task.GetAwaiter().GetResult()
                    $replies[$address]=if ($reply.Status -eq 'Success') { "Reply ($($reply.RoundtripTime) ms)" } else { "No reply ($($reply.Status))" }
                } catch { $replies[$address]="Error: $($_.Exception.GetBaseException().Message)" }
            }
        } finally { foreach ($probe in $probes.Values) { $probe.Ping.Dispose() } }
        $ipResult=if ($resolved.Ip) { $replies[[string]$resolved.Ip] } else { 'Unavailable' }
        $dnsResult=@(foreach ($address in $resolved.Addresses) { "$address = $($replies[[string]$address])" })
        [pscustomobject]@{Id=[string]$c.Id; Name=$c.FullDomainName; IP=[string]$c.IPAddress
            DNS=($resolved.Addresses -join ', '); IpResult=$ipResult; DnsResult=($dnsResult -join '; ')
            Finding=$resolved.Finding; CheckedAt=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')}
    }
    function TestReAddGroups($identity,$catalog,$targetingMode) {
        if ($targetingMode -ne 'Client') { return }
        $names=@($identity.TargetGroup -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)
        if (!$identity.TargetingEnabled -or !$names.Count) { throw 'Client-side targeting is disabled or has no configured target groups.' }
        $invalid=@($names | Where-Object { !$catalog.ContainsKey($_) -or $catalog[$_] -ne 1 })
        if ($invalid.Count) { throw "Configured groups absent or ambiguous in WSUS: $($invalid -join '; ')." }
        $names
    }
    $reAddGroupCatalog=$null
    function TestReAddClient($r,$refreshCatalog=$false) {
        $c=$ws.GetComputerTarget([string]$r.Id)
        if ($c.FullDomainName -ne $r.Name -or [string]$c.IPAddress -ne $r.IP -or !(StaleReport $c)) {
            throw 'Identity or reporting status changed. Refresh the client list.'
        }
        if (!(ResolveClientAddress $c).OK) { throw 'DNS and the WSUS IP address do not match.' }
        $identity=ClientIdentity $r.Name
        if (!$identity.MachineGuid -or $identity.ClientId -ne [string]$c.Id) { throw 'The endpoint WSUS client ID does not match the selected record.' }
        $catalog=$reAddGroupCatalog
        if ([string]$config.TargetingMode -eq 'Client' -and (!$catalog -or $refreshCatalog)) {
            $catalog=@{}
            foreach ($g in $ws.GetComputerTargetGroups()) { $catalog[$g.Name]=1+[int]$catalog[$g.Name] }
        }
        $names=@(TestReAddGroups $identity $catalog ([string]$config.TargetingMode))
        [pscustomobject]@{Computer=$c; Identity=$identity; Groups=$names; Catalog=$catalog}
    }
    function CaseTime([string]$value) {
        [datetimeoffset]::Parse($value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
    }
    $computerMatches = @{}
    function FindCaseClient($name) {
        if (!$computerMatches.ContainsKey($name)) {
            $computerMatches[$name] = @($ws.SearchComputerTargets($name) | Where-Object FullDomainName -eq $name)
        }
        $computerMatches[$name]
    }
    function Get-CaseState($case) {
        $start = CaseTime $case.Start
        $baseline = if ($case.RemovedUtc) { CaseTime $case.RemovedUtc } else { $start }
        $watchFrom = if ($case.ScanFinishedUtc) { CaseTime $case.ScanFinishedUtc } else { $baseline }
        $row = [pscustomobject]@{Key=$case.Key; Name=$case.Name; Start=$start.ToLocalTime(); ScanResult=$case.ScanResult
            Contact='Pending'; ReportTime='Pending'; Comparison='Waiting for contact'; Missing=@(); CurrentId=''
            Pending=([datetime]::UtcNow -lt $watchFrom.AddHours(24)); Retry=($case.Removed -or $case.RemovalState -eq 'Prepared')
            Verify=$false; Stage='Waiting for contact'; OriginalId=$case.Id
            Timeline=@($case.Timeline | Where-Object { $_ }); ExpectedGroups=@($case.ExpectedGroups | Where-Object { $_ })
            ActualGroups=@(); RequestedGroups=@()}
        if ($case.RemovalState -eq 'Prepared') {
            $row.Stage='Removal outcome unknown'; $row.Pending=$false
            $row.Comparison='Use Retry re-registration to reconcile the saved removal.'
            return $row
        }
        $found = @(FindCaseClient $case.Name)
        if ($found.Count -gt 1) {
            $row.Stage='Multiple WSUS records'; $row.Pending=$false
            $row.Comparison='Resolve duplicate names before restoring groups.'
            return $row
        }
        if (!$found.Count) {
            if (!$row.Pending) { $row.Stage='No contact within 24 hours' }
            return $row
        }
        $c = $found[0]
        $row.CurrentId = [string]$c.Id
        if ($c.LastSyncTime.Ticks -gt [long]$case.Sync -and $c.LastSyncTime -ge $baseline) {
            $row.Contact=TimeText $c.LastSyncTime
            AddCaseEvent $row 'Latest WSUS contact' '' ([datetime]::SpecifyKind($c.LastSyncTime,'Utc').ToString('o'))
        }
        if ($c.LastReportedStatusTime.Ticks -gt [long]$case.Report -and $c.LastReportedStatusTime -ge $baseline) {
            $row.ReportTime=TimeText $c.LastReportedStatusTime
            AddCaseEvent $row 'Latest WSUS report' '' ([datetime]::SpecifyKind($c.LastReportedStatusTime,'Utc').ToString('o'))
        }
        if ($row.CurrentId -ne $case.Id -and ($case.VerifiedId -ne $row.CurrentId -or !$case.MachineGuid)) {
            $row.Stage='New ID requires verification'; $row.Pending=$false
            $row.Comparison=if ($case.MachineGuid) { 'WSUS ID changed. Verify the endpoint before restoring groups.' } else { 'Older case without endpoint identity. Review the groups and restore manually in WSUS.' }
            $row.Verify=$case.Removed -and [bool]$case.MachineGuid -and ($row.Contact -ne 'Pending' -or $row.ReportTime -ne 'Pending')
            return $row
        }
        if ($row.Contact -eq 'Pending' -and $row.ReportTime -eq 'Pending') {
            if (!$row.Pending) { $row.Stage='No fresh contact within 24 hours' }
            return $row
        }
        $row.Pending = $row.Pending -and ($row.ReportTime -eq 'Pending')
        $row.Stage = if ($row.ReportTime -ne 'Pending') { 'Report received' } elseif ($row.Pending) { 'Waiting for report' } else { 'No report within 24 hours' }
        $members = @($c.GetComputerTargetGroups())
        $row.ActualGroups=@($members | Where-Object Id -notin $builtins | ForEach-Object Name)
        if ([string]$config.TargetingMode -eq 'Client') {
            $row.RequestedGroups=@($c.RequestedTargetGroupNames | Where-Object { $_ })
            $wanted=if ($row.ExpectedGroups.Count) { $row.ExpectedGroups } else { $row.RequestedGroups }
            $missing = @($wanted | Where-Object { $_ -and $_ -notin $members.Name })
            $extra = @($members | Where-Object { $_.Id -notin $builtins -and $_.Name -notin $wanted })
            $row.Comparison = "Expected: $($wanted -join ', ') | Reported: $($row.RequestedGroups -join ', ') | Missing: $($missing -join ', ') | Additional: $($extra.Name -join ', ')"
            if ($missing.Count -and !$row.Pending) { $row.Stage='Client target groups missing' }
        } else {
            $gaps = @($case.Groups | Where-Object { [guid]$_.Id -notin $builtins -and [guid]$_.Id -notin $members.Id })
            $row.Comparison = if (!$gaps.Count) { 'All saved groups are present' } else { 'Missing: '+($gaps.Name -join ', ') }
            if ($case.Removed) {
                $row.Missing=$gaps
                if ($gaps.Count -and !$row.Pending) { $row.Stage='Groups missing' }
            }
        }
        $row
    }
    $builtins = @([Microsoft.UpdateServices.Administration.ComputerTargetGroupId]::AllComputers,
        [Microsoft.UpdateServices.Administration.ComputerTargetGroupId]::UnassignedComputers)
    function CaseForPlan($plan) {
        $case = ReadCase (Join-Path $store (([guid]$plan.Key).ToString()+'.json'))
        if ($case.Endpoint -ne $endpoint) { throw 'The case belongs to another WSUS server.' }
        $case
    }
    function VerifyCaseClient($case,$currentId) {
        if (!$case.MachineGuid) { throw 'This older case has no saved endpoint identity.' }
        $identity = ClientIdentity $case.Name
        if ($identity.MachineGuid -ne $case.MachineGuid -or ($currentId -and $identity.ClientId -ne $currentId)) {
            throw 'Kerberos endpoint identity or WSUS client ID did not match.'
        }
    }
    function GetWindowsUpdateEvents($sinceUtc,$machineId,$clientId,$errorsOnly) {
        if ($machineId) {
            $machine=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction Stop
            if ([string]$machine.MachineGuid -ne $machineId) { throw 'The remote machine identity does not match the saved case.' }
        }
        if ($clientId) {
            $client=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate' -ErrorAction Stop
            if (([string]$client.SusClientId).Trim('{}') -ne $clientId) { throw 'The remote WSUS client ID does not match the selected computer.' }
        }
        $filter=@{LogName='Microsoft-Windows-WindowsUpdateClient/Operational'; StartTime=$sinceUtc}
        if ($errorsOnly) { $filter.Level=@(1,2,3) }
        try {
            foreach ($event in (Get-WinEvent -FilterHashtable $filter -MaxEvents 100 -ErrorAction Stop)) {
                [pscustomobject]@{Utc=$event.TimeCreated.ToUniversalTime().ToString('o'); Id=$event.Id
                    Level=$event.LevelDisplayName; Message=$event.Message}
            }
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
        }
    }
    function ReadScanSources($machineId,$clientId) {
        $ErrorActionPreference='Stop'
        if ($machineId) {
            $identity=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography'
            if ($identity.MachineGuid -ne $machineId) { throw 'The machine identity differs from the saved case.' }
        }
        if ($clientId) {
            $identity=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate'
            if (([string]$identity.SusClientId).Trim('{}') -ne $clientId) { throw 'The WSUS identity differs from the saved case.' }
        }
        $path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        $policy=if (Test-Path -LiteralPath $path) { Get-ItemProperty -LiteralPath $path }
        $au=if (Test-Path -LiteralPath "$path\AU") { Get-ItemProperty -LiteralPath "$path\AU" }
        "WSUS server: $($policy.WUServer) | UseWUServer: $($au.UseWUServer)"
        "Client target group: $($policy.TargetGroup) | Enabled: $($policy.TargetGroupEnabled)"
        foreach ($category in 'Feature','Quality','Driver','Other') {
            $value=$policy."SetPolicyDrivenUpdateSourceFor${category}Updates"
            $source=if ($null -eq $value) { 'Default (no class policy)' }
                elseif ($au.UseUpdateClassPolicySource -ne 1) { "Default (class policy inactive, stored value $value)" }
                elseif ($value -eq 1) { 'WSUS' } elseif ($value -eq 0) { 'Windows Update' } else { "Unknown ($value)" }
            "$category updates: $source"
        }
    }
    if ($job.Mode -eq 'Scan sources') {
        foreach ($plan in $job.Rows) {
            try {
                $case=CaseForPlan $plan
                $clientId=if ($case.VerifiedId) { $case.VerifiedId } elseif (!$case.MachineGuid) { $case.Id }
                if (!$case.MachineGuid -and !$clientId) { throw 'No saved endpoint identity.' }
                $details=@(Invoke-Command -ComputerName $case.Name -Authentication Kerberos -ScriptBlock ${function:ReadScanSources} -ArgumentList $case.MachineGuid,$clientId -ErrorAction Stop)
                $state='OK'
            } catch { $details=@($_.Exception.GetBaseException().Message); $state='Error' }
            Log $job.Mode $state @{Computer=$plan.Name;Case=$plan.Key}
            [pscustomobject]@{Name=$plan.Name; Status=$state; Details=$details}
        }
        return
    }
    if ($job.Mode -eq 'Windows Update events') {
        $since=[datetime]::UtcNow.AddHours(-[int]$job.Options.Hours)
        $sessionOptions=New-PSSessionOption -OpenTimeout 10000
        $processed=0
        foreach ($r in $job.Rows) {
            $processed++
            Write-Progress -Activity 'Reading Windows Update events' -Status "$processed of $($job.Rows.Count) - $($r.Name)"
            $events=@(); $status='OK'; $message=''
            try {
                $name=$r.Name; $machineId=''; $clientId=''
                if ($r.Key) {
                    $case=CaseForPlan $r
                    $name=$case.Name; $machineId=$case.MachineGuid
                    if ($machineId) { $clientId=$case.VerifiedId }
                    else { $clientId=$case.Id }
                } else { $clientId=[string]$r.Id }
                if (!$machineId) {
                    if (!$clientId) { throw 'The selected item has no verified client identity.' }
                    $c=$ws.GetComputerTarget($clientId)
                    if ($c.FullDomainName -ne $name -or !(ResolveClientAddress $c).OK) {
                        throw 'WSUS and DNS could not confirm the selected computer.'
                    }
                }
                $remote=@{ComputerName=$name; Authentication='Kerberos'; SessionOption=$sessionOptions
                    ScriptBlock=${function:GetWindowsUpdateEvents}
                    ArgumentList=@($since,$machineId,$clientId,[bool]$job.Options.ErrorsOnly); ErrorAction='Stop'}
                $events=@(Invoke-Command @remote)
            } catch { $status='Error'; $message=$_.Exception.GetBaseException().Message }
            try { Log $job.Mode $status @{Computer=$r.Name; Since=$since.ToString('o'); Count=$events.Count; Message=$message} }
            catch { Write-Warning "Event access could not be audited. $($_.Exception.GetBaseException().Message)" }
            [pscustomobject]@{Target=$r.Name; Status=$status; Events=$events; Message=$message}
        }
        return
    }
    if ($job.Mode -eq 'Reporting status') {
        foreach ($file in (Get-ChildItem -LiteralPath $store -Filter '*.json' -File)) {
            try {
                $case = ReadCase $file.FullName
                if ($case.Endpoint -eq $endpoint) { Get-CaseState $case }
            } catch {
                [pscustomobject]@{Key=$file.BaseName; Name=$file.Name; ScanResult='Status check failed'
                    Comparison=$_.Exception.GetBaseException().Message; Missing=@(); Pending=$false}
            }
        }
        return
    }
    if ($job.Mode -in @('Retry re-registration','Verify re-registration')) {
        foreach ($plan in $job.Rows) {
            $status='OK'
            try {
                $case=CaseForPlan $plan
                if ($job.Mode -eq 'Verify re-registration') {
                    $live=Get-CaseState $case
                    if (!$live.Verify -or $live.CurrentId -ne $plan.CurrentId) { throw 'The returned WSUS record changed. Refresh the case.' }
                    VerifyCaseClient $case $live.CurrentId
                    $case.VerifiedId=$live.CurrentId
                    $message="Verified replacement WSUS ID $($live.CurrentId)"
                    AddCaseEvent $case 'Replacement ID verified' $message
                    SaveCase $case
                } else {
                    if ($case.RemovalState -eq 'Prepared') {
                        $found=@(FindCaseClient $case.Name)
                        if ($found.Count -gt 1 -or ($found.Count -eq 1 -and [string]$found[0].Id -eq $case.Id)) {
                            throw 'The original record is present or the name is ambiguous. Review the client in WSUS before attempting another removal.'
                        }
                        $currentId=if ($found.Count) { [string]$found[0].Id } else { '' }
                        VerifyCaseClient $case $currentId
                        $case.Removed=$true; $case.RemovalState='Removed'; $case.VerifiedId=$currentId
                        AddCaseEvent $case 'Removal reconciled' 'The original WSUS entry is absent.'
                        SaveCase $case
                    }
                    if (!$case.Removed) { throw 'This case has no confirmed removal.' }
                    if (!$case.MachineGuid) {
                        $found=@(FindCaseClient $case.Name)
                        if ($found.Count -ne 1 -or [string]$found[0].Id -ne $case.Id -or !(ResolveClientAddress $found[0]).OK) {
                            throw 'The older case can be retried only when its original endpoint is identifiable.'
                        }
                        $identity=ClientIdentity $case.Name
                        if (!$identity.MachineGuid -or $identity.ClientId -ne $case.Id) { throw 'Could not verify the original endpoint.' }
                        $case.MachineGuid=$identity.MachineGuid
                        SaveCase $case
                    }
                    RemoteScan $case $case
                    continue
                }
            } catch { $status='Error'; $message=$_.Exception.GetBaseException().Message }
            Log $job.Mode $status @{Computer=$plan.Name; Case=$plan.Key; Message=$message}
            [pscustomobject]@{Action=$job.Mode; Target=$plan.Name; Status=$status; Message=$message}
        }
        return
    }
    if ($job.Mode -eq 'Restore groups') {
        if ($config.IsReplicaServer -or [string]$config.TargetingMode -ne 'Server') { throw 'Server-side targeting is required.' }
        foreach ($plan in $job.Rows) {
            try {
                $case = CaseForPlan $plan
                if (!$case.Removed) { throw 'No confirmed removal on this WSUS server.' }
                $live = Get-CaseState $case
                if (!$live.CurrentId -or $live.CurrentId -ne $plan.CurrentId -or !$live.Missing.Count) {
                    throw 'The returned WSUS record or group membership changed. Refresh the case.'
                }
                if ($case.MachineGuid) { VerifyCaseClient $case $live.CurrentId }
            } catch {
                $message=$_.Exception.GetBaseException().Message
                Log $job.Mode 'Error' @{Computer=$plan.Name; Case=$plan.Key; Message=$message}
                [pscustomobject]@{Action=$job.Mode; Target=$plan.Name; Status='Error'; Message=$message}
                continue
            }
            foreach ($g in $plan.Missing) {
                $target = "$($case.Name) | $($g.Name) [$($g.Id)]"
                Log $job.Mode 'Started' @{Target=$target; ClientId=$case.Id}
                try {
                    if (!$live.CurrentId -or $live.CurrentId -ne $plan.CurrentId -or $g.Id -notin $live.Missing.Id) { throw 'Membership has changed or already exists.' }
                    $c = $ws.GetComputerTarget($live.CurrentId)
                    if ($c.FullDomainName -ne $case.Name) { throw 'Computer name has changed.' }
                    $group = $ws.GetComputerTargetGroup([guid]$g.Id)
                    $group.AddComputerTarget($c)
                    $state='OK'; $msg='Group membership restored'
                } catch { $state='Error'; $msg=$_.Exception.GetBaseException().Message }
                AddCaseEvent $case "Group assignment $state" "$($g.Name) | $msg"
                try { SaveCase $case } catch { $state='Partial'; $msg+=" | Timeline could not be saved: $($_.Exception.Message)" }
                Log $job.Mode $state @{Target=$target; ClientId=$case.Id; Message=$msg}
                [pscustomobject]@{Action=$job.Mode; Target=$target; Status=$state; Message=$msg}
            }
        }
        return
    }
    function ApprovalPlan {
        if ($config.IsReplicaServer) { throw 'Perform write operations on the upstream WSUS server.' }
        $needed=@{}; $paths=@{}; $groupCache=@{}; $updates=@{}; $selected=@{}
        $signature=[Collections.Generic.List[string]]::new()
        $rules=@(ReadRules)
        foreach ($r in $job.Rows) { $selected["$($r.Id)/$($r.GroupId)"]=$true }
        foreach ($r in $job.Rows) {
            if (!$updates.ContainsKey($r.Id)) {
                $u=Latest $r.Id
                $approvals=@($u.GetUpdateApprovals())
                $updates[$r.Id]=@{Update=$u; Approvals=$approvals}
                foreach ($a in $approvals) {
                    $signature.Add("A|$($r.Id)|$($a.ComputerTargetGroupId)|$($a.Action)|$($a.Deadline.Ticks)|$($a.UpdateId.RevisionNumber)|$($a.IsOptional)")
                }
            }
            $u=$updates[$r.Id].Update; $approvals=$updates[$r.Id].Approvals
            $group=$ws.GetComputerTargetGroup([guid]$r.GroupId)
            $reason=Exclusion $u $rules
            if ($reason) { throw "Excluded by rule: $reason" }
            if ($u.IsDeclined -or $u.Id.RevisionNumber -ne $r.Revision -or
                (State $approvals @(Chain $group)) -ne $r.Status) { throw 'Revision or approval status has changed. Reload the updates.' }
            if ($r.DeadlineUtc -and $r.DeadlineUtc -le [datetime]::UtcNow) { throw "Deadline for $($r.Group) has passed." }
            $queue = [Collections.Queue]::new()
            $queue.Enqueue($group)
            while ($queue.Count) {
                $g=$queue.Dequeue()
                if ($g.Id -ne $r.GroupId -and ($selected.ContainsKey("$($r.Id)/$($g.Id)") -or
                    ($approvals | Where-Object ComputerTargetGroupId -eq $g.Id))) { continue }
                if (!$groupCache.ContainsKey($g.Id)) {
                    $names=@((Chain $g) | ForEach-Object { $_.Name }); [array]::Reverse($names)
                    $groupCache[$g.Id]=@{Path=$names -join ' / '; Children=@($g.GetChildTargetGroups())}
                }
                $paths[$g.Id]=$groupCache[$g.Id].Path
                $signature.Add("G|$($r.Id)|$($r.GroupId)|$($g.Id)|$($paths[$g.Id])")
                foreach ($rec in $u.GetUpdateInstallationInfoPerComputerTarget((Scope @($g)))) {
                    $signature.Add("C|$($r.Id)|$($g.Id)|$($rec.ComputerTargetId)|$($rec.UpdateInstallationState)|$($rec.UpdateApprovalAction)")
                    if ([string]$rec.UpdateInstallationState -in @('NotInstalled','Downloaded','Failed')) {
                        $needed[[string]$rec.ComputerTargetId]=$true
                    }
                }
                foreach ($child in $groupCache[$g.Id].Children) { $queue.Enqueue($child) }
            }
        }
        $signature.Sort([StringComparer]::Ordinal)
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $fingerprint=[Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($signature -join "`n")))) }
        finally { $sha.Dispose() }
        [pscustomobject]@{Count=$needed.Count; Paths=@($paths.Values | Sort-Object); Fingerprint=$fingerprint}
    }
    if ($job.Mode -eq 'Deployment scope') {
        ApprovalPlan
        return
    }
    if ($job.Mode -eq 'Approval' -and (ApprovalPlan).Fingerprint -ne $job.Fingerprint) {
        throw 'The approval scope or existing approvals changed. Reload the updates and review the plan again.'
    }
    if ($job.Mode -in @('ReAdd check','ReAdd preview')) {
        foreach ($r in $job.Rows) {
            $status='OK'; $groupsText=''; $plan=$null
            try {
                if ($config.IsReplicaServer) { throw 'Re-registration must be performed on the upstream WSUS server.' }
                $check=TestReAddClient $r
                $reAddGroupCatalog=$check.Catalog
                $groupsText=$check.Groups -join '; '
                $message=if ($groupsText) { "Configured client groups found in WSUS: $groupsText" } else { 'Server-side targeting: current memberships will be saved.' }
                $plan=$r | Select-Object *,@{Name='ApprovedClientGroups';Expression={$groupsText}}
            } catch { $status='Blocked'; $message=$_.Exception.GetBaseException().Message }
            Log 'ReAdd check' $status @{Computer=$r.Name; ClientId=$r.Id; Message=$message}
            [pscustomobject]@{Target=$r.Name; Status=$status; Message=$message; Plan=$plan}
        }
        return
    }
    if ($job.Mode -eq 'Online check') {
        function FailedProbe($r,$reason) {
            [pscustomobject]@{Id=[string]$r.Id;Name=$r.Name;IP=$r.IP;DNS='';IpResult='Unavailable';DnsResult=''
                Finding=$reason;CheckedAt=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')}
        }
        $pending=[Collections.ArrayList]::new()
        function ReceiveProbes {
            $handles=[Threading.WaitHandle[]]@($pending | ForEach-Object { $_.Async.AsyncWaitHandle })
            [void][Threading.WaitHandle]::WaitAny($handles,250)
            for ($n=$pending.Count-1; $n -ge 0; $n--) {
                $probe=$pending[$n]
                if (!$probe.Async.IsCompleted) { continue }
                try { $response=$probe.PS.EndInvoke($probe.Async)[0] }
                catch { $response=FailedProbe $probe.Row $_.Exception.GetBaseException().Message }
                finally { $probe.PS.Dispose(); $pending.RemoveAt($n) }
                $job.OnlineQueue.Enqueue($response)
            }
        }
        $pool=[runspacefactory]::CreateRunspacePool(1,8)
        $probeScript='param($target)'+[Environment]::NewLine+'$ErrorActionPreference="Stop"'+[Environment]::NewLine+
            'function ResolveClientAddress {'+${function:ResolveClientAddress}.ToString()+'}'+[Environment]::NewLine+
            'function CheckReachability {'+${function:CheckReachability}.ToString()+'}'+[Environment]::NewLine+'CheckReachability $target'
        try {
            $pool.Open()
            foreach ($r in $job.Rows) {
                while ($pending.Count -ge 8) { ReceiveProbes }
                $ps=$null
                try {
                    $c=$ws.GetComputerTarget([string]$r.Id)
                    if ($r.Name -and $r.Name -ne $c.FullDomainName) { throw 'The WSUS computer name changed. Refresh the view.' }
                    $target=@{Id=$c.Id;FullDomainName=$c.FullDomainName;IPAddress=[string]$c.IPAddress}
                    $ps=[powershell]::Create(); $ps.RunspacePool=$pool
                    [void]$ps.AddScript($probeScript).AddArgument($target)
                    [void]$pending.Add(@{PS=$ps;Async=$ps.BeginInvoke();Row=$r})
                } catch {
                    if ($ps) { $ps.Dispose() }
                    $job.OnlineQueue.Enqueue((FailedProbe $r $_.Exception.GetBaseException().Message))
                }
            }
            while ($pending.Count) { ReceiveProbes }
        } finally {
            foreach ($probe in $pending) {
                try { [void]$probe.PS.BeginStop($null,$null) } catch { Write-Verbose $_.Exception.Message }
            }
            foreach ($probe in $pending) { $probe.PS.Dispose() }
            $pool.Dispose()
        }
        return
    }
    Log $job.Mode 'Start' @{Groups=$job.Groups; Days=$job.Days}
    if ($job.Mode -eq 'Groups') {
        foreach ($g in ($ws.GetComputerTargetGroups() | Sort-Object Name)) {
            $names = @((Chain $g) | ForEach-Object { $_.Name })
            [array]::Reverse($names)
            [pscustomobject]@{Id=$g.Id; Name=$names -join ' / '; Server=$ws.Name; Mode=[string]$config.TargetingMode}
        }
        return
    }
    $groups = @($job.Groups | ForEach-Object { $ws.GetComputerTargetGroup([guid]$_) })
    if (!$groups.Count) { throw 'No target groups selected.' }
    $us = New-Object Microsoft.UpdateServices.Administration.UpdateScope
    $rules = @(ReadRules)
    function GetUpdateRows {
        $cache=@{}; $metadata=@{}; $approvalsByUpdate=@{}
        function IndexApprovals($scope,$wanted) {
            foreach ($approval in $ws.GetUpdateApprovals($scope)) {
                $id=$approval.UpdateId.UpdateId
                if (!$wanted.ContainsKey($id) -or !$relevantGroups.ContainsKey($approval.ComputerTargetGroupId) -or
                    !$metadata.ContainsKey($id) -or $metadata[$id].Id.RevisionNumber -ne $approval.UpdateId.RevisionNumber) { continue }
                if (!$approvalsByUpdate.ContainsKey($id)) { $approvalsByUpdate[$id]=[Collections.Generic.List[object]]::new() }
                $approvalsByUpdate[$id].Add($approval)
            }
        }
        $catalogTime=[Diagnostics.Stopwatch]::new()
        $approvalTime=[Diagnostics.Stopwatch]::new()
        $groupTime=[Diagnostics.Stopwatch]::StartNew()
        $stateLabels=@{'No approval set'='No approval configured';NotApproved='Not approved'
            Scan='Detect only';Install='Approved for installation'}
        $all=[Collections.Generic.List[object]]::new()
        $current=[Collections.Generic.List[object]]::new()
        $chains=@{}; $relevantGroups=@{}
        foreach ($g in $groups) {
            $chains[$g.Id]=@(Chain $g)
            foreach ($ancestor in $chains[$g.Id]) { $relevantGroups[$ancestor.Id]=$ancestor }
        }
        if ($job.IncludeApproved) {
            $approvedScope=New-Object Microsoft.UpdateServices.Administration.UpdateScope
            $approvedScope.ApprovedStates='LatestRevisionApproved'
            foreach ($ancestor in $relevantGroups.Values) { [void]$approvedScope.ApprovedComputerTargetGroups.Add($ancestor) }
            Write-Progress -Activity 'Loading updates' -Status 'Reading approvals for selected groups and their ancestors'
            $catalogTime.Start()
            foreach ($u in $ws.GetUpdates($approvedScope)) { $metadata[$u.Id.UpdateId]=$u }
            $catalogTime.Stop()
            Write-Progress -Activity 'Loading updates' -Status 'Reading WSUS approvals'
            $approvalTime.Start()
            IndexApprovals $approvedScope $metadata
            $approvalTime.Stop()
        }
        $summariesByGroup=@{}; $neededIds=@{}
        foreach ($g in $groups) {
            Write-Progress -Activity 'Loading updates' -Status "Reading installation counts for $($g.Name)"
            $summariesByGroup[$g.Id]=@(foreach ($s in $ws.GetSummariesPerUpdate($us,(Scope @($g)))) {
                if ($s.NotInstalledCount+$s.DownloadedCount+$s.FailedCount -gt 0) {
                    if (!$metadata.ContainsKey($s.UpdateId)) { $neededIds[$s.UpdateId]=$true }
                    $s
                } elseif ($job.IncludeApproved -and $approvalsByUpdate.ContainsKey($s.UpdateId)) { $s }
            })
        }
        # Small selections cost fewer individual calls. For large selections fetch metadata and approvals in bulk.
        if ($neededIds.Count -gt 48) {
            $neededScope=New-Object Microsoft.UpdateServices.Administration.UpdateScope
            $neededScope.IncludedInstallationStates='NotInstalled, Downloaded, Failed'
            $neededScope.ApprovedStates='NotApproved, LatestRevisionApproved, HasStaleUpdateApprovals'
            $catalogTime.Start()
            foreach ($u in $ws.GetUpdates($neededScope)) {
                if ($neededIds.ContainsKey($u.Id.UpdateId)) { $metadata[$u.Id.UpdateId]=$u }
            }
            $catalogTime.Stop()
            $approvalTime.Start()
            IndexApprovals $neededScope $neededIds
            $approvalTime.Stop()
        }
        $groupNumber=0
        foreach ($g in $groups) {
            $groupNumber++
            Write-Progress -Activity 'Loading updates' -Status "Group $groupNumber of $($groups.Count) - $($g.Name)"
            $chain=$chains[$g.Id]
            $groupNames=@($chain | ForEach-Object { $_.Name }); [array]::Reverse($groupNames)
            $groupPath=$groupNames -join ' / '
            foreach ($s in $summariesByGroup[$g.Id]) {
                $id=$s.UpdateId
                $missing=$s.NotInstalledCount; $downloaded=$s.DownloadedCount; $failed=$s.FailedCount
                $needed=$missing+$downloaded+$failed
                if (!$needed -and (!$job.IncludeApproved -or !$approvalsByUpdate.ContainsKey($id))) { continue }
                $info=$cache[$id]
                if (!$info) {
                    $u=$metadata[$id]
                    if ($u) {
                        $approvals=$approvalsByUpdate[$id]
                    } else {
                        $catalogTime.Start()
                        $u=Latest $id
                        $catalogTime.Stop()
                        $approvalTime.Start()
                        $approvals=$u.GetUpdateApprovals()
                        $approvalTime.Stop()
                    }
                    $byGroup=@{}
                    if (!$u.IsDeclined) {
                        foreach ($approval in $approvals) {
                            $entry=$byGroup[$approval.ComputerTargetGroupId]
                            if (!$entry) {
                                $entry=@{Actions=[Collections.Generic.List[string]]::new()
                                    Deadlines=[Collections.Generic.List[string]]::new()}
                                $byGroup[$approval.ComputerTargetGroupId]=$entry
                            }
                            $entry.Actions.Add([string]$approval.Action)
                            if ($approval.Action -eq 'Install' -and $approval.Deadline -ne [datetime]::MaxValue) {
                                $entry.Deadlines.Add((TimeText $approval.Deadline))
                            }
                        }
                        foreach ($entry in $byGroup.Values) {
                            $entry.State=if ($entry.Actions.Count -eq 1) { $entry.Actions[0] } else { ($entry.Actions | Sort-Object -Unique) -join ',' }
                            $entry.Deadline=$entry.Deadlines -join ', '
                        }
                    }
                    $info=@{Update=$u; ByGroup=$byGroup; Declined=$u.IsDeclined}
                    $cache[$id]=$info
                }
                if ($info.Declined) { continue }
                $state='No approval set'
                if ($info.ByGroup.Count) {
                    foreach ($ancestor in $chain) {
                        $entry=$info.ByGroup[$ancestor.Id]
                        if ($entry) { $state=$entry.State; break }
                    }
                }
                $approved=$job.IncludeApproved -and $state -eq 'Install'
                if (!$approved -and (!$needed -or $state -notin @('No approval set','NotApproved','Scan'))) { continue }
                if (!$info.ContainsKey('Title')) {
                    $u=$info.Update
                    $info.Title=$u.Title; $info.KB=$u.KnowledgebaseArticles -join ', '
                    $info.Revision=$u.Id.RevisionNumber; $info.Superseded=$u.IsSuperseded
                    $info.Exclusion=if ($rules.Count) { [string](Exclusion $u $rules) } else { '' }
                }
                $row=[pscustomobject]@{GroupId=$g.Id; Depth=$chain.Count; Group=$groupPath; Title=$info.Title; KB=$info.KB
                    Missing=$missing; Downloaded=$downloaded; Failed=$failed
                    Needed=$needed; Id=$id; Revision=$info.Revision; Status=$state
                    Exclusion=$info.Exclusion; Superseded=$info.Superseded; CurrentDeadline=[string]$info.ByGroup[$g.Id].Deadline
                    Cells=@()}
                $label=$stateLabels[$state]
                if (!$label) { $label=$state }
                $supersededLabel=if ($row.Superseded) { 'Yes' } else { 'No' }
                $row.Cells=@($groupPath,$row.Title,$row.KB,$needed,$label,$row.CurrentDeadline,$supersededLabel,
                    $row.Exclusion,$id,$row.Revision,$missing,$downloaded,$failed)
                $all.Add($row)
                if (!$row.Superseded) { $current.Add($row) }
            }
        }
        $groupTime.Stop()
        $timings='Catalogue {0:N2}s | Approvals {1:N2}s | Group evaluation {2:N2}s' -f $catalogTime.Elapsed.TotalSeconds,
            $approvalTime.Elapsed.TotalSeconds,($groupTime.Elapsed-$catalogTime.Elapsed-$approvalTime.Elapsed).TotalSeconds
        [pscustomobject]@{All=$all.ToArray(); NonSuperseded=$current.ToArray(); Timings=$timings}
    }
    if ($job.Mode -eq 'Updates') {
        GetUpdateRows
        return
    }
    if ($job.Mode -eq 'Clients') {
        $scope=Scope $groups
        $scope.ToLastReportedStatusTime=$job.ReportCutoff
        foreach ($c in $ws.GetComputerTargets($scope)) {
            if (!(StaleReport $c)) { continue }
            $members = @($c.GetComputerTargetGroups() | Sort-Object Id)
            $r = [pscustomobject]@{Id=$c.Id; Name=$c.FullDomainName; IP=[string]$c.IPAddress
                Finding=$(if ($c.LastSyncTime -ge $job.ReportCutoff) { 'Synchronized recently' } else { 'Report overdue' })
                ReportTime=(TimeText $c.LastReportedStatusTime); Contact=(TimeText $c.LastSyncTime)
                Groups=($members.Name -join ', '); MembershipIds=(@($members | ForEach-Object {[string]$_.Id}) -join ',')}
            Log 'Client check' 'Result' $r
            $r
        }
        return
    }
    if ($job.Mode -eq 'Remote scan') {
        foreach ($r in $job.Rows) { RemoteScan $r }
        return
    }
    if ($config.IsReplicaServer) { throw 'Perform write operations on the upstream WSUS server.' }
    foreach ($r in $job.Rows) {
        $target = if ($job.Mode -eq 'Approval') { "$($r.Group) | $($r.Title)" } else { $r.Name }
        Log $job.Mode 'Requested' @{Target=$r; DeadlineUTC=$r.DeadlineUtc}
        $status = 'OK'
        try {
            if ($job.Mode -eq 'Approval') {
                $g = $ws.GetComputerTargetGroup([guid]$r.GroupId)
                $u = Latest $r.Id
                $reason = Exclusion $u @(ReadRules)
                if ($reason) { throw "Excluded by rule: $reason" }
                if ($u.IsDeclined -or $u.Id.RevisionNumber -ne $r.Revision -or
                    (State ($u.GetUpdateApprovals()) @(Chain $g)) -ne $r.Status) { throw 'Revision or approval status has changed.' }
                $deadline=if ($r.DeadlineUtc) { $r.DeadlineUtc } else { [datetime]::MaxValue }
                if ($deadline -le [datetime]::UtcNow) { throw 'The deadline has passed.' }
                [void]$u.Approve('Install',$g,$deadline)
                $message = if ($r.DeadlineUtc) { "Approved for installation | Deadline $($deadline.ToString('o'))" } else { 'Approved for installation | No deadline' }
            } elseif ($job.Mode -eq 'Remove') {
                $precheck=TestReAddClient $r
                $reAddGroupCatalog=$precheck.Catalog
                if (($precheck.Groups -join '; ') -ne $r.ApprovedClientGroups) { throw 'Configured target groups changed after the preview.' }
                $c=$precheck.Computer
                Log 'Pre-removal check' 'OK' @{Computer=$r.Name; ClientId=$precheck.Identity.ClientId; Groups=$precheck.Groups}
                $members = @($c.GetComputerTargetGroups() | Sort-Object Id)
                $ids = @($members | ForEach-Object {[string]$_.Id})
                if (!(StaleReport $c) -or $c.FullDomainName -ne $r.Name -or [string]$c.IPAddress -ne $r.IP -or
                    ($ids -join ',') -ne $r.MembershipIds -or !($members | Where-Object { $job.Groups -contains $_.Id })) {
                    throw 'Activity, identity or group membership has changed.'
                }
                $priorReportTicks=$c.LastReportedStatusTime.Ticks
                $priorScan=$null; $priorFinished=$null
                foreach ($file in (Get-ChildItem -LiteralPath $store -Filter '*.json' -File)) {
                    try { $prior=ReadCase $file.FullName } catch { continue }
                    if ($prior.Endpoint -eq $endpoint -and $prior.Kind -eq 'Scan' -and $prior.ScanResult -like 'OK | *' -and
                        $prior.Id -eq $c.Id -and $prior.Name -eq $c.FullDomainName -and $prior.IP -eq [string]$c.IPAddress -and
                        $prior.MachineGuid -eq $precheck.Identity.MachineGuid -and $prior.ScanFinishedUtc -and
                        [long]$prior.Report -eq $c.LastReportedStatusTime.Ticks) {
                        try { $finished=CaseTime $prior.ScanFinishedUtc } catch { continue }
                        if ($finished -ge [datetime]::UtcNow.AddDays(-2) -and (!$priorFinished -or $finished -gt $priorFinished)) {
                            $priorScan=$prior; $priorFinished=$finished
                        }
                    }
                }
                if (!$priorScan) {
                    $scan=RemoteScan $r $null $precheck
                    $scan
                    if ($scan.Status -ne 'OK') { throw "Pre-removal scan failed: $($scan.Message)" }
                    $message="Removal deferred. Wait $($job.GraceMinutes) minutes after a successful scan, then refresh the client list."
                    Log $job.Mode 'Deferred' @{Target=$r; Message=$message}
                    [pscustomobject]@{Action=$job.Mode; Target=$target; Status='Deferred'; Message=$message}
                    continue
                }
                $ready=$priorFinished.AddMinutes($job.GraceMinutes)
                if ($ready -gt [datetime]::UtcNow) {
                    $message="Waiting for a status report until $($ready.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))."
                    Log $job.Mode 'Deferred' @{Target=$r; Message=$message}
                    [pscustomobject]@{Action=$job.Mode; Target=$target; Status='Deferred'; Message=$message}
                    continue
                }
                $latestCheck=TestReAddClient $r $true
                if ($latestCheck.Identity.MachineGuid -ne $precheck.Identity.MachineGuid -or
                    ($latestCheck.Groups -join '; ') -ne $r.ApprovedClientGroups) { throw 'Endpoint identity or target groups changed before removal.' }
                $c=$latestCheck.Computer
                if (!(StaleReport $c) -or $c.LastReportedStatusTime.Ticks -ne [long]$priorReportTicks -or
                    $c.FullDomainName -ne $r.Name -or [string]$c.IPAddress -ne $r.IP) {
                    throw 'The client changed while checking the previous scan. Refresh the client list.'
                }
                $ids=@($c.GetComputerTargetGroups() | Sort-Object Id | ForEach-Object { [string]$_.Id })
                if (($ids -join ',') -ne $r.MembershipIds) { throw 'Group membership changed before removal.' }
                $case = NewCase $c 'Remove' $precheck.Identity.MachineGuid $latestCheck.Groups $priorScan
                $c.Delete()
                $case.Removed=$true; $case.RemovalState='Removed'; $case.RemovedUtc=$case.Start
                AddCaseEvent $case 'WSUS record removed' 'The original computer entry was deleted.'
                try { SaveCase $case; $message='WSUS computer record removed' }
                catch { $status='Partial'; $message="WSUS record removed. Local case update failed. Use Retry re-registration. $($_.Exception.Message)" }
            } else { throw 'Unknown action.' }
        } catch { $status = 'Error'; $message = $_.Exception.GetBaseException().Message }
        Log $job.Mode $status @{Target=$r; Message=$message; DeadlineUTC=$(if ($r.DeadlineUtc) { $r.DeadlineUtc.ToString('o') })}
        [pscustomobject]@{Action=$job.Mode; Target=$target; Status=$status; Message=$message}
        if ($job.Mode -eq 'Remove' -and $status -eq 'OK') { RemoteScan $r $case }
    }
}

$invokeWorker={
    param($definition,$request)
    try { & ([scriptblock]::Create($definition)) $request }
    catch {
        $failure=$_
        $message=$failure.Exception.GetBaseException().Message
        try { Write-Audit $request.Log $request.Server $request.Operation $request.Mode 'Aborted' $message $request.LocalLog $request.AuditState }
        catch { Write-Warning "Could not audit the failed operation. $($_.Exception.GetBaseException().Message)" }
        throw $failure
    }
}

# Dashboard queries run independently of administrative operations.
$reportWorker = {
    param($connection,$q,$snapshot,$metadata)
    $ErrorActionPreference='Stop'
    $duration=[Diagnostics.Stopwatch]::StartNew()
    $newList=$null -eq $snapshot
    if (!$metadata) { $metadata=@{} }
    $learned=@{}
    $related=@{}
    $ws=$null
    if ($newList) {
        Import-Module UpdateServices
        $ws=Get-WsusServer @connection
    }
    $states=@{Installed='Installed'; InstalledPendingReboot='Restart pending'; NotInstalled='Not downloaded'
        Downloaded='Downloaded'; Failed='Failed'; Unknown='Unknown'; NotApplicable='Not applicable'}
    $actions=@{Install='Approved for installation'; Uninstall='Approved for removal'; NotApproved='Not approved'
        Scan='Detect only'; All='All'}
    function Row($cells,$next='',$id='',$group='') {
        [pscustomobject]@{Cells=@($cells); Next=$next; Id=[string]$id; Group=[string]$group}
    }
    function Update($id) {
        $ws.GetUpdate([Microsoft.UpdateServices.Administration.UpdateRevisionId]::new([guid]$id))
    }
    function LocalTime($t) {
        if (!$t -or $t.Year -lt 1900) { return '-' }
        [datetime]::SpecifyKind($t,'Utc').ToLocalTime().ToString('yyyy-MM-dd HH:mm')
    }
    function ReportSnapshot($title,$columns,$entries,$stamp) {
        $ids=@{}
        foreach ($entry in $entries) {
            if ($entry.Next -eq 'PC' -and $entry.Id) { $ids[[string]$entry.Id]=$true }
        }
        @{Title=$title; Columns=$columns; Entries=$entries; ComputerIds=$ids; Stamp=$stamp}
    }
    function ReadRollout($includeApproved) {
        $scope=New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
        $scope.IncludeDownstreamComputerTargets=$true
        $scope.IncludedInstallationStates='NotInstalled, Downloaded, Failed'
        $updateScope=New-Object Microsoft.UpdateServices.Administration.UpdateScope
        $approvedScope=New-Object Microsoft.UpdateServices.Administration.UpdateScope
        $approvedScope.IncludedInstallationStates=$scope.IncludedInstallationStates
        $approvedScope.UpdateApprovalActions='Install'
        $computers=@{}
        foreach ($c in $ws.GetComputerTargets($scope)) { $computers[[string]$c.Id]=$c }
        $approved=[Collections.Generic.List[object]]::new()
        $all=@(foreach ($s in $ws.GetSummariesPerComputerTarget($updateScope,$scope)) {
            $c=$computers[[string]$s.ComputerTargetId]
            $count=$s.NotInstalledCount+$s.DownloadedCount+$s.FailedCount
            if (!$c -or !$count) { continue }
            $last=LocalTime $c.LastReportedStatusTime
            Row @($c.FullDomainName,$count,$s.NotInstalledCount,$s.DownloadedCount,$s.FailedCount,$last,[string]$c.IPAddress) 'PC' $c.Id
            if ($includeApproved) {
                $counts=@{NotInstalled=0; Downloaded=0; Failed=0}
                foreach ($i in $c.GetUpdateInstallationInfoPerUpdate($approvedScope)) {
                    $state=[string]$i.UpdateInstallationState
                    if ($i.UpdateApprovalAction -eq 'Install' -and $counts.ContainsKey($state)) { $counts[$state]++ }
                }
                $total=$counts.NotInstalled+$counts.Downloaded+$counts.Failed
                if ($total) {
                    $approved.Add((Row @($c.FullDomainName,$total,$counts.NotInstalled,$counts.Downloaded,$counts.Failed,$last,[string]$c.IPAddress) 'PC' $c.Id))
                }
            }
        })
        $columns=@('Computer','Outstanding','Not downloaded','Downloaded','Failed','Last WSUS report','WSUS IP')
        $order=@(@{Expression={$_.Cells[1]};Descending=$true},@{Expression={$_.Cells[0]}})
        $stamp=[datetime]::UtcNow.Ticks.ToString()
        $all=@($all | Sort-Object $order)
        $related['Computers needing updates']=ReportSnapshot 'Missing updates including unapproved' $columns $all $stamp
        $related['Computers with errors']=ReportSnapshot 'Computers with installation errors' $columns @($all | Where-Object { $_.Cells[4] -gt 0 }) $stamp
        if ($includeApproved) {
            $related['Approved outstanding']=ReportSnapshot 'Missing updates approved for installation' $columns @($approved | Sort-Object $order) $stamp
        }
    }
    function ReadUnknownGroups($status) {
        $rows=@(foreach ($name in ($status.UnrecognizedClientRequestedTargetGroupNames | Sort-Object -Unique)) {
            if ($name) { Row @([string]$name) }
        })
        ReportSnapshot 'Unrecognized groups requested by clients' @('Requested group name') $rows ([datetime]::UtcNow.Ticks.ToString())
    }
    function ReadDeadlines {
        $scope=New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
        $scope.IncludeDownstreamComputerTargets=$true
        $scope.IncludedInstallationStates='NotInstalled, Downloaded, Failed, InstalledPendingReboot'
        $updates=New-Object Microsoft.UpdateServices.Administration.UpdateScope
        $updates.UpdateApprovalActions='Install'
        $approvalIndex=@{}
        foreach ($a in $ws.GetUpdateApprovals($updates)) {
            if ($a.Action -ne 'Install') { continue }
            $key="$($a.UpdateId.UpdateId)/$($a.ComputerTargetGroupId)"
            if ($approvalIndex.ContainsKey($key) -and $approvalIndex[$key].Deadline -ne $a.Deadline) {
                $approvalIndex[$key]=$null
            } elseif (!$approvalIndex.ContainsKey($key)) { $approvalIndex[$key]=$a }
        }
        $updates.IncludedInstallationStates=$scope.IncludedInstallationStates
        $groups=@{}; $titles=@{}
        foreach ($g in $ws.GetComputerTargetGroups()) { $groups[[string]$g.Id]=$g.Name }
        $now=[datetime]::UtcNow; $week=$now.AddDays(7)
        $rows=@(foreach ($c in $ws.GetComputerTargets($scope)) {
            $last=LocalTime $c.LastReportedStatusTime
            foreach ($i in $c.GetUpdateInstallationInfoPerUpdate($updates)) {
                $state=[string]$i.UpdateInstallationState
                if ($i.UpdateApprovalAction -ne 'Install' -or $state -notin @('NotInstalled','Downloaded','Failed','InstalledPendingReboot')) { continue }
                $groupId=[string]$i.UpdateApprovalTargetGroupId; $id=[string]$i.UpdateId
                $approval=$approvalIndex["$id/$groupId"]
                $due=$null; $bucket='Unresolved'
                if ($approval) {
                    if ($approval.Deadline.Year -eq 9999) { $bucket='No deadline' }
                    else {
                        $due=[datetime]::SpecifyKind($approval.Deadline,'Utc')
                        $bucket=if ($due -lt $now) { 'Overdue' } elseif ($due -le $week) { 'Next 7 days' } else { 'Later' }
                    }
                }
                if (!$titles.ContainsKey($id)) {
                    try { $u=$i.GetUpdate(); $titles[$id]=@{KB=$u.KnowledgebaseArticles -join ', ';Title=$u.Title} }
                    catch { $titles[$id]=@{KB='-';Title=$id} }
                }
                $groupName=if ($groups.ContainsKey($groupId)) { $groups[$groupId] } else { $groupId }
                $r=Row @($c.FullDomainName,$titles[$id].KB,$titles[$id].Title,(LocalTime $due),$bucket,$groupName,$states[$state],$last) 'PC' $c.Id
                $r
            }
        })
        $rows=@($rows | Sort-Object @{Expression={if ($_.Cells[3] -eq '-') { '9999' } else { $_.Cells[3] }}},@{Expression={$_.Cells[0]}})
        $cols=@('Computer','KB','Update','Effective deadline (local)','Due','Effective group','Installation status','Last WSUS report')
        $stamp=$now.Ticks.ToString()
        $related['Deadlines']=ReportSnapshot 'Installation deadlines by PC' $cols $rows $stamp
        $related['Overdue deadlines']=ReportSnapshot 'Overdue installation deadlines' $cols @($rows | Where-Object { $_.Cells[4] -eq 'Overdue' }) $stamp
        $related['Deadlines next 7 days']=ReportSnapshot 'Installation deadlines in the next 7 days' $cols @($rows | Where-Object { $_.Cells[4] -eq 'Next 7 days' }) $stamp
        $related['Restart pending']=ReportSnapshot 'Approved updates waiting for a restart' $cols @($rows | Where-Object { $_.Cells[6] -eq 'Restart pending' }) $stamp
    }
    if ($newList) {
        $title=$q.Label
        $entries=@(switch ($q.Kind) {
            'Server' {
                $cols=@('Server-wide metric','Count')
                $v=$ws.GetStatus()
                $related['Unknown target groups']=ReadUnknownGroups $v
                $metrics=@(
                    Row @('Registered computers',$v.ComputerTargetCount)
                    Row @('Computers with no applicable updates outstanding',$v.ComputersUpToDateCount)
                    Row @('Approved updates',$v.ApprovedUpdateCount)
                    Row @('Unapproved updates',$v.NotApprovedUpdateCount)
                    Row @('Updates needed by computers',$v.UpdatesNeededByComputersCount)
                    Row @('Updates awaiting content files',$v.UpdatesNeedingFilesCount)
                    Row @('Updates with server download errors',$v.UpdatesWithServerErrorsCount)
                    Row @('Unrecognized client target groups',$related['Unknown target groups'].Entries.Count) 'Unknown target groups'
                    try {
                        $sync=$ws.GetSubscription().GetLastSynchronizationInfo()
                        Row @('Last synchronization (local)',(LocalTime $sync.EndTime))
                        Row @('Synchronization result',[string]$sync.Result)
                    } catch { Row @('Last synchronization','Unavailable') }
                )
                if ($null -ne $q.PreviewQueue) {
                    $q.PreviewQueue.Enqueue([pscustomobject]@{Title=$title;Columns=$cols;Rows=$metrics;Total=$metrics.Count
                        Page=0;Stamp=[datetime]::UtcNow.Ticks.ToString()})
                }
                ReadRollout $true
                $metrics[0]; $metrics[1]
                Row @('PCs missing approved updates',$related['Approved outstanding'].Entries.Count) 'Approved outstanding'
                Row @('PCs missing updates incl. unapproved',$related['Computers needing updates'].Entries.Count) 'Computers needing updates'
                Row @('Computers with installation errors',$related['Computers with errors'].Entries.Count) 'Computers with errors'
                $metrics[2..($metrics.Count-1)]
            }
            { $_ -in @('Deadlines','Overdue deadlines','Deadlines next 7 days','Restart pending') } {
                ReadDeadlines
                $list=$related[$q.Kind]; $title=$list.Title; $cols=$list.Columns; $list.Entries
            }
            'Update search' {
                $cols=@('Update','KB','Revision','Update ID')
                $found=$ws.SearchUpdates($q.Text)
                foreach ($u in ($found | Sort-Object Title,@{Expression={$_.Id.UpdateId}},@{Expression={$_.Id.RevisionNumber}})) {
                    Row @($u.Title,($u.KnowledgebaseArticles -join ', '),$u.Id.RevisionNumber,$u.Id.UpdateId) 'Update' $u.Id.UpdateId
                }
            }
            'Computer search' {
                $cols=@('Computer','IP','Last contact','Last report')
                $found=$ws.SearchComputerTargets($q.Text)
                foreach ($c in ($found | Sort-Object FullDomainName,Id)) {
                    Row @($c.FullDomainName,[string]$c.IPAddress,(LocalTime $c.LastSyncTime),(LocalTime $c.LastReportedStatusTime)) 'PC' $c.Id
                }
            }
            { $_ -in @('Computers needing updates','Approved outstanding','Computers with errors','Unknown target groups') } {
                if ($_ -eq 'Unknown target groups') { $list=ReadUnknownGroups ($ws.GetStatus()) }
                else { ReadRollout ($_ -eq 'Approved outstanding'); $list=$related[$q.Kind] }
                $title=$list.Title; $cols=$list.Columns; $list.Entries
            }
            'Update' {
                $u=Update $q.Id
                $title="$($u.Title) | Revision $($u.Id.RevisionNumber)"
                $cols=@('Group','Approval','Source','Deadline (local)','Installed','Restart pending','Downloaded','Missing','Error','Unknown','Not applicable')
                $groups=@{}; $approvals=@{}; $parents=@{}
                foreach ($g in $ws.GetComputerTargetGroups()) { $groups[$g.Id]=$g }
                foreach ($a in $u.GetUpdateApprovals()) { $approvals[$a.ComputerTargetGroupId]=$a }
                $summary=$u.GetSummaryPerComputerTargetGroup()
                foreach ($v in ($summary | Sort-Object ComputerTargetGroupId)) {
                    $g=$groups[$v.ComputerTargetGroupId]
                    if (!$g) { continue }
                    $ancestor=$g; $a=$null
                    while ($ancestor) {
                        $a=$approvals[$ancestor.Id]
                        if ($a -or $ancestor.Id -eq [Microsoft.UpdateServices.Administration.ComputerTargetGroupId]::AllComputers) { break }
                        if (!$parents.ContainsKey($ancestor.Id)) { $parents[$ancestor.Id]=$ancestor.GetParentTargetGroup() }
                        $ancestor=$parents[$ancestor.Id]
                    }
                    $state='No approval'; $origin='-'; $due='-'
                    if ($a) {
                        $state=$actions[[string]$a.Action]
                        $origin=if ($ancestor.Id -eq $g.Id) { 'Direct' } else { "Inherited from $($ancestor.Name)" }
                        if ($a.Deadline.Year -lt 9999) { $due=LocalTime $a.Deadline }
                    }
                    Row @($g.Name,$state,$origin,$due,$v.InstalledCount,$v.InstalledPendingRebootCount,$v.DownloadedCount,
                        $v.NotInstalledCount,$v.FailedCount,$v.UnknownCount,$v.NotApplicableCount) 'Computer list' $q.Id $g.Id
                }
            }
            'Computer list' {
                $u=Update $q.Id; $g=$ws.GetComputerTargetGroup([guid]$q.Group)
                $title="$($u.Title) | $($g.Name)"
                if ($q.Filter) { $title+=" | "+$states[$q.Filter] }
                $cols=@('Computer','Installation status','Effective approval','Last report','Effective deadline (local)')
                $scope=New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
                [void]$scope.ComputerTargetGroups.Add($g)
                $scope.IncludeSubgroups=$false
                $scope.IncludeDownstreamComputerTargets=$true
                $items=$u.GetUpdateInstallationInfoPerComputerTarget($scope)
                if ($q.Filter) { $items=@($items | Where-Object { [string]$_.UpdateInstallationState -eq $q.Filter }) }
                $clients=@{}
                $deadlines=@{}
                if ($items.Count) {
                    foreach ($c in $ws.GetComputerTargets($scope)) { $clients[[string]$c.Id]=$c }
                    foreach ($a in $u.GetUpdateApprovals()) {
                        $deadlines["$($a.ComputerTargetGroupId)/$($a.Action)"] = if ($a.Deadline -eq [datetime]::MaxValue) { '-' } else { LocalTime $a.Deadline }
                    }
                }
                $resultRows=foreach ($i in $items) {
                    $id=[string]$i.ComputerTargetId
                    $c=$clients[$id]
                    $name=if ($c) { $c.FullDomainName } else { $id }
                    $next=if ($c) { 'PC' } else { '' }
                    $deadline=$deadlines["$($i.UpdateApprovalTargetGroupId)/$($i.UpdateApprovalAction)"]
                    if (!$deadline) { $deadline='-' }
                    Row @($name,$states[[string]$i.UpdateInstallationState],$actions[[string]$i.UpdateApprovalAction],
                        (LocalTime $c.LastReportedStatusTime),$deadline) $next $id
                }
                $resultRows | Sort-Object { $_.Cells[0] },Id
            }
            'PC' {
                $c=$ws.GetComputerTarget($q.Id)
                $title="$($c.FullDomainName) | Report: $(LocalTime $c.LastReportedStatusTime) | Groups: $(($c.GetComputerTargetGroups().Name) -join ', ')"
                $cols=@('Update','Installation status','Effective approval','KB')
                $us=New-Object Microsoft.UpdateServices.Administration.UpdateScope
                if ($q.Filter -in @('Outstanding','Approved outstanding')) {
                    $title+=' | Outstanding updates'
                    $us.IncludedInstallationStates='NotInstalled, Downloaded, Failed'
                } elseif ($q.Filter) { $us.IncludedInstallationStates=$q.Filter }
                $items=$c.GetUpdateInstallationInfoPerUpdate($us)
                if ($q.Filter -in @('Outstanding','Approved outstanding')) {
                    $items=@($items | Where-Object { [string]$_.UpdateInstallationState -in @('NotInstalled','Downloaded','Failed') -and
                        ($q.Filter -ne 'Approved outstanding' -or $_.UpdateApprovalAction -eq 'Install') })
                } elseif ($q.Filter) { $items=@($items | Where-Object { [string]$_.UpdateInstallationState -eq $q.Filter }) }
                foreach ($i in ($items | Sort-Object UpdateId)) {
                    [pscustomobject]@{Id=[string]$i.UpdateId; State=[string]$i.UpdateInstallationState; Action=[string]$i.UpdateApprovalAction}
                }
            }
        })
        $snapshot=ReportSnapshot $title $cols $entries ([datetime]::UtcNow.Ticks.ToString())
        if ($q.Kind -eq 'Server') { $snapshot.Related=$related }
    }
    $total=$snapshot.Entries.Count
    $pageIndex=[Math]::Min([int]$q.Page,[int][Math]::Max(0,[Math]::Ceiling($total/100.0)-1))
    $rows=@(for ($n=$pageIndex*100; $n -lt [Math]::Min(($pageIndex+1)*100,$total); $n++) {
        $entry=$snapshot.Entries[$n]
        switch ($q.Kind) {
            'PC' {
                try {
                    $info=$metadata[$entry.Id]
                    if (!$info -or ([datetime]::UtcNow.Ticks - $info.Stamp) -ge $q.CacheTicks) {
                        if (!$ws) {
                            Import-Module UpdateServices
                            $ws=Get-WsusServer @connection
                        }
                        $u=Update $entry.Id
                        $info=@{Title=$u.Title; KB=($u.KnowledgebaseArticles -join ', '); Stamp=[datetime]::UtcNow.Ticks}
                        $learned[$entry.Id]=$info
                    }
                    Row @($info.Title,$states[$entry.State],$actions[$entry.Action],$info.KB) 'Update' $entry.Id
                } catch {
                    if ($_.Exception.GetBaseException().GetType().Name -ne 'WsusObjectNotFoundException') { throw }
                    Row @($entry.Id,$states[$entry.State],$actions[$entry.Action],'-')
                }
            }
            default { $entry }
        }
    })
    $source=if ($newList) { 'WSUS query' } elseif ($ws) { 'Result cache + WSUS details' } else { 'Result cache' }
    $data=[pscustomobject]@{Title=$snapshot.Title; Columns=$snapshot.Columns; Rows=$rows; Total=$total; Page=$pageIndex; Stamp=$snapshot.Stamp}
    [pscustomobject]@{Data=$data; Snapshot=$snapshot; Related=$related; Metadata=$learned; Source=$source; Seconds=$duration.Elapsed.TotalSeconds}

}

$highContrast=[Windows.Forms.SystemInformation]::HighContrast
$appVersion='1.1.0'
$appAuthor='chr1s5'
$palette=@{
    Header=[Drawing.Color]::FromArgb(20,39,59)
    Accent=[Drawing.Color]::FromArgb(22,85,131)
    Surface=[Drawing.Color]::FromArgb(240,245,250)
    Alternate=[Drawing.Color]::FromArgb(245,248,252)
}
# Multi-resolution ICO for the Windows caption and the application header.
$iconBase64=@'
AAABAAUAEBAAAAEAIADjAQAAVgAAABQUAAABACAAdQIAADkCAAAYGAAAAQAgAMgCAACuBAAAICAA
AAEAIABoAwAAdgcAADAwAAABACAAAgUAAN4KAACJUE5HDQoaCgAAAA1JSERSAAAAEAAAABAIBgAA
AB/z/2EAAAABc1JHQgCuzhzpAAAABGdBTUEAALGPC/xhBQAAAAlwSFlzAAAOwwAADsMBx2+oZAAA
AXhJREFUOE9jYGBgYBCNny8hETd7vkTs7PsScbP/48UQNcvF4mdZgPQyiMdPV5CInfUeQyERWDx+
tgMDyDR0CaJx7OzzDMi2GxWu+N+09ixebFm2GsUQkAvgnOtvvv0/eO3B/2sv3v9//fs/Vvz02x/c
BoAUaPjk/m+auwHMRpaDyaOLoxiw9+ZLDBvR8cUXn3AbQA5GMaBj4wUMG2F46u5r/2Pm7v/v3b4F
FPrYDQApjKqY9H/etqMoflUsWvw/9MbJ/0lfroCx76kj/2XS52EaAArhCat2/991/hbc5v5tl/+H
3z0N1xz74ux/9+1r/3scOIBpQGT/Lox4t+vdCNboc2Tr//h3F/6rZlWD2QnvL0EMEI+d9R3ZEHSs
UroUbIBRR/9/2fCC//ZLF4H5ca8vwlwwaz+6JnQcdOUE3BUwr7hs3/tfInbWawaJmNke6BrQsULO
QrghIOy2Z/9/qeS5/8VjZ1dAcmTMrASCORIp6sRjZ/2AaQYAHFNup98ESbsAAAAASUVORK5CYIKJ
UE5HDQoaCgAAAA1JSERSAAAAFAAAABQIBgAAAI2JHQ0AAAABc1JHQgCuzhzpAAAABGdBTUEAALGP
C/xhBQAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAgpJREFUOE9jYIACiZjZHhJxs9dLxM56LhE3+z9R
GKIWpCcDZg7EsLjZ/RiKScWxs4/Lx8/nYBCPmRmBIUk2ntXOIB43azumBJk4dvZ9BonYWe+RBYO7
tv9vWnuWKJw4ZR+GoaDwg3N0cpf8f/rtz/+7776C8evf/wli++p1uA30bd0CVmQXX/vfPKICzD5y
781/37YtKLh08XG4gSA9OA10a9gIVjRv21EwBrEvvvj0v3HNWRQ858BN4gwEYZDibVeeEYVXnXrw
Xy55Hn4DKcUYBk7bfQ0j4JHx9TffwN6OnrD7f0DHtv8yiXNxGwgLw6V7ToMxeqTYVq75r92w4n/A
+WP/k75c+R/3+uJ/l+17/8ukI7yNM5YNgopQIqV86cn/uk0rwQah4/C7p/9LJUNcipEOQYZce/Ee
jJG9WrPi1P/QGydRDIp6dOK/dmkzmG02exOmgSCMK6eYVa0Ca4y4feR/0IW9/+PfXfivnFz+3//k
DrC499HDEAPFY2d9RzcUG5ZOnvc/4f0lsIEgg1Szqv87rV4Kd63bnv2gwuE/A6jYQdeMC/ueOgLW
HPvi7H/7pYtQvG8yfeN/8diZHxnEY2c3oGvEhRULF/+PfnYeI1JAFkHVLGcAFYrisbOvo2vGhUFJ
xHbldnDSAYUbLDJApZZo/HwJcIktHz9fQDxu9nRiwxMLXg4zDADB3M0aXW/TzQAAAABJRU5ErkJg
golQTkcNChoKAAAADUlIRFIAAAAYAAAAGAgGAAAA4Hc9+AAAAAFzUkdCAK7OHOkAAAAEZ0FNQQAA
sY8L/GEFAAAACXBIWXMAAA7DAAAOwwHHb6hkAAACXUlEQVRIS2NggAL5+PkC4rGzK8TjZm2XiJ31
XiJu9n+SMFjPrP3isbMbROPnS8DMBQOp+FkGErGz72NoIhfHznovGTMzAO5yqhoOxeKxs76Lx09X
YJCIm9WOLklFvBxkwX4sEtTBsbPvM4C8gi6RPvPg/21XnpGEc+cd+S+XPA/DEgZ0gcj+Xf9f//5P
FgZZgm4ehgVNa8+CFUdVTPov7ZD8/9qL92A+yJWNa85iYJA4zAKQXnTz8FogYhn7/8KjV2A+yDB0
tSAMEifJApoHEQiDIhnkGlIw0ZFMbYxhAcgVcw7cxPA+Nnzxxaf//dsug30MClrV9AWELQB5FaQZ
lHoOXnsANww9Ffm3b/uv1bDiv9ue/f8Dzh8DY4sFW/5LJc/FbwEsFdnF1/7nNY74f+LOUzAfPRVZ
L9n6P+nLFQwcfvf0f+XSJYQt6Fq87b93Tvv/u+++ogTLkXtv/uu3r8YwGISjHp0A00FXTvyXiMdh
gX31OoywRsbtGy/89z56GMPw2Bdn/8uGF8At0ahbjt0CEDYqXPHft3ULVqyZvfh/5KOzYEO89m78
H//uApitnFz+3+cIIthA8YHTAkI49MZJsCEum1b+1yho+G/Q1PXfdv48FB+ZTN8ItSB29nl0Awhh
l+174QaBfAGyAD3IwBEdO+s9g3jc7OnoBhDC8jkL/se9vohhKAyDHABSB6rfGSTjZ2pgqxPw4tjZ
4EgEJUl0w0H5QhqWF2Jme4DrZYnYWRkYhhCBQZlKt2P1f9uV28GRqlq1DFm+H6VlIRY/ywLkJZJ9
g4Fn7Ye7HAgAlnR6cBfFsGkAAAAASUVORK5CYIKJUE5HDQoaCgAAAA1JSERSAAAAIAAAACAIBgAA
AHN6evQAAAABc1JHQgCuzhzpAAAABGdBTUEAALGPC/xhBQAAAAlwSFlzAAAOwwAADsMBx2+oZAAA
Av1JREFUWEfNl11IFFEUx+exl8CHbGalWMMXwaKHPmgJUQLDByULwo32zkgWBbVgoBUIQVrUSyw9
xOaMumGGmCYmpZGCS2wfbiyrJZlUFkVmKC1FGFFw4lydaffelpnZ3ZYGfuzuzL3/87/n3DnsFQTm
cnhaqiRZPS/J6qgka5AZqJZP9Kg1TiWwgo1Jr1wlIImyOsRPziwi0aYcSkthQnBR8edLRI2xg/8V
IlG/r1bUbYaBzKbbGpgJWg7R0+JmH2YLkWinBFHW/OyDbIF7TpCIFmUfZA2ixgTu5jLrvZ3QGpyG
+Z+QFh0PXkFJYx+nr5PUwI3wW04sVUIzC5y+qQF98s3741B2qAmu9Ac5YTuw+pYNFFZ4YeUmN6xy
EUuC7Hyz8aYGmtr6qYEjZ1stCbLzzcYnNYB1Y0VSZWphkdM3NVB57jZMzH3lxOwy8+UHeNtDnL6p
gWzx/xpIpxGNTH+Cy8PP4UxvBMilEdhS383pmxpIpRGF38egtLEP1h2/Bhsv9kJx9xBs1Qag8HQX
p29qQBdN1ojY8UhebRuU9N2DA98mOfZMPoaChk5wyK32DFhtRBh874sxLnA8NbGnsOFCjz0DyRqR
zofFX+A60QM7Boa5gDpkLgIVoTv0+/7ZKKw53G5uwGojGpycpallg+oon8chX66ni9g1dpfewzKZ
GrDaiHyDz2Cz/xYXWKeooZkGRxNoBu9VRR+Cw8yAHeLTj4EKak/StBcH2mnw3LKD4H4ZMsbI8xPG
3LQN4Eq2dy7VVzeAQfN2H6WfOS6PkXqd6tdP4jJAtDesqF1wZ+viuPK11XU0OFJyvYMrS3kwCJKy
9PccM9DFCtoFX8F97yIJJrD2WAI2OGK8ikR7JDiIWscKpkJRczcX6G/Q1f+Z5xOcSiBHIupHVjAV
8G3ADcYG1akMh4wegOnHE9ny0UwrZcVSxXnsKuwcGTW6IjYeDMx2QDyoxp0OBUHyaOWZyYRKN1jC
vbjfdOVscP2i5ZA1H24OXjhNlg5AAfZk/Budc6mm2qE+uwAAAABJRU5ErkJggolQTkcNChoKAAAA
DUlIRFIAAAAwAAAAMAgGAAAAVwL5hwAAAAFzUkdCAK7OHOkAAAAEZ0FNQQAAsY8L/GEFAAAACXBI
WXMAAA7DAAAOwwHHb6hkAAAEl0lEQVRoQ+2abWgURxjH76NfCiK0twm2AUsh0AqitWjB6ger0iq1
lqLV7K00FAOtIn6oQm1JU0qE0qYoRW5XcyotQeNrK0lRQxJMrFHCKbURWzUlvraKoaVa+gJT/mN2
O/s8c+fsJXu5gAu/JLuz88z/f/PM7NxOEokcR4WTGZ+scldaKe+AlXLbLdvrt1KeKAqyLbc9mXJb
LdutedTJWFRf3kMKt91BFniUSNrun0nb20B1sgOfupXymmiAksH2vitz0pVUtzzQTUVNkwJBb5Q7
7hSqP3E/13mFksT2shVOZlwgfmiw8htLGrdeikfqoFv4DaWPTCVMU7Rg7ODWJ+RcywrGBknbO5/A
D1owVkDqI4WMHlhPVDeKRR8fFnX7emMFbTxVs5O1nwtMn+wi5ZnVX4pTVwbFrX9EUTh/+56Y+W4z
06HDyMCu7ouskbhpu/AL06HDyMDl3/4KBT958Zr4pucHcenOXdbwSEJ16DAyoAZtbOkWj0xbJpk0
r0Zcvfs3a3ikoDp0RDZQuXB1YAB8vudoQQ3nih81TmQDLzjvhwx8dex0QQ3nih81TmQDR7I/iilL
1knxyzds1qYQrf8gaP0ocYwMnL35OwseN9fu/ct06DAy0NDyPWsgbjB1Ux06jAzgKbyt4wJrJC4O
Zq8YP42NDJQyDw2MNsYGVqU7Rcu56yxfhwsWbrt7+sWHe3slaMfZ0sbaz4WRAQSlDQ8XiJ5fe4i1
xXE11/7HyEDX5dtMQKHgmeILn7iqUUzdfEAs6OgQi7MnAnCO6+XV25kWipEBVQBWoHgCv/hWnajb
fpAJBLS+jsmbmsWK61nx5h/ncrL00mlR+UETq6sS2cBr6z4NrYU6+36OZACf+rxj7UxsPmbvPyJ7
o0wTL7IBLKFVA7peoPVVoor3mduqH9iRDaz5ZFfIwJmBX5kBCgYs4iBtqLB8LB84GTp/+qPdTJuR
ASysVEH4UrNxa7P8ZkbF6pjz3n6ZOg/KeZXJG+vlBzR1U0Nw7Y2B3vsD24loYDjzP2YdxHh26yEm
MhfPp9NBDz++dG2oDHFUbUYG8KqD9oIpXxztkzFe7j7OhOqY37ovlKI4V8sRJ7IBgNcc9B2OCTCP
+pgSVSGv9HwrZmUaQ3n+el+nmDB7ZSB++mdbmEHEKcjAcEH++iKcO2fE+JlVUmRyYY1Y9lOXsG/2
yr998ZVra5l4gDhq3KIZoD1Q/urbgVgIf7J6fXCOMhii4rU9UKxX64tOdYWE4FNXP3EfpBBSiQr3
QRw1bqJY20rPeV8zMToTL7Xln60QR42bkFuomgZHmop3dojUrbNMEExgqsSYwKCm5Sp4jiBOENf2
+vF6vZY2FhdRngU6sEIlMTMJbFvShuKEjgVTsMSmsawqb4G/Q9nACmMAq0ksKaKawP2op8bCzlKw
S4kty2Lv1CCddGNCBeV06SCx3UH27wePOe4MdmPMYEDO2HFYfgvzzeA3znE9NGAVsC0cEu8fyCnL
dm/QCrFga67pUO+z3cGc4v1j6P8lMizQKIOcZ2mT70g63hxpxHATMA6GVglNZVXpxVSff/wHIQq1
Kpuf4kQAAAAASUVORK5CYII=
'@
$appIconBytes=[Convert]::FromBase64String($iconBase64)
$appIconStream=[IO.MemoryStream]::new($appIconBytes)
$appIcon=[Drawing.Icon]::new($appIconStream,32,32)
# Load the 32px PNG entry directly for .NET Framework compatibility.
$headerIconEntry=6+3*16
$appIconImageStream=[IO.MemoryStream]::new($appIconBytes,
    [BitConverter]::ToInt32($appIconBytes,$headerIconEntry+12),
    [BitConverter]::ToInt32($appIconBytes,$headerIconEntry+8))
$appIconImage=[Drawing.Image]::FromStream($appIconImageStream)
function Bar($parent,$height=0) {
    $p = [Windows.Forms.FlowLayoutPanel]::new()
    $p.Dock = 'Top'; $p.Padding = [Windows.Forms.Padding]::new(8,5,8,5)
    if ($height) { $p.Height=$height }
    else { $p.AutoSize=$true; $p.AutoSizeMode='GrowAndShrink' }
    if (!$highContrast) { $p.BackColor=$palette.Surface }
    $parent.Controls.Add($p)
    $p
}
function Button($parent,$label,$click,[switch]$Primary,[switch]$PassThru) {
    $b = [Windows.Forms.Button]::new()
    $b.Text = $label; $b.AutoSize = $true
    $b.MinimumSize=[Drawing.Size]::new(0,29)
    $b.Padding=[Windows.Forms.Padding]::new(5,0,5,0)
    if ($Primary -and !$highContrast) {
        $b.FlatStyle='Flat'; $b.FlatAppearance.BorderSize=0
        $b.BackColor=$palette.Accent; $b.ForeColor=[Drawing.Color]::White
    }
    $b.Add_Click($click); $parent.Controls.Add($b)
    if ($PassThru) { $b }
}
function Label($parent,$value) {
    $l = [Windows.Forms.Label]::new()
    $l.Text = $value; $l.AutoSize = $true; $l.Margin = [Windows.Forms.Padding]::new(5,8,5,3)
    $l.UseMnemonic=$false
    $parent.Controls.Add($l)
}
function ListView($parent,$columns,$widths) {
    $v = [Windows.Forms.ListView]::new()
    $v.View = 'Details'; $v.Dock = 'Fill'; $v.FullRowSelect = $true
    $v.CheckBoxes = $true; $v.HideSelection = $false; $v.ShowItemToolTips=$true
    $v.BorderStyle='None'
    for ($i=0; $i -lt $columns.Count; $i++) { [void]$v.Columns.Add($columns[$i],$widths[$i]) }
    $parent.Controls.Add($v)
    $v
}
function AddRow($list,$record,$values) {
    $item = [Windows.Forms.ListViewItem]::new([string]$values[0])
    for ($column=1; $column -lt $values.Count; $column++) {
        [void]$item.SubItems.Add([string]$values[$column])
    }
    $item.Tag = $record
    if (!$highContrast -and ($list.Items.Count % 2)) { $item.BackColor=$palette.Alternate }
    [void]$list.Items.Add($item)
    $item
}
function SelectTableRows {
    param($rows,$text,$column,$descending)
    $terms=@($text -split '\s+' | Where-Object { $_ })
    if (!$terms.Count -and $column -lt 0) { return ,$rows }
    $ranked=[Collections.Generic.List[object]]::new()
    $comparison=[StringComparison]::OrdinalIgnoreCase
    $number=0
    foreach ($row in $rows) {
        $number++
        $score=0
        foreach ($term in $terms) {
            $best=0
            foreach ($cell in $row.Cells) {
                $value=[string]$cell
                if (!$value) { continue }
                $index=$value.IndexOf($term,$comparison)
                if ($index -lt 0) { continue }
                if ($index -eq 0 -and $value.Length -eq $term.Length) { $best=40; break }
                if ($index -eq 0) { $best=[Math]::Max(20,$best) }
                elseif (![char]::IsLetterOrDigit($value[$index-1])) { $best=[Math]::Max(12,$best) }
                else { $best=[Math]::Max(5,$best) }
            }
            if (!$best) { $score=-1; break }
            $score+=$best
        }
        if ($score -lt 0) { continue }
        $key=if ($column -ge 0) { $row.Cells[$column] } else { $score }
        $ranked.Add([pscustomobject]@{Row=$row; Key=$key; Position=$number})
    }
    $descendingOrder=$column -lt 0 -or $descending
    $ordered=@($ranked | Sort-Object -Property @{Expression='Key';Descending=$descendingOrder},Position |
        ForEach-Object Row)
    ,$ordered
}
function TableRows($view,$rows) {
    if (!$view) { return ,$rows }
    $text=$view.Box.Text.Trim()
    $view.WantedRows=$rows
    if (![object]::ReferenceEquals($view.Source,$rows) -or $view.Filter -ne $text -or
        $view.SortedColumn -ne $view.Column -or $view.SortedDescending -ne $view.Descending) {
        if ($rows.Count -gt 1000 -and ($text -or $view.Column -ge 0)) {
            if (!$view.Job) {
                $ps=[powershell]::Create()
                try {
                    [void]$ps.AddScript(${function:SelectTableRows}.ToString()).AddArgument($rows)
                    [void]$ps.AddArgument($text).AddArgument($view.Column).AddArgument($view.Descending)
                    $view.Job=@{PS=$ps;Async=$ps.BeginInvoke();Rows=$rows;Text=$text;Column=$view.Column;Descending=$view.Descending}
                    $view.AsyncTimer.Start()
                } catch { $ps.Dispose(); throw }
            }
            $view.Pending=$true
            $view.Caption.Text='Filtering / sorting ...'
            return ,@()
        }
        $view.Result=SelectTableRows $rows $text $view.Column $view.Descending
        $view.Source=$rows; $view.Filter=$text; $view.SortedColumn=$view.Column; $view.SortedDescending=$view.Descending
    }
    $view.Pending=$false
    $view.Caption.Text=if ($view.Error) { "$($view.Label) (error)" } else { $view.Label }
    ,$view.Result
}
function UpdateTableHeaders($view) {
    for ($index=0; $index -lt $view.List.Columns.Count; $index++) {
        $header=$view.List.Columns[$index]
        if (!$header.Tag) { $header.Tag=$header.Text }
        $header.Text=if ($index -eq $view.Column) {
            $arrow=if ($view.Descending) { [char]0x25BC } else { [char]0x25B2 }
            "$($header.Tag) $arrow"
        } else { $header.Tag }
    }
}
function NewTableFilter($list,$bar,$action,$label='Filter rows') {
    Label $bar $label
    $caption=$bar.Controls[$bar.Controls.Count-1]
    $box=[Windows.Forms.TextBox]::new()
    $box.Width=156; $box.AccessibleName=$label; $bar.Controls.Add($box)
    $box.AccessibleDescription='Type part of a displayed field. Words can match different columns.'
    $delay=[Windows.Forms.Timer]::new(); $delay.Interval=250
    $asyncTimer=[Windows.Forms.Timer]::new(); $asyncTimer.Interval=100
    $view=@{List=$list;Box=$box;Caption=$caption;Label=$label;Delay=$delay;AsyncTimer=$asyncTimer
        Action=$action;Rows=@();Column=-1;Descending=$false}
    $delay.Tag=$view; $box.Tag=$view; $list.Tag=$view
    $asyncTimer.Tag=$view
    $asyncTimer.Add_Tick({
        param($sender,$e)
        $state=$sender.Tag; $job=$state.Job
        if (!$job -or !$job.Async.IsCompleted) { return }
        $sender.Stop(); $state.Job=$null
        $result=@()
        $errorText=''
        try {
            $output=$job.PS.EndInvoke($job.Async)
            if ($output.Count -eq 1) { $result=$output[0].PSObject.BaseObject }
        } catch { $errorText=$_.Exception.GetBaseException().Message }
        finally { $job.PS.Dispose() }
        if ($state.Delay.Enabled) { return }
        if ([object]::ReferenceEquals($state.WantedRows,$job.Rows) -and $state.Box.Text.Trim() -eq $job.Text -and
            $state.Column -eq $job.Column -and $state.Descending -eq $job.Descending) {
            $state.Result=$result; $state.Source=$job.Rows; $state.Filter=$job.Text
            $state.SortedColumn=$job.Column; $state.SortedDescending=$job.Descending; $state.Error=$errorText
        }
        & $state.Action $state
        UpdateTableHeaders $state
    })
    $box.Add_TextChanged({
        param($sender,$e)
        $state=$sender.Tag
        $state.Column=-1; $state.Descending=$false; $state.FilterChanged=$true; $state.Page=0
        if ($null -ne $state.Checks) { $state.Checks.Clear() }
        $state.Error=''
        $state.Delay.Stop(); $state.Delay.Start()
    })
    $delay.Add_Tick({
        param($sender,$e)
        $sender.Stop()
        $state=$sender.Tag
        & $state.Action $state
        $state.FilterChanged=$false
        UpdateTableHeaders $state
    })
    $list.Add_ColumnClick({
        param($sender,$e)
        $state=$sender.Tag
        $state.Delay.Stop()
        $state.Descending=$state.Column -eq $e.Column -and !$state.Descending
        $state.Page=0
        $state.Column=$e.Column
        $state.Error=''
        & $state.Action $state
        $state.FilterChanged=$false
        UpdateTableHeaders $state
    })
    $list.Add_Disposed({
        param($sender,$e)
        $state=$sender.Tag
        $state.Delay.Dispose(); $state.AsyncTimer.Dispose()
        if ($state.Job) {
            try {
                if ($state.Job.Async.IsCompleted) { $state.Job.PS.Dispose() }
                else { [void]$state.Job.PS.BeginStop($null,$null) }
            } catch { Write-Verbose $_.Exception.Message }
        }
    })
    $view
}
function TableRow($data,$cells,$tooltip='') {
    [pscustomobject]@{Data=$data;Cells=$cells;ToolTip=$tooltip}
}
function TablePage($view,$matches) {
    $view.Matches=$matches
    if ($view.Pending) {
        if ($view.PageLabel) {
            $view.PageLabel.Text='Filtering / sorting ...'; $view.Previous.Enabled=$false; $view.Next.Enabled=$false
        }
        return
    }
    $pages=[Math]::Max(1,[int][Math]::Ceiling($matches.Count/[double]$view.PageSize))
    $view.Page=[Math]::Max(0,[Math]::Min([int]$view.Page,$pages-1))
    if ($view.PageLabel) {
        $view.PageLabel.Text="Page $($view.Page+1) of $pages | $($matches.Count) matches"
        $view.Previous.Enabled=$view.Page -gt 0; $view.Next.Enabled=$view.Page+1 -lt $pages
    }
    $start=$view.Page*$view.PageSize
    for ($n=$start; $n -lt [Math]::Min($matches.Count,$start+$view.PageSize); $n++) { $matches[$n] }
}
function AddTablePager($view,$parent) {
    $bar=Bar $parent; $bar.Dock='Bottom'
    $view.PageSize=200; $view.Page=0
    $view.Previous=Button $bar 'Previous' { param($sender,$e) $v=$sender.Tag; $v.Page--; & $v.Action $v } -PassThru
    Label $bar 'Page 1 of 1'; $view.PageLabel=$bar.Controls[$bar.Controls.Count-1]
    $view.Next=Button $bar 'Next' { param($sender,$e) $v=$sender.Tag; $v.Page++; & $v.Action $v } -PassThru
    $view.Previous.Tag=$view; $view.Next.Tag=$view
    $view.Previous.Enabled=$false; $view.Next.Enabled=$false
}
$onlineResults=@{}
$script:onlineGeneration=0
function OnlineLabel($result) {
    if (!$result) { return 'Not checked' }
    if ($result.Finding -eq 'DNS matches WSUS IP' -and $result.IpResult -like 'Reply*') { return 'Reachable' }
    if ($result.Finding -eq 'DNS matches WSUS IP' -and $result.IpResult -like 'No reply*') { return 'No reply' }
    'Unverified'
}
function OnlineFor($id,$name,$ip) {
    $result=$onlineResults[[string]$id]
    if ($result -and (!$name -or $result.Name -eq $name) -and (!$ip -or !$result.IP -or $ip -eq $result.IP)) { $result }
}
function PaintOnline($item,$column,$label) {
    $cell=$item.SubItems[$column]
    $item.UseItemStyleForSubItems=$false
    $cell.Text="$([char]0x25CF)  $label"
    $cell.ForeColor=switch ($label) {
        'Reachable' { [Drawing.Color]::ForestGreen }
        'Not checked' { [Drawing.SystemColors]::GrayText }
        default { [Drawing.Color]::Firebrick }
    }
}
function ShowOnlineDetails($id,$name,$ip) {
    $r=OnlineFor $id $name $ip
    if (!$r) { return }
    [void](Preview "Online check | $($r.Name)" @((OnlineLabel $r),$r.CheckedAt,"WSUS IP: $($r.IP)","DNS addresses: $($r.DNS)",
        "Ping by WSUS IP: $($r.IpResult)","Ping by DNS address: $($r.DnsResult)",$r.Finding,'',
        'A missing ICMP reply may also indicate blocked ping traffic.') $null)
}
function OnlineCellHit($list,$point) {
    $hit=$list.HitTest($point)
    if (!$hit.Item -or !$hit.SubItem) { return }
    $n=$hit.Item.SubItems.IndexOf($hit.SubItem)
    if ($n -ge 0 -and $list.Columns[$n].Name -eq 'Reachability') { return $hit.Item.Tag }
}
function EnableOnlineDetails($list) {
    $list.Add_MouseClick({ param($sender,$e)
        if ($e.Button -ne 'Left') { return }
        $r=OnlineCellHit $sender $e.Location
        if ($r) {
            if ($r.Name) { ShowOnlineDetails $r.Id $r.Name $r.IP }
            else { ShowOnlineDetails $r.Id $r.Cells[0] }
        }
    })
}
function ShowLocalTable($view,$identity='') {
    $list=$view.List
    $checked=@{}; $selected=@{}
    if ($identity -and $null -eq $view.Checks) {
        foreach ($item in $list.CheckedItems) { $checked[[string]$item.Tag.$identity]=$true }
        foreach ($item in $list.SelectedItems) { $selected[[string]$item.Tag.$identity]=$true }
    }
    $rows=TableRows $view $view.Rows
    if ($null -ne $view.Checks -and $view.Checks.Count -and $view.Filter -and !$view.Pending -and
        ![object]::ReferenceEquals($view.CheckSource,$rows)) {
        $keep=@{}
        foreach ($match in $rows) {
            $id=[string]$match.Data.Id
            if ($view.Checks.ContainsKey($id)) { $keep[$id]=$match.Data }
        }
        $view.Checks=$keep
    }
    $view.CheckSource=$rows
    if ($view.PageSize) { $rows=@(TablePage $view $rows) }
    if ($null -ne $view.Checks) { $checked=$view.Checks }
    if ($identity -and $null -eq $view.Checks -and $view.Pending) {
        if (!$view.PendingSelection) { $view.PendingSelection=@{Checked=$checked;Selected=$selected} }
    } elseif ($view.PendingSelection) {
        $checked=$view.PendingSelection.Checked; $selected=$view.PendingSelection.Selected
        $view.PendingSelection=$null
    }
    $list.BeginUpdate()
    try {
        $list.Items.Clear()
        foreach ($row in $rows) {
            $item=AddRow $list $row.Data $row.Cells
            $item.ToolTipText=$row.ToolTip
            if ($view.Online) { PaintOnline $item 5 $row.Cells[5] }
            if ($identity) {
                $key=[string]$row.Data.$identity
                $item.Checked=$checked.ContainsKey($key)
                $item.Selected=$selected.ContainsKey($key)
            }
        }
    } finally { $list.EndUpdate() }
}
function CheckedRows($list) {
    if ($null -ne $list.Tag.Checks) {
        if (!$list.Tag.Pending -and !$list.Tag.Delay.Enabled) { $list.Tag.Checks.Values }
        return
    }
    foreach ($item in $list.CheckedItems) { $item.Tag }
}
function Notice($text) {
    [void][Windows.Forms.MessageBox]::Show($form,$text,'WSUS-Manager','OK','Information')
}
function Preview($title,$lines,$commit) {
    $dialog = [Windows.Forms.Form]::new()
    $dialog.Icon=$appIcon
    $dialog.Text = $title; $dialog.Size = [Drawing.Size]::new(880,520); $dialog.StartPosition = 'CenterParent'
    $txt = [Windows.Forms.TextBox]::new()
    $txt.Multiline = $true; $txt.ReadOnly = $true; $txt.ScrollBars = 'Both'; $txt.WordWrap = $false
    $txt.Dock = 'Fill'; $txt.Text = $lines -join [Environment]::NewLine; $dialog.Controls.Add($txt)
    $panel = Bar $dialog 45
    $panel.Dock = 'Bottom'
    $cancel = [Windows.Forms.Button]::new(); $cancel.Text = 'Close'; $cancel.AutoSize = $true
    $cancel.DialogResult = 'Cancel'; $panel.Controls.Add($cancel)
    $dialog.CancelButton = $cancel; $dialog.AcceptButton = $cancel
    if ($commit) {
        $cancel.Text = 'Cancel'
        $b = [Windows.Forms.Button]::new(); $b.Text = $commit; $b.AutoSize = $true
        $b.DialogResult = 'OK'; $panel.Controls.Add($b)
    }
    try { $dialog.ShowDialog($form) -eq 'OK' } finally { $dialog.Dispose() }
}
$form = [Windows.Forms.Form]::new()
$form.Icon=$appIcon
$form.Text = "WSUS Manager v$appVersion"; $form.Size = [Drawing.Size]::new(1320,780)
$form.MinimumSize = [Drawing.Size]::new(900,570); $form.StartPosition = 'CenterScreen'
$form.AutoScaleMode='Dpi'
$form.Font=[Drawing.Font]::new('Segoe UI',9.5)
$workspace=[Windows.Forms.SplitContainer]::new()
$workspace.Dock='Fill'; $workspace.FixedPanel='Panel1'; $workspace.SplitterWidth=6
$workspace.Size=[Drawing.Size]::new(1280,650)
$workspace.Panel1MinSize=170; $workspace.Panel2MinSize=500; $workspace.SplitterDistance=245
$workspace.Panel1Collapsed=$true
$form.Controls.Add($workspace)
$tabs = [Windows.Forms.TabControl]::new(); $tabs.Dock = 'Fill'
$tabs.Padding=[Drawing.Point]::new(13,6)
$workspace.Panel2.Controls.Add($tabs)
$dashboard = [Windows.Forms.TabPage]::new('Dashboard')
$updates = [Windows.Forms.TabPage]::new('Updates')
$clients = [Windows.Forms.TabPage]::new('Client maintenance')
$history = [Windows.Forms.TabPage]::new('Audit log')
$tracking = [Windows.Forms.TabPage]::new('Re-registration')
$settings = [Windows.Forms.TabPage]::new('Exclusions')
foreach ($tab in @($dashboard,$updates,$clients,$tracking,$history,$settings)) { $tabs.TabPages.Add($tab) }
$groupBox = [Windows.Forms.CheckedListBox]::new(); $groupBox.Dock = 'Fill'
$groupBox.CheckOnClick = $true; $groupBox.HorizontalScrollbar = $true; $groupBox.IntegralHeight=$false
$groupBox.DisplayMember = 'Name'; $groupBox.AccessibleName='Target groups'; $groupBox.BorderStyle='None'
$workspace.Panel1.Controls.Add($groupBox)
$groupBar=Bar $workspace.Panel1
Label $groupBar 'Target groups'
Button $groupBar 'Reload' { StartWork 'Groups' }
$groupCount=[Windows.Forms.Label]::new()
$groupCount.Dock='Bottom'; $groupCount.Height=30; $groupCount.Padding=[Windows.Forms.Padding]::new(8,0,0,0)
$groupCount.TextAlign='MiddleLeft'; $groupCount.Text='No groups selected'
$workspace.Panel1.Controls.Add($groupCount)
$header=[Windows.Forms.Panel]::new()
$header.Height=58; $header.Dock='Top'
if (!$highContrast) { $header.BackColor=$palette.Header; $header.ForeColor=[Drawing.Color]::White }
$brand=[Windows.Forms.Panel]::new()
$brand.Dock='Left'; $brand.Width=226
$appTitle=[Windows.Forms.Label]::new()
$appTitle.Text='WSUS Manager'; $appTitle.Font=[Drawing.Font]::new($form.Font.FontFamily,16,[Drawing.FontStyle]::Bold)
$appTitle.Dock='Fill'; $appTitle.TextAlign='MiddleLeft'
$brandIconArea=[Windows.Forms.Panel]::new()
$brandIconArea.Dock='Left'; $brandIconArea.Width=52
$brandIcon=[Windows.Forms.PictureBox]::new()
$brandIcon.Image=$appIconImage; $brandIcon.SizeMode='Zoom'; $brandIcon.TabStop=$false
$brandIcon.Location=[Drawing.Point]::new(14,13); $brandIcon.Size=[Drawing.Size]::new(32,32)
$brandIconArea.Controls.Add($brandIcon)
$brand.Controls.Add($appTitle); $brand.Controls.Add($brandIconArea)
$banner = [Windows.Forms.Label]::new()
$banner.Dock='Fill'; $banner.AutoEllipsis=$true; $banner.TextAlign='MiddleLeft'
$banner.Padding=[Windows.Forms.Padding]::new(12,0,12,0); $banner.Text="Connecting to $script:auditServer ..."
$header.Controls.Add($banner); $header.Controls.Add($brand)
$form.Controls.Add($header)
$status = [Windows.Forms.StatusStrip]::new(); $hint = [Windows.Forms.ToolStripStatusLabel]::new()
$hint.Spring=$true; $hint.TextAlign='MiddleLeft'
$busyIndicator=[Windows.Forms.ToolStripProgressBar]::new()
$busyIndicator.Style='Marquee'; $busyIndicator.MarqueeAnimationSpeed=30; $busyIndicator.Visible=$false
$cancelWorkButton=[Windows.Forms.ToolStripButton]::new()
$cancelWorkButton.Text='Cancel query'; $cancelWorkButton.DisplayStyle='Text'; $cancelWorkButton.Available=$false
$cancelWorkButton.ToolTipText='Cancel the running query (Esc)'
$cancelWorkButton.Add_Click({ StopWork })
$authorCredit=[Windows.Forms.ToolStripStatusLabel]::new()
$authorCredit.Text="Created by $appAuthor"; $authorCredit.Padding=[Windows.Forms.Padding]::new(10,0,3,0)
[void]$status.Items.Add($hint); [void]$status.Items.Add($busyIndicator); [void]$status.Items.Add($cancelWorkButton)
[void]$status.Items.Add($authorCredit); $form.Controls.Add($status)
$ul = ListView $updates @('Target group','Update','KB','Affected PCs','Approval status','Direct deadline (local)','Superseded','Exclusion','Update ID','Revision','Not downloaded','Downloaded','Installation failed') @(136,249,80,95,155,146,85,165,235,70,120,110,160)
$ul.Columns[5].DisplayIndex=2
$cl = ListView $clients @('Computer','WSUS IP','Last report','Last contact','Groups','Online status','Finding') @(185,120,135,135,180,135,210)
$cl.Columns[5].Name='Reachability'
EnableOnlineDetails $cl
$cl.Columns[5].DisplayIndex=2
$script:updateRows = @()
$script:nonSupersededRows=@()
$script:updatePage=0
$updatePageSize=200
$checkedUpdates=@{}
$script:renderingUpdatePage=$false
function UpdateSelectionInfo {
    $approvalButton.Enabled=$checkedUpdates.Count -gt 0
    $updateSelectionLabel.Text="$($checkedUpdates.Count) checked"
}
function Clear-UpdateList {
    $script:updateRows=@(); $script:nonSupersededRows=@(); $script:updatePage=0
    $checkedUpdates.Clear()
    Show-UpdateRows
}
function Show-UpdateRows {
    $rows=if ($supersededFilter.Checked) { ,$script:nonSupersededRows } else { ,$script:updateRows }
    $rows=TableRows $updateTable $rows
    $pages=[int][Math]::Max(1,[Math]::Ceiling($rows.Count/[double]$updatePageSize))
    $script:updatePage=[Math]::Max(0,[Math]::Min($script:updatePage,$pages-1))
    $start=$script:updatePage*$updatePageSize
    $end=[Math]::Min($start+$updatePageSize,$rows.Count)
    $script:renderingUpdatePage=$true
    $ul.BeginUpdate()
    try {
        $ul.Items.Clear()
        for ($index=$start; $index -lt $end; $index++) {
            $row=$rows[$index]
            $item=AddRow $ul $row $row.Cells
            $item.ToolTipText="$($row.Title)`n$($row.Group) | $($row.Cells[4])"
            if ($row.Exclusion) {
                $item.ToolTipText+="`nExcluded by $($row.Exclusion)"
                if (!$highContrast) { $item.ForeColor=[Drawing.Color]::DimGray }
            }
            elseif ($checkedUpdates.ContainsKey("$($row.GroupId)/$($row.Id)")) { $item.Checked=$true }
        }
    } finally { $ul.EndUpdate(); $script:renderingUpdatePage=$false }
    $updatePrevButton.Enabled=$script:updatePage -gt 0
    $updateNextButton.Enabled=$script:updatePage+1 -lt $pages
    $updatePageLabel.Text="Page $($script:updatePage+1) of $pages | $($rows.Count) updates"
    UpdateSelectionInfo
}
$ub = Bar $updates
Button $ub 'Load updates' { StartWork 'Updates' }
$approvalButton=Button $ub 'Review group deadlines ...' { ApproveSelection } -Primary -PassThru
$approvalButton.Enabled=$false
Button $ub 'Check eligible on page' { foreach ($i in $ul.Items) { $i.Checked = !$i.Tag.Exclusion } }
Button $ub 'Uncheck all' { $checkedUpdates.Clear(); Show-UpdateRows }
$supersededFilter = [Windows.Forms.CheckBox]::new()
$supersededFilter.AutoSize = $true
$supersededFilter.Margin=[Windows.Forms.Padding]::new(7,7,4,5)
$supersededFilter.Text = 'Hide superseded updates'
$supersededFilter.Add_CheckedChanged({
    if ($supersededFilter.Checked) {
        foreach ($key in @($checkedUpdates.Keys)) {
            if ($checkedUpdates[$key].Superseded) { $checkedUpdates.Remove($key) }
        }
    }
    $script:updatePage=0
    Show-UpdateRows
})
$ub.Controls.Add($supersededFilter)
$includeApproved=[Windows.Forms.CheckBox]::new()
$includeApproved.AutoSize=$true; $includeApproved.Text='Include approved updates'
$includeApproved.Margin=$supersededFilter.Margin
$includeApproved.Add_CheckedChanged({ Clear-UpdateList })
$ub.Controls.Add($includeApproved)
$updateTable=NewTableFilter $ul $ub {
    param($view)
    if ($view.FilterChanged) { $checkedUpdates.Clear() }
    $script:updatePage=0
    Show-UpdateRows
}
$updateFooter=Bar $updates
$updateFooter.Dock='Bottom'
$updatePrevButton=Button $updateFooter 'Previous' { $script:updatePage--; Show-UpdateRows } -PassThru
$updatePageLabel=[Windows.Forms.Label]::new()
$updatePageLabel.AutoSize=$true; $updatePageLabel.Margin=[Windows.Forms.Padding]::new(5,8,5,3)
$updateFooter.Controls.Add($updatePageLabel)
$updateNextButton=Button $updateFooter 'Next' { $script:updatePage++; Show-UpdateRows } -PassThru
$updateSelectionLabel=[Windows.Forms.Label]::new()
$updateSelectionLabel.AutoSize=$true; $updateSelectionLabel.Margin=$updatePageLabel.Margin
$updateFooter.Controls.Add($updateSelectionLabel)
Show-UpdateRows
$cb = Bar $clients
Label $cb 'Last report older than (days)'
$days = [Windows.Forms.NumericUpDown]::new(); $days.Minimum = 1; $days.Maximum = 3650; $days.Value = 30; $days.Width = 65
$cb.Controls.Add($days)
Button $cb 'Load overdue clients' { StartWork 'Clients' } -Primary
$selectAllClients=[Windows.Forms.CheckBox]::new()
$selectAllClients.Text='Select all computers'; $selectAllClients.AutoSize=$true; $selectAllClients.Enabled=$false
$selectAllClients.Margin=$supersededFilter.Margin; $cb.Controls.Add($selectAllClients)
$selectAllClients.Add_Click({
    if ($clientTable.Pending -or $clientTable.Delay.Enabled) { return }
    $check=$clientTable.Checks.Count -lt $clientTable.Matches.Count
    $clientTable.Checks.Clear()
    if ($check) { foreach ($row in $clientTable.Matches) { $clientTable.Checks[[string]$row.Data.Id]=$row.Data } }
    ShowClientTable
})
$onlineButton=Button $cb 'Check online' { StartWork 'Online check' @(CheckedRows $cl) } -PassThru
$clientEventsButton=Button $cb 'Windows Update events ...' { OpenEventQuery @(CheckedRows $cl) } -PassThru
$preflightButton=Button $cb 'Check ReAdd readiness' { StartWork 'ReAdd check' @(CheckedRows $cl) } -PassThru
$scanButton=Button $cb 'Request new report ...' {
    $rows = @(CheckedRows $cl)
    if (!$rows.Count) { Notice 'Check at least one client in the list.'; return }
    $lines = @('Start a WSUS scan on the following computers using PowerShell remoting:', '') + @($rows | ForEach-Object { "$($_.Name) | $($_.IP)" })
    if (Preview 'Remote scan' $lines 'Start scan') { StartWork 'Remote scan' $rows }
} -PassThru
$scanButton.Enabled=$false
$removeButton=Button $cb 'Review re-registration ...' { RemoveSelection } -PassThru
$removeButton.Enabled=$false; $onlineButton.Enabled=$false; $preflightButton.Enabled=$false; $clientEventsButton.Enabled=$false
$clientTable=NewTableFilter $cl $cb { param($view) ShowClientTable }
$clientTable.Checks=@{}; $clientTable.Online=$true
AddTablePager $clientTable $clients
$wl = ListView $tracking @('Computer','Started','Stage','Scan','New contact','New report','Group comparison') @(160,135,170,240,140,140,350)
$wb = Bar $tracking
Button $wb 'Refresh status' { StartWork 'Reporting status' }
$timelineButton=Button $wb 'Open timeline' { ShowSelectedTimeline } -PassThru
$timelineButton.Enabled=$false
$caseEventsButton=Button $wb 'Windows Update events ...' {
    $cases=@(CheckedRows $wl)
    if (!$cases.Count -and $wl.SelectedItems.Count) { $cases=@($wl.SelectedItems[0].Tag) }
    OpenEventQuery $cases
} -PassThru
$caseEventsButton.Enabled=$false
$caseSourcesButton=Button $wb 'Read scan sources' {
    $cases=@(CheckedRows $wl)
    if (!$cases.Count -and $wl.SelectedItems.Count) { $cases=@($wl.SelectedItems[0].Tag) }
    if ($cases.Count) { StartWork 'Scan sources' $cases }
} -PassThru
$caseSourcesButton.Enabled=$false
$retryButton=Button $wb 'Retry re-registration ...' {
    $plans=@(CheckedRows $wl | Where-Object Retry)
    if (!$plans.Count) { Notice 'Select a removal case to retry.'; return }
    $lines=@('Verify the saved endpoint identity, then request detection and scan again.', '') + @($plans.Name)
    if (Preview 'Retry re-registration' $lines 'Retry') { StartWork 'Retry re-registration' $plans }
} -PassThru
$verifyButton=Button $wb 'Verify new ID ...' {
    $plans=@(CheckedRows $wl | Where-Object Verify)
    if (!$plans.Count) { Notice 'Select a returned client with a new WSUS ID and a saved endpoint identity.'; return }
    $lines=@('Compare the endpoint and WSUS client IDs over Kerberos.', '') + @($plans | ForEach-Object { "$($_.Name) | $($_.CurrentId)" })
    if (Preview 'Verify new WSUS client ID' $lines 'Verify') { StartWork 'Verify re-registration' $plans }
} -PassThru
$restoreButton=Button $wb 'Assign groups ...' {
    $plans = @(CheckedRows $wl | Where-Object { $_.Missing.Count })
    if (!$plans.Count) { Notice 'Select a computer with missing server-assigned groups.'; return }
    $lines = @($plans | ForEach-Object { "$($_.Name) [$($_.CurrentId)]"; foreach ($g in $_.Missing) { "    $($g.Name) [$($g.Id)]" } })
    if (Preview 'Assign missing groups' $lines 'Assign') { StartWork 'Restore groups' $plans }
} -PassThru
$retryButton.Enabled=$false; $verifyButton.Enabled=$false; $restoreButton.Enabled=$false
$auto = [Windows.Forms.CheckBox]::new(); $auto.Text='Refresh every 60 seconds'; $auto.Checked=$true; $auto.AutoSize=$true
$auto.Margin=$supersededFilter.Margin
$wb.Controls.Add($auto)
$trackingTable=NewTableFilter $wl $wb { param($view) ShowTrackingTable }
$hl = ListView $history @('Time (local)','User','WSUS','Action','Result','Details') @(140,155,130,155,95,550)
$hl.CheckBoxes=$false
$hb = Bar $history
Label $hb 'From'; $from=[Windows.Forms.DateTimePicker]::new(); $from.Format='Short'; $from.Width=95; $from.Value=(Get-Date).AddDays(-7); $hb.Controls.Add($from)
Label $hb 'To'; $until=[Windows.Forms.DateTimePicker]::new(); $until.Format='Short'; $until.Width=95; $hb.Controls.Add($until)
Label $hb 'User'; $userText=[Windows.Forms.TextBox]::new(); $hb.Controls.Add($userText)
Label $hb 'KB / group / PC'; $queryText=[Windows.Forms.TextBox]::new(); $queryText.Width=170; $hb.Controls.Add($queryText)
Button $hb 'Search audit log' { if ($from.Value.Date -gt $until.Value.Date) { Notice 'Check the date range.' } else { StartWork 'Audit log' } } -Primary
Button $hb 'Log location ...' { ShowLogSettings }
Button $hb 'Open log folder' { Start-Process explorer.exe -ArgumentList ('"{0}"' -f $LogDirectory) }
$auditTable=NewTableFilter $hl $hb { param($view) ShowLocalTable $view }
AddTablePager $auditTable $history
$hl.Add_DoubleClick({ if ($hl.SelectedItems.Count) { [void](Preview 'Audit entry' @((ConvertFrom-Json $hl.SelectedItems[0].Tag.Details | ConvertTo-Json -Depth 10)) $null) } })

$rulesBox = [Windows.Forms.TextBox]::new(); $rulesBox.Multiline = $true; $rulesBox.ScrollBars = 'Both'
$rulesBox.WordWrap = $false; $rulesBox.Dock = 'Fill'; $settings.Controls.Add($rulesBox)
$sb = Bar $settings
Button $sb 'Save exclusions' { SaveRules } -Primary
Button $sb 'Open log folder' { Start-Process explorer.exe -ArgumentList ('"{0}"' -f $LogDirectory) }
Label $sb 'One rule per line (KB5061234, update GUID, or Title:*Preview*).'
if (Test-Path -LiteralPath $fileRules) { $rulesBox.Lines = [IO.File]::ReadAllLines($fileRules) }
$script:dirty = $false
$rulesBox.Add_TextChanged({ $script:dirty = $true; Clear-UpdateList })
function SaveRules {
    try {
        $lines = @($rulesBox.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
        foreach ($line in $lines) {
            if ($line -match '^KB\d+$|^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$') { continue }
            if ($line -match '^(?:Title|Titel):\s*(\S.*)$') {
                [void]([Management.Automation.WildcardPattern]::new($Matches[1],'IgnoreCase')).IsMatch('')
                continue
            }
            throw "Invalid rule: $line"
        }
    } catch { Notice $_.Exception.Message; return }
    StartWork 'Save exclusions' $lines
}
function ShowLogSettings {
    $dialog=[Windows.Forms.Form]::new()
    $dialog.Icon=$appIcon; $dialog.Text='Audit log location'; $dialog.StartPosition='CenterParent'
    $dialog.ClientSize=[Drawing.Size]::new(640,165); $dialog.FormBorderStyle='FixedDialog'
    $dialog.MaximizeBox=$false; $dialog.MinimizeBox=$false; $dialog.Font=$form.Font
    $panel=Bar $dialog
    $useCustom=[Windows.Forms.CheckBox]::new()
    $useCustom.Text='Use a custom or shared folder'; $useCustom.AutoSize=$true
    $useCustom.Checked=$LogDirectory -ne $folder; $panel.Controls.Add($useCustom)
    $panel.SetFlowBreak($useCustom,$true)
    $pathBox=[Windows.Forms.TextBox]::new()
    $pathBox.Width=595; $pathBox.Text=$LogDirectory; $pathBox.Enabled=$useCustom.Checked
    $pathBox.AccessibleName='Audit log folder'; $panel.Controls.Add($pathBox)
    $panel.SetFlowBreak($pathBox,$true)
    Label $panel 'Enter a local folder or a UNC share such as \\server\share\WSUS.'
    $useCustom.Add_CheckedChanged({ $pathBox.Enabled=$useCustom.Checked })
    $footer=Bar $dialog; $footer.Dock='Bottom'
    $save=Button $footer 'Save log location' { $dialog.DialogResult='OK' } -Primary -PassThru
    $cancel=Button $footer 'Cancel' { $dialog.DialogResult='Cancel' } -PassThru
    $dialog.AcceptButton=$save; $dialog.CancelButton=$cancel
    try {
        if ($dialog.ShowDialog($form) -ne 'OK') { return }
        $path=if ($useCustom.Checked) { $pathBox.Text.Trim() } else { $folder }
    } finally { $dialog.Dispose() }
    StartWork 'Log location' @() '' @{Path=$path}
}
function OpenEventQuery($rows) {
    if (!$rows.Count) { return }
    $dialog=[Windows.Forms.Form]::new()
    $dialog.Icon=$appIcon; $dialog.Text='Windows Update events'; $dialog.StartPosition='CenterParent'
    $dialog.ClientSize=[Drawing.Size]::new(480,145); $dialog.FormBorderStyle='FixedDialog'
    $dialog.MaximizeBox=$false; $dialog.MinimizeBox=$false; $dialog.Font=$form.Font
    $panel=Bar $dialog
    Label $panel "Read up to 100 events per computer ($($rows.Count) selected)."
    $panel.SetFlowBreak($panel.Controls[0],$true)
    Label $panel 'Hours to look back'
    $hours=[Windows.Forms.NumericUpDown]::new()
    $hours.Minimum=1; $hours.Maximum=168; $hours.Value=24; $hours.Width=66
    $panel.Controls.Add($hours)
    $errorsOnly=[Windows.Forms.CheckBox]::new()
    $errorsOnly.Text='Warnings and errors only'; $errorsOnly.AutoSize=$true
    $errorsOnly.Margin=$supersededFilter.Margin; $panel.Controls.Add($errorsOnly)
    $footer=Bar $dialog; $footer.Dock='Bottom'
    $read=Button $footer 'Read events' { $dialog.DialogResult='OK' } -Primary -PassThru
    $cancel=Button $footer 'Cancel' { $dialog.DialogResult='Cancel' } -PassThru
    $dialog.AcceptButton=$read; $dialog.CancelButton=$cancel
    try {
        if ($dialog.ShowDialog($form) -ne 'OK') { return }
        $options=@{Hours=[int]$hours.Value; ErrorsOnly=$errorsOnly.Checked}
    } finally { $dialog.Dispose() }
    StartWork 'Windows Update events' $rows '' $options
}
function ShowEventResults($results,$hours) {
    $dialog=[Windows.Forms.Form]::new()
    $dialog.Icon=$appIcon; $dialog.Text="Windows Update events - last $hours hours"
    $dialog.StartPosition='CenterParent'; $dialog.Size=[Drawing.Size]::new(980,600); $dialog.Font=$form.Font
    $dialog.MinimumSize=[Drawing.Size]::new(730,440)
    $split=[Windows.Forms.SplitContainer]::new()
    $split.Orientation='Horizontal'; $split.Dock='Fill'; $split.Size=[Drawing.Size]::new(930,510); $split.SplitterDistance=167
    $dialog.Controls.Add($split)
    $list=ListView $split.Panel1 @('Computer','Result','Events','Details') @(245,95,68,500)
    $list.CheckBoxes=$false; $list.MultiSelect=$false
    $detail=[Windows.Forms.TextBox]::new()
    $detail.Multiline=$true; $detail.ReadOnly=$true; $detail.ScrollBars='Vertical'; $detail.Dock='Fill'
    $split.Panel2.Controls.Add($detail)
    $list.Add_SelectedIndexChanged({
        if (!$list.SelectedItems.Count) { $detail.Clear(); return }
        $selectedResult=$list.SelectedItems[0].Tag
        if ($selectedResult.Status -ne 'OK') { $detail.Text=$selectedResult.Message; return }
        if (!$selectedResult.Events.Count) { $detail.Text='No matching Windows Update events were found.'; return }
        $lines=foreach ($event in $selectedResult.Events) {
            $time=([datetimeoffset]$event.Utc).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
            "$time | Event $($event.Id) | $($event.Level)"
            [string]$event.Message
            ''
        }
        $detail.Lines=[string[]]$lines
        $detail.SelectionStart=0
    })
    $eventBar=Bar $split.Panel1
    $eventTable=NewTableFilter $list $eventBar { param($view) ShowLocalTable $view }
    $eventTable.Rows=@(
        foreach ($entry in $results) {
            TableRow $entry @($entry.Target,$entry.Status,$entry.Events.Count,$entry.Message)
        }
    )
    ShowLocalTable $eventTable
    $footer=Bar $dialog; $footer.Dock='Bottom'
    $close=Button $footer 'Close' { $dialog.DialogResult='OK' } -PassThru
    $dialog.CancelButton=$close
    $dialog.Add_Shown({ if ($list.Items.Count) { $list.Items[0].Selected=$true } })
    try { [void]$dialog.ShowDialog($form) } finally { $dialog.Dispose() }
}
$groupBox.Add_ItemCheck({
    param($sender,$e)
    $count=$sender.CheckedItems.Count
    if ($e.NewValue -eq 'Checked') { $count++ }
    if ($e.CurrentValue -eq 'Checked') { $count-- }
    $groupCount.Text="$count of $($sender.Items.Count) groups selected"
    Clear-UpdateList
    ClearClientTable
})
$days.Add_ValueChanged({ ClearClientTable })
$ul.Add_ItemCheck({ param($sender,$e)
    if ($sender.Items[$e.Index].Tag.Exclusion) { $e.NewValue = 'Unchecked' }
})
$ul.Add_ItemChecked({
    param($sender,$e)
    if ($script:renderingUpdatePage) { return }
    $row=$e.Item.Tag
    $key="$($row.GroupId)/$($row.Id)"
    if ($e.Item.Checked) { $checkedUpdates[$key]=$row } else { $checkedUpdates.Remove($key) }
    UpdateSelectionInfo
})
function UpdateClientActions {
    $checked=$clientTable.Checks.Count; $total=$clientTable.Matches.Count
    $hasChecked=$checked -gt 0 -and !$clientTable.Pending
    $scanButton.Enabled=$hasChecked; $removeButton.Enabled=$hasChecked
    $onlineButton.Enabled=$hasChecked; $preflightButton.Enabled=$hasChecked; $clientEventsButton.Enabled=$hasChecked
    $selectAllClients.Enabled=$total -gt 0
    $selectAllClients.CheckState=if (!$hasChecked) { 'Unchecked' } elseif ($checked -eq $total) { 'Checked' } else { 'Indeterminate' }
}
function ShowClientTable {
    $script:checkingClients=$true
    try { ShowLocalTable $clientTable 'Id' } finally { $script:checkingClients=$false }
    UpdateClientActions
}
function ClearClientTable {
    $clientTable.Rows=@(); $clientTable.Page=0; $clientTable.Checks.Clear()
    ShowClientTable
}
$cl.Add_ItemChecked({ param($sender,$e)
    if ($script:checkingClients -or !$e.Item.Tag) { return }
    $id=[string]$e.Item.Tag.Id
    if ($e.Item.Checked) { $clientTable.Checks[$id]=$e.Item.Tag } else { $clientTable.Checks.Remove($id) }
    UpdateClientActions
})
function UpdateTrackingActions {
    $retryButton.Enabled=$false; $verifyButton.Enabled=$false; $restoreButton.Enabled=$false
    foreach ($row in (CheckedRows $wl)) {
        if ($row.Retry) { $retryButton.Enabled=$true }
        if ($row.Verify) { $verifyButton.Enabled=$true }
        if ($row.Missing.Count) { $restoreButton.Enabled=$true }
    }
    $caseEventsButton.Enabled=$wl.CheckedItems.Count -gt 0 -or $wl.SelectedItems.Count -gt 0
    $caseSourcesButton.Enabled=$caseEventsButton.Enabled
}
function ShowTrackingTable {
    $script:renderingTracking=$true
    try { ShowLocalTable $trackingTable 'Key' } finally { $script:renderingTracking=$false }
    UpdateTrackingActions
    $timelineButton.Enabled=$wl.SelectedItems.Count -gt 0
}
$wl.Add_ItemChecked({ if (!$script:renderingTracking) { UpdateTrackingActions } })
$wl.Add_SelectedIndexChanged({
    if ($script:renderingTracking) { return }
    $timelineButton.Enabled=$wl.SelectedItems.Count -gt 0
    $caseEventsButton.Enabled=$wl.CheckedItems.Count -gt 0 -or $wl.SelectedItems.Count -gt 0
    $caseSourcesButton.Enabled=$caseEventsButton.Enabled
})
$wl.Add_DoubleClick({ ShowSelectedTimeline })
function ShowSelectedTimeline {
    if (!$wl.SelectedItems.Count) { return }
    $r=$wl.SelectedItems[0].Tag
    $lines=@($r.Name,"Status: $($r.Stage)","Original WSUS ID: $($r.OriginalId)","Current WSUS ID: $($r.CurrentId)",
        "Configured before removal: $($r.ExpectedGroups -join '; ')",
        "Reported to WSUS: $($r.RequestedGroups -join '; ')",
        "Assigned in WSUS: $($r.ActualGroups -join '; ')",$r.Comparison,'')
    $events=@($r.Timeline | Where-Object { $_ } | Sort-Object Utc)
    if ($events.Count) {
        $lines+=@($events | ForEach-Object {
            $time=([datetimeoffset]$_.Utc).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
            "$time | $($_.Stage) | $($_.Message)"
        })
    } else { $lines+=@('No timeline events recorded.',[string]$r.ScanResult) }
    [void](Preview 'Re-registration timeline' $lines $null)
}

function ApproveSelection {
    $rows=@($checkedUpdates.Values | Sort-Object Depth -Descending)
    if (!$rows.Count) { Notice 'Load updates and select the rows you want to approve.'; return }
    $dialog=[Windows.Forms.Form]::new()
    $dialog.Icon=$appIcon
    $dialog.Text='Installation deadlines by target group'
    $dialog.Size=[Drawing.Size]::new(910,480); $dialog.StartPosition='CenterParent'
    $content=[Windows.Forms.FlowLayoutPanel]::new()
    $content.Dock='Fill'; $content.AutoScroll=$true; $content.FlowDirection='TopDown'; $content.WrapContents=$false
    $dialog.Controls.Add($content)
    $choices=@{}
    foreach ($group in ($rows | Group-Object GroupId | Sort-Object { $_.Group[0].Group })) {
        $panel=[Windows.Forms.FlowLayoutPanel]::new()
        $panel.Size=[Drawing.Size]::new(840,38); $panel.WrapContents=$false
        $name=[Windows.Forms.Label]::new()
        $name.Text="$($group.Group[0].Group) ($($group.Count) updates)"; $name.Width=405
        $name.AutoEllipsis=$true; $name.TextAlign='MiddleLeft'
        $choice=[Windows.Forms.ComboBox]::new()
        $choice.DropDownStyle='DropDownList'; $choice.Width=185
        [void]$choice.Items.AddRange(@('Choose deadline action','Approve without deadline','Set deadline (local time)'))
        $choice.SelectedIndex=if ($group.Group | Where-Object Status -eq Install) { 0 } else { 1 }
        $picker=[Windows.Forms.DateTimePicker]::new()
        $picker.Format='Custom'; $picker.CustomFormat='yyyy-MM-dd HH:mm'; $picker.Width=160
        $picker.Value=(Get-Date).AddDays(7); $picker.Enabled=$false
        $choice.Tag=$picker
        $choice.Add_SelectedIndexChanged({ param($sender,$e) $sender.Tag.Enabled=$sender.SelectedIndex -eq 2 })
        $panel.Controls.AddRange(@($name,$choice,$picker)); $content.Controls.Add($panel)
        $choices[$group.Name]=@{Choice=$choice; Picker=$picker; Name=$group.Group[0].Group}
    }
    $footer=Bar $dialog 42; $footer.Dock='Bottom'
    $continue=[Windows.Forms.Button]::new(); $continue.Text='Review plan'; $continue.AutoSize=$true
    $cancel=[Windows.Forms.Button]::new(); $cancel.Text='Cancel'; $cancel.DialogResult='Cancel'
    $dialog.CancelButton=$cancel
    $footer.Controls.AddRange(@($continue,$cancel))
    $continue.Add_Click({
        try {
            $deadlines=@{}
            $zone=[TimeZoneInfo]::Local
            foreach ($id in $choices.Keys) {
                $entry=$choices[$id]
                if ($entry.Choice.SelectedIndex -eq 0) { throw "Choose a deadline action for $($entry.Name)." }
                if ($entry.Choice.SelectedIndex -eq 1) { continue }
                $value=$entry.Picker.Value
                $local=[datetime]::new($value.Year,$value.Month,$value.Day,$value.Hour,$value.Minute,0)
                if ($zone.IsAmbiguousTime($local) -or $zone.IsInvalidTime($local)) { throw "Select an unambiguous local time for $($entry.Name)." }
                $deadline=[TimeZoneInfo]::ConvertTimeToUtc($local,$zone)
                if ($deadline -le [datetime]::UtcNow) { throw "The deadline for $($entry.Name) must be in the future." }
                $deadlines[$id]=$deadline
            }
            $dialog.Tag=$deadlines; $dialog.DialogResult='OK'
        } catch { [void][Windows.Forms.MessageBox]::Show($dialog,$_.Exception.Message,'Check deadlines','OK','Information') }
    })
    try {
        if ($dialog.ShowDialog($form) -ne 'OK') { return }
        $deadlines=$dialog.Tag
        $plan=@($rows | Select-Object *,@{Name='DeadlineUtc'; Expression={$deadlines[[string]$_.GroupId]}})
    } finally { $dialog.Dispose() }
    StartWork 'Deployment scope' $plan
}
function RemoveSelection {
    $rows = @(CheckedRows $cl)
    if ($rows.Count) { StartWork 'ReAdd preview' $rows }
}
$script:active = $null
$retiringWork=[Collections.ArrayList]::new()
$timer = [Windows.Forms.Timer]::new(); $timer.Interval = 200
function UnlockWork {
    $script:active=$null
    $tabs.Enabled=$true; $workspace.Panel1.Enabled=$true
    $busyIndicator.Visible=$false; $cancelWorkButton.Available=$false
    UpdateClientActions
}
function ReceiveOnlineResults($work,[switch]$Finish) {
    $changed=@{}; $r=$null
    while ($work.Request.OnlineQueue.TryDequeue([ref]$r)) {
        $id=[string]$r.Id
        $onlineResults[$id]=$r; $changed[$id]=$r; $work.Received++
        if ($null -ne $work.OnlineSeen) { $work.OnlineSeen[$id]=$true }
    }
    if ($changed.Count) {
        $script:onlineGeneration++
        foreach ($list in $cl,$reportList) {
            $col=$list.Columns.IndexOfKey('Reachability')
            if ($col -lt 0) { continue }
            foreach ($item in $list.Items) {
                $result=$changed[[string]$item.Tag.Id]
                if ($result) {
                    if ($list -eq $cl) { $result=OnlineFor $item.Tag.Id $item.Tag.Name $item.Tag.IP }
                    elseif ($item.Tag.Next -eq 'PC') { $result=OnlineFor $item.Tag.Id $item.Tag.Cells[0] }
                    PaintOnline $item $col (OnlineLabel $result)
                }
            }
        }
        if ($script:reportQuery.Kind -eq 'PC') { UpdateReportControls }
    }
    $hint.Text="Online check: $($work.Received) of $($work.Request.Rows.Count)"
    if ($Finish) {
        $clientTable.Rows=@(foreach ($row in $clientTable.Rows) {
            $r=OnlineFor $row.Data.Id $row.Data.Name $row.Data.IP
            if (!$r -and $row.Cells[5] -eq 'Not checked') { $row; continue }
            $cells=$row.Cells.Clone(); $cells[5]=OnlineLabel $r
            TableRow $row.Data $cells "$($r.CheckedAt) | $($r.Finding)"
        })
        ShowClientTable
        if ($script:reportData -and (ReportComputerView)) { ShowReportData $script:reportData }
    }
}
function StopWork {
    $work=$script:active
    if (!$work -or !$work.Cancellable -or $work.Completing) { return }
    try {
        if ($work.Async.IsCompleted) {
            try { [void]$work.PS.EndInvoke($work.Async) } catch { Write-Verbose $_.Exception.Message }
            $work.PS.Dispose()
        } else {
            $work.Stop=$work.PS.BeginStop($null,$null)
            [void]$retiringWork.Add($work)
        }
    } catch {
        $hint.Text="Could not cancel $($work.Mode): $($_.Exception.Message)"
        return
    }
    $timer.Stop()
    if ($work.Mode -eq 'Online check') { ReceiveOnlineResults $work -Finish }
    if ($work.Mode -eq 'Reporting status') { $script:pendingReports=$false }
    UnlockWork
    $hint.Text="$($work.Mode): query canceled."
    if ($work.Stop -and !$work.Stop.IsCompleted) { $hint.Text+=' WSUS request is still finishing in the background.' }
}
function StartWork($mode,$rows=@(),$fingerprint='',$options=@{}) {
    if ($script:active) { return }
    $cancellable=$mode -in @('Groups','Updates','Clients','Audit log','Reporting status','Deployment scope','Online check','ReAdd check','ReAdd preview','Windows Update events','Scan sources')
    if ($cancellable -and $retiringWork.Count -ge 2) {
        $hint.Text='Two canceled requests are still finishing. Try again once one finishes.'
        return
    }
    if ($script:dirty -and $mode -in @('Updates','Approval','Deployment scope')) { Notice 'Save your exclusion changes first.'; return }
    $ids = @($groupBox.CheckedItems | ForEach-Object { $_.Id })
    if ($mode -in @('Updates','Clients','Approval','Remove','Remote scan','Deployment scope','ReAdd check','ReAdd preview') -and !$ids.Count) { Notice 'Select at least one group on the left.'; return }
    if ($mode -in @('Online check','ReAdd check','ReAdd preview','Windows Update events') -and !$rows.Count) { return }
    $request = @{Mode=$mode; Groups=$ids; Rows=$rows; Days=[int]$days.Value; Connect=$connect
        Folder=$folder; Directory=$LogDirectory; ClientUrl=[string]$ClientWsusUrl
        From=$from.Value.Date; Until=$until.Value.Date.AddDays(1); UserFilter=$userText.Text; Query=$queryText.Text
        Rules=$fileRules; Log=$fileLog; Fingerprint=$fingerprint; Operation=[guid]::NewGuid().ToString()
        Options=$options; Server=$script:auditServer; LogSettings=$logSettingsPath
        LogName=$fileLogName; LocalLog=$localFileLog; AuditState=@{Error=''}
        Scan=$scanBlock.ToString(); ReportCutoff=[datetime]::UtcNow.AddDays(-[int]$days.Value)
        GraceMinutes=$ReportGraceMinutes; IncludeApproved=$includeApproved.Checked}
    if ($mode -eq 'Online check') { $request.OnlineQueue=[Collections.Concurrent.ConcurrentQueue[object]]::new() }
    $ps = [powershell]::Create()
    try {
        $auditDefinition = "function Write-Audit {`n" + ${function:Write-Audit}.ToString() + "`n}"
        [void]$ps.AddScript($auditDefinition).AddStatement()
        [void]$ps.AddScript($invokeWorker.ToString()).AddArgument($worker.ToString()).AddArgument($request)
        $async = $ps.BeginInvoke()
        $script:active = @{PS=$ps; Async=$async; Mode=$mode; Operation=$request.Operation; Request=$request; Cancellable=$cancellable; Received=0}
        if ($mode -eq 'Online check') { $script:active.OnlineSeen=@{} }
        $tabs.Enabled = $mode -in @('Groups','Online check'); $workspace.Panel1.Enabled=$false
        $busyIndicator.Visible=$true
        $cancelWorkButton.Available=$cancellable
        $hint.Text = "$mode in progress ..."; $timer.Start()
    } catch { $ps.Dispose(); Notice $_.Exception.Message }
}
$timer.Add_Tick({
    $work = $script:active
    if (!$work) { return }
    if (!$work.Async.IsCompleted) {
        if ($work.Mode -eq 'Online check') { ReceiveOnlineResults $work }
        if ($work.Mode -in @('Updates','Windows Update events')) {
            $progress=$work.PS.Streams.Progress
            if ($progress.Count) { $hint.Text="$($work.Mode): $($progress[$progress.Count-1].StatusDescription)" }
        }
        return
    }
    $timer.Stop()
    $work.Completing=$true
    $cancelWorkButton.Available=$false
    $next=$null; $nextRows=@()
    try {
        $result = @($work.PS.EndInvoke($work.Async))
        switch ($work.Mode) {
            'Log location' {
                if ($result.Count -ne 1) { throw 'The new audit log location could not be saved.' }
                $script:LogDirectory=$result[0].Directory
                $script:fileLog=$result[0].Log
                $auditTable.Rows=@()
                ShowLocalTable $auditTable
            }
            'Save exclusions' {
                $script:dirty=$false
                Clear-UpdateList
            }
            'Windows Update events' {
                ShowEventResults $result $work.Request.Options.Hours
            }
            'Scan sources' {
                $lines=@(foreach ($r in $result) { "$($r.Name) | $($r.Status)"; $r.Details; '' })
                [void](Preview 'Configured update sources' $lines $null)
            }
            'Audit log' {
                $auditTable.Page=0
                $auditTable.Rows=@(
                    foreach ($r in ($result | Sort-Object Time -Descending)) {
                        if ($r.Warning) { Notice $r.Warning; continue }
                        TableRow $r @($r.Time,$r.User,$r.Server,$r.Action,$r.Result,$r.Details)
                    }
                )
                ShowLocalTable $auditTable
            }
            'Reporting status' {
                $script:pendingReports = @($result | Where-Object Pending).Count -gt 0
                $trackingTable.Rows=@(
                    foreach ($r in ($result | Sort-Object Start -Descending)) {
                        TableRow $r @($r.Name,$r.Start,$r.Stage,$r.ScanResult,$r.Contact,$r.ReportTime,$r.Comparison)
                    }
                )
                ShowTrackingTable
            }
            { $_ -in @('ReAdd check','ReAdd preview') } {
                $lines=@(@($banner.Text,'') + @($result | ForEach-Object { "$($_.Target) | $($_.Status) | $($_.Message)" }))
                $eligible=@($result | Where-Object Status -eq 'OK' | ForEach-Object Plan)
                if ($work.Mode -eq 'ReAdd preview' -and $eligible.Count) {
                    $lines+=@('',"Continue with the $($eligible.Count) devices marked OK.",
                        'Removal deletes the old WSUS record, its history and all memberships.',
                        "Removal requires a successful scan and $ReportGraceMinutes minutes without a fresh report.",
                        'The manager saves the groups and starts a new scan after removal.')
                    if (Preview 'Re-registration preflight' $lines 'Continue with eligible devices') {
                        $next='Remove'; $nextRows=$eligible
                    }
                } else { [void](Preview 'Re-registration preflight' $lines $null) }
            }
            'Online check' { ReceiveOnlineResults $work -Finish }
            'Deployment scope' {
                $impact=$result[0]
                $req=$work.Request
                $lines=@($banner.Text,"Computers reporting a need in the listed groups: $($impact.Count)",
                    'Effective client deadlines follow WSUS rules for multiple memberships.',
                    '', 'Groups in scope, including inherited approvals:') + @($impact.Paths)
                $lines+=@('','Installation approvals by group and deadline:')
                $lines+=@($req.Rows | ForEach-Object {
                    $deadlineLabel=if ($_.DeadlineUtc) { $_.DeadlineUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm zzz') } else { 'No deadline' }
                    "$($_.Group) | $deadlineLabel | $($_.Title) | KB $($_.KB) | $($_.Id) Rev. $($_.Revision)"
                })
                $work.Fingerprint=$impact.Fingerprint
                if (Preview 'Approval preview' $lines 'Approve now') { $next='Approval' }
            }
            'Groups' {
                $checked=@{}
                foreach ($group in $groupBox.CheckedItems) { $checked[[string]$group.Id]=$true }
                $groupBox.Items.Clear(); Clear-UpdateList; ClearClientTable
                foreach ($row in $result) { [void]$groupBox.Items.Add($row,$checked.ContainsKey([string]$row.Id)) }
                $groupCount.Text="$($groupBox.CheckedItems.Count) of $($groupBox.Items.Count) groups selected"
                UpdateClientActions
                if ($result.Count) {
                    $script:auditServer=$result[0].Server
                    $banner.Text="$($result[0].Server)   |   $($result[0].Mode)-side targeting"
                }
            }
            'Updates' {
                if ($result.Count -ne 1) { throw 'Incomplete update result.' }
                $checkedUpdates.Clear()
                $script:updatePage=0
                $script:updateRows=$result[0].All
                $script:nonSupersededRows=$result[0].NonSuperseded
                Show-UpdateRows
            }
            'Clients' {
                $clientTable.Page=0; $clientTable.Checks.Clear()
                $clientTable.Rows=@(
                    foreach ($row in $result) {
                        $prior=$onlineResults[[string]$row.Id]
                        if ($prior -and ($prior.Name -ne $row.Name -or $prior.IP -ne $row.IP)) { $onlineResults.Remove([string]$row.Id); $prior=$null }
                        TableRow $row @($row.Name,$row.IP,$row.ReportTime,$row.Contact,$row.Groups,(OnlineLabel $prior),$row.Finding) "$($row.Name)`n$($row.Finding)`n$($row.Groups)"
                    }
                )
                ShowClientTable
            }
            default {
                Clear-UpdateList; ClearClientTable
                $success=@($result | Where-Object Status -eq 'OK').Count
                $deferred=@($result | Where-Object Status -eq 'Deferred').Count
                $lines = @("Successful: $success | Deferred: $deferred | Failed or partial: $($result.Count-$success-$deferred)", "Log: $fileLog", '')
                $lines += @($result | ForEach-Object { "$($_.Action) | $($_.Status) | $($_.Target) | $($_.Message)" })
                [void](Preview 'Result' $lines $null)
                if ($work.Mode -in @('Remove','Remote scan','Restore groups','Retry re-registration','Verify re-registration')) { $tabs.SelectedTab=$tracking; $next='Reporting status' }
            }
        }
        $hint.Text=switch ($work.Mode) {
            'Online check' { "Online check completed | $($work.Received) of $($work.Request.Rows.Count) computers" }
            'Log location' { "Audit log folder: $LogDirectory" }
            'Save exclusions' { 'Exclusions saved. Reload the updates.' }
            'Updates' { "$($script:updateRows.Count) update/group rows | $($result[0].Timings)" }
            default { "$($work.Mode): $($result.Count) entries" }
        }
        if ($work.Request.AuditState.Error) { $hint.Text+=' | Central log unavailable. Used the local log.' }
    } catch {
        if ($work.Mode -notin @('Reporting status','Audit log','Deployment scope','Online check','ReAdd check','ReAdd preview','Log location','Save exclusions','Windows Update events','Scan sources')) {
            Clear-UpdateList; ClearClientTable
        }
        $message = $_.Exception.GetBaseException().Message
        $hint.Text = "Error during $($work.Mode)"
        if ($work.Mode -eq 'Groups') { $banner.Text="Connection failed   |   $script:auditServer" }
        foreach ($warning in $work.PS.Streams.Warning) { $message+="`n$($warning.Message)" }
        if ($work.Mode -eq 'Online check') {
            ReceiveOnlineResults $work
            foreach ($r in $work.Request.Rows) {
                if (!$work.OnlineSeen.ContainsKey([string]$r.Id)) {
                    $work.Request.OnlineQueue.Enqueue([pscustomobject]@{Id=$r.Id;Name=$r.Name;IP=$r.IP;Finding=$message;
                        CheckedAt=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');IpResult='Unavailable';DnsResult='';DNS=''})
                }
            }
            ReceiveOnlineResults $work -Finish
            $hint.Text="Online check: $($work.Received) of $($work.Request.Rows.Count) | $message"
        } else { Notice $message }
    } finally {
        if ($work.Mode -in @('Approval','Remove','Restore groups','Remote scan','Retry re-registration')) {
            try { InvalidateReport } catch { $hint.Text+=" | Cache: $($_.Exception.Message)" }
        }
        $work.PS.Dispose()
        UnlockWork
    }
    if ($next -eq 'Approval') { StartWork $next $work.Request.Rows $work.Fingerprint }
    elseif ($next) { StartWork $next $nextRows }
})
$poll=[Windows.Forms.Timer]::new(); $poll.Interval=60000
$poll.Add_Tick({ if ($auto.Checked -and !$script:active -and $tabs.SelectedTab -eq $tracking -and $script:pendingReports) { StartWork 'Reporting status' } })
$poll.Start()
$form.Add_FormClosing({ param($sender,$e)
    if ($script:active) { StopWork }
    if ($script:active) {
        $e.Cancel=$true
        $hint.Text='An operation is still running. Close the window after it finishes.'
        return
    }
    if ($script:reportJob) { StopReportRead }
    if ($script:reportJob) { $e.Cancel=$true }
})
$form.KeyPreview=$true
$form.Add_KeyDown({
    param($sender,$e)
    if ($e.KeyCode -ne 'Escape') { return }
    if ($cancelWorkButton.Available) { $e.SuppressKeyPress=$true; StopWork }
    elseif ($tabs.SelectedTab -eq $dashboard -and $script:reportJob -and !$script:active) {
        $e.SuppressKeyPress=$true; StopReportRead
    }
})
function CacheHash([string]$value) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-','') }
    finally { $sha.Dispose() }
}
$serverKey=CacheHash ("en-1.1|{0}|{1}|{2}|{3}" -f $env:COMPUTERNAME,$connect.Name,$connect.PortNumber,$connect.UseSsl)
$reportDir=Join-Path $folder ("Dashboard/"+$serverKey)
[void][IO.Directory]::CreateDirectory($reportDir)
$marker=Join-Path $reportDir 'Aenderungen'
function CacheVersion {
    if ([IO.File]::Exists($marker)) { return [IO.File]::GetLastWriteTimeUtc($marker).Ticks.ToString() }
    '0'
}
function InvalidateReport {
    [IO.File]::WriteAllText($marker,[guid]::NewGuid().ToString())
    $script:reportNext=[datetime]::MinValue
}
function NewReportQuery($kind,$label,$text='',$id='',$group='',$filter='') {
    [ordered]@{Kind=$kind; Label=$label; Text=$text; Id=[string]$id; Group=[string]$group; Filter=$filter; Page=0}
}
$reportList=ListView $dashboard @('Metric','Count') @(360,100)
$reportList.CheckBoxes=$false
$reportList.MultiSelect=$false
$reportTitle=[Windows.Forms.Label]::new()
$reportTitle.Dock='Top'; $reportTitle.Height=38; $reportTitle.TextAlign='MiddleLeft'
$reportTitle.Padding=[Windows.Forms.Padding]::new(10,0,10,0); $reportTitle.AutoEllipsis=$true
$reportTitle.Font=[Drawing.Font]::new($form.Font.FontFamily,12,[Drawing.FontStyle]::Bold)
$overviewScroll=[Windows.Forms.Panel]::new()
$overviewScroll.Dock='Fill'; $overviewScroll.AutoScroll=$true; $overviewScroll.Padding=[Windows.Forms.Padding]::new(8)
if (!$highContrast) { $overviewScroll.BackColor=$palette.Surface }
$overviewCards=[Windows.Forms.TableLayoutPanel]::new()
$overviewCards.Dock='Top'; $overviewCards.AutoSize=$true; $overviewCards.AutoSizeMode='GrowAndShrink'
$overviewCards.ColumnCount=3
foreach ($column in 1..3) { [void]$overviewCards.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent',100.0/3)) }
$overviewScroll.Controls.Add($overviewCards); $dashboard.Controls.Add($overviewScroll)
$overviewScroll.Visible=$false
$dashboard.Controls.Add($reportTitle)
$reportBar=Bar $dashboard
$reportFooter=Bar $dashboard
$reportFooter.Dock='Bottom'
$reportNote=[Windows.Forms.Label]::new()
$reportNote.Dock='Bottom'; $reportNote.Height=27; $reportNote.AutoEllipsis=$true
$reportNote.Padding=[Windows.Forms.Padding]::new(10,0,10,0); $reportNote.TextAlign='MiddleLeft'
$dashboard.Controls.Add($reportNote)
$reportBack=[Collections.Stack]::new()
$script:reportQuery=NewReportQuery 'Server' 'Overview'
$script:reportJob=$null; $script:reportDirty=$false; $script:reportNext=[datetime]::MinValue
$script:reportData=$null; $script:reportPath=''
$indexes=@{}
$reportPages=@{}
$reportMetadata=@{}
$retiring=[Collections.ArrayList]::new()
$script:pausedPath=''
$script:reportSource=''
$script:reportSelectionKey=''
$reportChecked=@{}
$reportTargets=@{}
function ReportComputerView {
    $script:reportQuery.Kind -in @('Computer search','Computers with errors','Computers needing updates','Approved outstanding','Computer list','Deadlines','Overdue deadlines','Deadlines next 7 days','Restart pending')
}
function ReportCheckedCount { $reportChecked.Count }
function ReportRowChecked($id) { $reportChecked.ContainsKey([string]$id) }
function RefreshReportChecks {
    $script:refreshingReportChecks=$true
    try {
        foreach ($item in $reportList.Items) {
            if ($item.Tag.Next -eq 'PC') { $item.Checked=ReportRowChecked $item.Tag.Id }
        }
    } finally { $script:refreshingReportChecks=$false }
    UpdateReportControls
}
function GetReportComputerTargets {
    if ($script:reportQuery.Kind -eq 'PC' -and $script:reportQuery.Id) {
        [pscustomobject]@{Id=$script:reportQuery.Id;Name=$script:reportQuery.Label}
    } elseif (!$reportTable.Delay.Enabled -and !$reportTable.Pending) {
        if ($reportChecked.Count) { $reportChecked.Values }
        elseif ($reportList.SelectedItems.Count -and $reportList.SelectedItems[0].Tag.Next -eq 'PC') {
            $row=$reportList.SelectedItems[0].Tag
            [pscustomobject]@{Id=$row.Id;Name=$row.Cells[0]}
        }
    }
}
function ReportDisplayRows($data) {
    $slot=$indexes[$script:reportSelectionKey]
    $snapshot=if ($slot -and $slot.Snapshot.Stamp -eq $data.Stamp) { $slot.Snapshot }
    $source=if ($snapshot) { ,$snapshot.Entries } else { ,$data.Rows }
    if (![object]::ReferenceEquals($reportTable.Raw,$source) -or $reportTable.Generation -ne $script:onlineGeneration) {
        $reportTable.Projected=@(foreach ($r in $source) {
            $label=if ($r.Next -eq 'PC') { OnlineLabel (OnlineFor $r.Id $r.Cells[0]) } else { '' }
            [pscustomobject]@{Cells=($r.Cells+@($label));Id=$r.Id;Next=$r.Next;Group=$r.Group}
        })
        $reportTable.Raw=$source; $reportTable.Generation=$script:onlineGeneration
    }
    $matches=TableRows $reportTable $reportTable.Projected
    if (![object]::ReferenceEquals($reportTable.Indexed,$matches) -or $reportTable.HasSnapshot -ne [bool]$snapshot) {
        $reportTargets.Clear()
        if ($snapshot) {
            foreach ($r in $matches) {
                if ($r.Next -eq 'PC') { $reportTargets[[string]$r.Id]=[pscustomobject]@{Id=$r.Id;Name=$r.Cells[0]} }
            }
        }
        if (!$reportTable.Pending) {
            foreach ($id in @($reportChecked.Keys)) { if (!$reportTargets.ContainsKey($id)) { $reportChecked.Remove($id) } }
        }
        $reportTable.Indexed=$matches; $reportTable.HasSnapshot=[bool]$snapshot
    }
    TablePage $reportTable $matches
}
function ReportPagePath($key,$number) { Join-Path $reportDir ("$key-$number.json") }
function ReportPageIsFresh($data,$version,$now) {
    $data -and $data.Version -eq $version -and $data.Stamp -and
        ($now - [long]$data.Stamp) -lt [timespan]::FromMinutes($CacheMinutes).Ticks
}
function UpdateReportControls {
    $reportBackButton.Enabled=$reportBack.Count -gt 0
    $reportCancelButton.Enabled=$null -ne $script:reportJob
    $data=$script:reportData
    $reportPrevButton.Enabled=$script:reportQuery.Page -gt 0
    $reportNextButton.Enabled=$data -and (($script:reportQuery.Page+1)*100 -lt $data.Total)
    $reportPageLabel.Text=if ($data) {
        "Page $($data.Page+1) of $([Math]::Max(1,[Math]::Ceiling($data.Total/100.0)))"
    } else { 'Page -' }
    if (ReportComputerView) {
        $totalMatches=$reportTable.Matches.Count
        $reportPrevButton.Enabled=$reportTable.Page -gt 0
        $reportNextButton.Enabled=$reportTable.HasSnapshot -and ($reportTable.Page+1)*100 -lt $totalMatches
        $reportPageLabel.Text="Page $($reportTable.Page+1) of $([Math]::Max(1,[Math]::Ceiling($totalMatches/100.0)))"
    }
    $reportDetailsButton.Enabled=$reportList.SelectedItems.Count -gt 0 -and [bool]$reportList.SelectedItems[0].Tag.Next
    $selectedCount=ReportCheckedCount
    $computerView=ReportComputerView
    $total=$reportTargets.Count
    $reportTable.Box.Visible=$script:reportQuery.Kind -ne 'Server'
    $reportTable.Caption.Visible=$reportTable.Box.Visible
    $reportSelectAll.Text=if ($reportTable.Filter) { 'Select all matching computers' } else { 'Select all computers' }
    $reportSelectAll.Visible=$computerView
    $reportSelectAll.Enabled=$computerView -and $reportList.CheckBoxes -and $total -gt 0
    $reportSelectAll.CheckState=if (!$selectedCount) { 'Unchecked' } elseif ($selectedCount -eq $total) { 'Checked' } else { 'Indeterminate' }
    $reportSelectionLabel.Visible=$computerView
    $reportSelectionLabel.Text="$selectedCount selected"
    $hasTarget=($script:reportQuery.Kind -eq 'PC' -and [bool]$script:reportQuery.Id) -or $selectedCount -gt 0 -or
        ($reportList.SelectedItems.Count -gt 0 -and $reportList.SelectedItems[0].Tag.Next -eq 'PC')
    $reportOnlineButton.Enabled=$hasTarget; $reportEventsButton.Enabled=$hasTarget
    $reportOnlineStatus.Visible=$script:reportQuery.Kind -eq 'PC'
    if ($reportOnlineStatus.Visible) {
        $info=OnlineFor $script:reportQuery.Id $script:reportQuery.Label; $label=OnlineLabel $info
        $reportOnlineStatus.Text="$([char]0x25CF)  $label"; $reportOnlineStatus.Enabled=[bool]$info
        $reportOnlineStatus.LinkColor=if ($label -eq 'Reachable') { [Drawing.Color]::ForestGreen } else { [Drawing.Color]::Firebrick }
    }
}
function StopReportRead {
    $j=$script:reportJob
    if (!$j) { return }
    try {
        $j.Stop=$j.PS.BeginStop($null,$null)
        [void]$retiring.Add($j)
        $script:reportJob=$null; $script:reportDirty=$false; $script:reportForce=$false
        $script:pausedPath=$script:reportPath
        $reportNote.Text='Dashboard query canceled. Run a new search or click Refresh to try again.'
        UpdateReportControls
    } catch { $reportNote.Text="Cancellation failed: $($_.Exception.Message)" }
}
function ShowOverviewCards($rows,$snapshot) {
    $shortLabels=@{
        'Computers with no applicable updates outstanding'='Up-to-date computers'
        'Computers needing at least one update'='Computers needing updates'
    }
    $overviewCards.SuspendLayout()
    try {
        while ($overviewCards.Controls.Count) { $overviewCards.Controls[0].Dispose() }
        $overviewCards.RowStyles.Clear()
        $overviewCards.RowCount=[int][Math]::Ceiling($rows.Count/3.0)
        for ($i=0; $i -lt $overviewCards.RowCount; $i++) {
            $height=84
            for ($index=$i*3; $index -lt [Math]::Min(($i+1)*3,$rows.Count); $index++) {
                if ($rows[$index].Next) { $height=102; break }
            }
            [void]$overviewCards.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute',$height))
        }
        for ($index=0; $index -lt $rows.Count; $index++) {
            $r=$rows[$index]
            $card=[Windows.Forms.Panel]::new()
            $card.Dock='Fill'; $card.Margin=[Windows.Forms.Padding]::new(5)
            $card.Padding=[Windows.Forms.Padding]::new(12,6,12,6)
            $card.BackColor=[Drawing.SystemColors]::Window
            $card.ForeColor=[Drawing.SystemColors]::WindowText
            $metric=[Windows.Forms.Label]::new()
            $fullLabel=[string]$r.Cells[0]
            $metric.Text=if ($shortLabels.ContainsKey($fullLabel)) { $shortLabels[$fullLabel] } else { $fullLabel }
            $metric.AccessibleName=$fullLabel; $metric.AutoEllipsis=$true; $metric.Dock='Top'
            $metric.Height=if ($r.Next) { 21 } else { 29 }
            $metric.UseMnemonic=$false
            $value=[Windows.Forms.Label]::new()
            $value.Text=if ($r.Cells[1] -is [string]) { $r.Cells[1] } else { '{0:N0}' -f [long]$r.Cells[1] }
            $value.AutoEllipsis=$true
            $value.Font=$overviewValueFont; $value.Dock='Top'
            $value.Height=if ($r.Next) { 28 } else { 31 }
            if ($r.Next) {
                $caption=if ($r.Next -eq 'Unknown target groups') { 'View requested names' } else { 'View affected computers' }
                $details=Button $card $caption { param($sender,$e) OpenReportRow $sender.Tag } -PassThru
                $details.Enabled=$null -ne $snapshot.Related -and $snapshot.Related.ContainsKey($r.Next)
                $details.Tag=$r; $details.Dock='Bottom'; $details.TextAlign='MiddleLeft'
            }
            $card.Controls.Add($value); $card.Controls.Add($metric)
            $overviewCards.Controls.Add($card,($index % 3),[int][Math]::Floor($index/3.0))
        }
    } finally { $overviewCards.ResumeLayout() }
}
$overviewValueFont=[Drawing.Font]::new($form.Font.FontFamily,18,[Drawing.FontStyle]::Bold)
function ShowReportData($data) {
    $overview=$script:reportQuery.Kind -eq 'Server'
    $overviewScroll.Visible=$overview
    $reportList.Visible=!$overview
    $reportFooter.Visible=!$overview
    if ($overview) {
        $parentSnapshot=$indexes[$script:reportSelectionKey].Snapshot
        if ($parentSnapshot.Stamp -ne $data.Stamp) { $parentSnapshot=$null }
        ShowOverviewCards $data.Rows $parentSnapshot
    } else {
        $selection=if ($reportList.SelectedItems.Count) { $reportList.SelectedItems[0].Tag }
        $reportList.BeginUpdate()
        $script:refreshingReportChecks=$true
        try {
            $reportList.Items.Clear(); $reportList.Columns.Clear()
            $reportList.CheckBoxes=(ReportComputerView) -and [bool]$indexes[$script:reportSelectionKey].Snapshot.ComputerIds.Count
            for ($index=0; $index -lt $data.Columns.Count; $index++) {
                $col=[string]$data.Columns[$index]
                $width=if ($index -eq 0) { 265 }
                    else { [Math]::Max(104,[Windows.Forms.TextRenderer]::MeasureText($col,$reportList.Font).Width+22) }
                $headerColumn=$reportList.Columns.Add($col,$width)
                if ($col -in @('Count','Installed','Restart pending','Outstanding','Not downloaded','Downloaded','Missing','Failed','Error','Unknown','Not applicable')) {
                    $headerColumn.TextAlign='Right'
                }
            }
            if (ReportComputerView) {
                $statusColumn=$reportList.Columns.Add('Reachability','Online status',138)
                $statusColumn.DisplayIndex=1
                $reportTable.Label='Filter all results'
                $visibleRows=@(ReportDisplayRows $data)
                $reportList.CheckBoxes=$reportTable.HasSnapshot -and $reportTargets.Count -gt 0
            } else { $reportTable.Label='Filter this page'; $visibleRows=TableRows $reportTable $data.Rows }
            foreach ($r in $visibleRows) {
                $item=AddRow $reportList $r $r.Cells
                if ($statusColumn -and $r.Next -eq 'PC') { PaintOnline $item $statusColumn.Index $r.Cells[-1] }
                if ($reportList.CheckBoxes -and $r.Next -eq 'PC') { $item.Checked=ReportRowChecked $r.Id }
                if ($r.Next) { $item.ToolTipText="$($r.Cells[0])`nDouble-click or press Enter for details." }
                if ($selection -and $r.Id -eq $selection.Id -and $r.Group -eq $selection.Group -and $r.Cells[0] -eq $selection.Cells[0]) {
                    $item.Selected=$true
                }
            }
        } finally { $reportList.EndUpdate(); $script:refreshingReportChecks=$false }
        UpdateTableHeaders $reportTable
    }
    $stamp=[datetime]::new([long]$data.Stamp,[DateTimeKind]::Utc).ToLocalTime()
    $reportTitle.Text=$data.Title
    $reportNote.Text=if ($overview) { 'As of {0:yyyy-MM-dd HH:mm:ss}' -f $stamp }
        elseif ($data.Total) { '{0} results | As of {1:yyyy-MM-dd HH:mm:ss}' -f $data.Total,$stamp }
        else { 'No results | As of {0:yyyy-MM-dd HH:mm:ss}' -f $stamp }
    if ($script:reportSource) { $reportNote.Text+=" | $script:reportSource" }
    if ((ReportComputerView) -and $reportTable.Filter) {
        $reportNote.Text+=" | $($reportTable.Matches.Count) matching rows"
    } elseif (!$overview -and $reportTable.Filter) {
        $reportNote.Text+=" | $($reportList.Items.Count) of $($data.Rows.Count) rows on this page"
    }
    UpdateReportControls
}
function ReadReport([bool]$force=$false) {
    $q=$script:reportQuery
    $key=CacheHash (ConvertTo-Json @($q.Kind,$q.Text,$q.Id,$q.Group,$q.Filter) -Compress)
    if ($script:reportSelectionKey -ne $key) {
        $script:reportSelectionKey=$key
        $reportChecked.Clear(); $reportTargets.Clear()
        $reportTable.Page=0; $reportTable.Matches=@(); $reportTable.HasSnapshot=$false; $reportTable.Indexed=$null
        $reportTable.Box.Clear()
        $reportTable.Delay.Stop()
        $reportTable.Column=-1; $reportTable.Descending=$false
        $reportTable.Filter=''; $reportTable.FilterChanged=$false; $reportTable.Source=$null
    }
    $path=ReportPagePath $key $q.Page
    if ($force -or $script:pausedPath -ne $path) { $script:pausedPath='' }
    if ($script:pausedPath) { return }
    $version=CacheVersion
    $now=[datetime]::UtcNow.Ticks
    $seed=$q.Seed
    if ($seed -and ($force -or $seed.Version -ne $version)) { $seed=$null; $q.Remove('Seed') }
    if ($seed) { $indexes[$key]=$seed }
    if ($script:reportPath -ne $path) {
        $script:reportPath=$path; $script:reportData=$null
        $reportList.Items.Clear(); $reportList.Columns.Clear()
        $overviewScroll.Visible=$false; $reportList.Visible=$true
        $reportFooter.Visible=$q.Kind -ne 'Server'
        $reportTitle.Text=$q.Label
        $reportNote.Text='Loading data ...'
        try {
            $saved=$null
            if ($reportPages.ContainsKey($path)) {
                $reportPages[$path].Used=$now
                $saved=$reportPages[$path].Data
            } elseif ([IO.File]::Exists($path)) {
                $saved=ConvertFrom-Json ([IO.File]::ReadAllText($path))
            }
            if ($saved -and (!$seed -or $saved.Stamp -eq $seed.Snapshot.Stamp)) {
                if (!$saved.Stamp -or !$saved.Columns.Count) { throw 'Invalid cache format' }
                $script:reportSource=if (ReportPageIsFresh $saved $version $now) { 'Page cache' } else { 'Stale page cache' }
                $script:reportData=$saved
                ShowReportData $saved
            }
        } catch { $script:reportData=$null; $reportList.Items.Clear() }
    }
    UpdateReportControls
    $data=$script:reportData
    $slot=$indexes[$key]
    $fresh=$slot -and $slot.Version -eq $version -and
        ($now - [long]$slot.Snapshot.Stamp) -lt [timespan]::FromMinutes($CacheMinutes).Ticks
    if ($seed) { $fresh=$true }
    if ($fresh) { $slot.Used=$now }
    if (!$force -and (ReportPageIsFresh $data $version $now) -and
        (!$fresh -or $data.Stamp -eq $slot.Snapshot.Stamp) -and
        (!(ReportComputerView) -or ($fresh -and $data.Stamp -eq $slot.Snapshot.Stamp)) -and
        ($q.Kind -ne 'Server' -or ($fresh -and $slot.Snapshot.Related -and $data.Stamp -eq $slot.Snapshot.Stamp))) {
        if ($seed) { $q.Remove('Seed') }
        return
    }
    if ($retiring.Count -ge 2) {
        $reportNote.Text='Canceled WSUS requests are finishing. The selected view will load afterward.'
        $script:reportNext=[datetime]::MinValue
        return
    }
    if ($script:reportJob) {
        if ($force) { $script:reportForce=$true; $script:reportDirty=$true }
        if ($script:reportJob.Path -ne $path -or $script:reportJob.Version -ne $version) { $script:reportDirty=$true }
        return
    }
    if ($data) { $reportNote.Text=($reportNote.Text -replace ' \| Refreshing \.\.\.$','')+' | Refreshing ...' }
    else { $reportNote.Text='Loading data ...' }
    $ps=[powershell]::Create()
    try {
        $copy=@{}; foreach ($k in $q.Keys) { if ($k -ne 'Seed') { $copy[$k]=$q[$k] } }
        if ($q.Kind -eq 'Server') { $copy.PreviewQueue=[Collections.Concurrent.ConcurrentQueue[object]]::new() }
        $copy.CacheTicks=[timespan]::FromMinutes($CacheMinutes).Ticks
        $snapshot=if ($fresh -and !$force) { $slot.Snapshot }
        $metadata=if (!$force -and $q.Kind -eq 'PC') { $reportMetadata.Clone() }
        [void]$ps.AddScript($reportWorker.ToString()).AddArgument($connect).AddArgument($copy).AddArgument($snapshot).AddArgument($metadata)
        $script:reportJob=@{PS=$ps; Async=$ps.BeginInvoke(); Path=$path; Version=$version; Key=$key; PreviewQueue=$copy.PreviewQueue}
        if ($seed) { $q.Remove('Seed') }
        UpdateReportControls
    } catch { $ps.Dispose(); $reportNote.Text+=' | '+$_.Exception.Message }
}
function OpenReport($q) {
    $script:pausedPath=''
    $reportBack.Push($script:reportQuery)
    $script:reportQuery=$q
    ReadReport
}
function SearchReport {
    $term=$dashboardSearch.Text.Trim()
    if ($term.Length -lt 2) { Notice 'Enter at least two characters.'; return }
    $kind=if ($reportSearchMode.SelectedIndex -eq 1) { 'Computer search' } else { 'Update search' }
    OpenReport (NewReportQuery $kind "$kind - $term" $term)
}
Button $reportBar 'Overview' { $reportBack.Clear(); $script:reportQuery=NewReportQuery 'Server' 'Overview'; ReadReport }
$reportBackButton=Button $reportBar 'Back' { if ($reportBack.Count) { $script:reportQuery=$reportBack.Pop(); ReadReport } } -PassThru
$reportSearchMode=[Windows.Forms.ComboBox]::new()
$reportSearchMode.DropDownStyle='DropDownList'; $reportSearchMode.Width=130; $reportSearchMode.AccessibleName='Search type'
$reportSearchMode.Items.AddRange(@('KB or title','Computer name')); $reportSearchMode.SelectedIndex=0
$reportBar.Controls.Add($reportSearchMode)
$dashboardSearch=[Windows.Forms.TextBox]::new(); $dashboardSearch.Width=184; $dashboardSearch.MaxLength=255
$dashboardSearch.AccessibleName='Dashboard search'; $reportBar.Controls.Add($dashboardSearch)
$dashboardSearch.Add_KeyDown({ param($sender,$e) if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress=$true; SearchReport } })
Button $reportBar 'Search' { SearchReport } -Primary
$deadlineMode=[Windows.Forms.ComboBox]::new()
$deadlineMode.DropDownStyle='DropDownList'; $deadlineMode.Width=153; $deadlineMode.AccessibleName='Deadline report'
$deadlineMode.Items.AddRange(@('Deadlines','Overdue deadlines','Deadlines next 7 days','Restart pending')); $deadlineMode.SelectedIndex=0
$reportBar.Controls.Add($deadlineMode)
Button $reportBar 'View deadlines' { $kind=[string]$deadlineMode.SelectedItem; OpenReport (NewReportQuery $kind $kind) }
Button $reportBar 'Refresh' { ReadReport $true }
$reportCancelButton=Button $reportBar 'Cancel query' { StopReportRead } -PassThru
$reportTable=NewTableFilter $reportList $reportBar {
    param($view)
    if ($view.FilterChanged) {
        $reportChecked.Clear()
    }
    if ($script:reportData) { ShowReportData $script:reportData }
} 'Filter this page'
$reportTable.PageSize=100; $reportTable.Page=0
EnableOnlineDetails $reportList
$reportPrevButton=Button $reportFooter 'Previous' {
    if (ReportComputerView) { $reportTable.Page--; ShowReportData $script:reportData }
    elseif ($script:reportQuery.Page -gt 0) { $script:reportQuery.Page--; ReadReport }
} -PassThru
$reportPageLabel=[Windows.Forms.Label]::new()
$reportPageLabel.AutoSize=$true; $reportPageLabel.Margin=[Windows.Forms.Padding]::new(5,8,5,3)
$reportFooter.Controls.Add($reportPageLabel)
$reportNextButton=Button $reportFooter 'Next' {
    if (ReportComputerView) { $reportTable.Page++; ShowReportData $script:reportData }
    elseif ($script:reportData -and ($script:reportQuery.Page+1)*100 -lt $script:reportData.Total) { $script:reportQuery.Page++; ReadReport }
} -PassThru
$reportDetailsButton=Button $reportFooter 'Open details' {
    if ($reportList.SelectedItems.Count) { OpenReportRow $reportList.SelectedItems[0].Tag }
} -PassThru
$reportOnlineButton=Button $reportFooter 'Check online' {
    StartWork 'Online check' @(GetReportComputerTargets)
} -PassThru
$reportOnlineStatus=[Windows.Forms.LinkLabel]::new()
$reportOnlineStatus.AutoSize=$true; $reportOnlineStatus.Margin=$reportPageLabel.Margin
$reportOnlineStatus.Add_LinkClicked({ ShowOnlineDetails $script:reportQuery.Id $script:reportQuery.Label })
$reportFooter.Controls.Add($reportOnlineStatus)
$reportEventsButton=Button $reportFooter 'Windows Update events ...' {
    OpenEventQuery @(GetReportComputerTargets)
} -PassThru
$reportSelectAll=[Windows.Forms.CheckBox]::new()
$reportSelectAll.Text='Select all computers'; $reportSelectAll.AutoSize=$true; $reportSelectAll.Margin=$supersededFilter.Margin
$reportFooter.Controls.Add($reportSelectAll)
$reportSelectionLabel=[Windows.Forms.Label]::new()
$reportSelectionLabel.AutoSize=$true; $reportSelectionLabel.Margin=$reportPageLabel.Margin
$reportFooter.Controls.Add($reportSelectionLabel)
$reportSelectAll.Add_Click({
    if ($reportTable.Delay.Enabled -or $reportTable.Pending) { return }
    $check=$reportChecked.Count -lt $reportTargets.Count
    $reportChecked.Clear()
    if ($check) { foreach ($id in $reportTargets.Keys) { $reportChecked[$id]=$reportTargets[$id] } }
    RefreshReportChecks
})
function OpenReportRow($r,$column=-1) {
    if (!$r.Next) { return }
    $filter=switch ($script:reportQuery.Kind) {
        'Computers with errors' { 'Failed' }
        'Computers needing updates' { 'Outstanding' }
        'Approved outstanding' { 'Approved outstanding' }
        default { '' }
    }
    if ($r.Next -eq 'Computer list') {
        $map=@{4='Installed';5='InstalledPendingReboot';6='Downloaded';7='NotInstalled';8='Failed';9='Unknown';10='NotApplicable'}
        if ($map.ContainsKey($column)) { $filter=$map[$column] }
    }
    $q=NewReportQuery $r.Next $r.Cells[0] '' $r.Id $r.Group $filter
    if ($script:reportQuery.Kind -eq 'Server') {
        $slot=$indexes[$script:reportSelectionKey]
        if (!$slot.Snapshot.Related -or $slot.Snapshot.Stamp -ne $script:reportData.Stamp) { return }
        $q.Seed=@{Snapshot=$slot.Snapshot.Related[$r.Next];Version=$slot.Version;Used=[datetime]::UtcNow.Ticks}
    }
    OpenReport $q
}
$reportList.Add_SelectedIndexChanged({
    UpdateReportControls
})
$reportList.Add_ItemCheck({
    param($sender,$e)
    if ($sender.Items[$e.Index].Tag.Next -ne 'PC') { $e.NewValue='Unchecked' }
})
$reportList.Add_ItemChecked({
    param($sender,$e)
    if ($script:refreshingReportChecks -or $e.Item.Tag.Next -ne 'PC' -or !$reportList.CheckBoxes) { return }
    $id=[string]$e.Item.Tag.Id
    if ($e.Item.Checked -and $reportTargets.ContainsKey($id)) { $reportChecked[$id]=$reportTargets[$id] }
    else { $reportChecked.Remove($id) }
    if ($script:reportQuery.Kind -in @('Deadlines','Overdue deadlines','Deadlines next 7 days','Restart pending')) { RefreshReportChecks }
    UpdateReportControls
})
$reportList.Add_MouseDoubleClick({ param($sender,$e)
    if (OnlineCellHit $reportList $e.Location) { return }
    $hit=$reportList.HitTest($e.Location)
    if ($hit.Item) { OpenReportRow $hit.Item.Tag ($hit.Item.SubItems.IndexOf($hit.SubItem)) }
})
$reportList.Add_KeyDown({ param($sender,$e)
    if ($e.KeyCode -eq 'Enter' -and $reportList.SelectedItems.Count) {
        $e.SuppressKeyPress=$true
        OpenReportRow $reportList.SelectedItems[0].Tag
    }
})
$ul.Add_DoubleClick({
    if ($ul.SelectedItems.Count) {
        $r=$ul.SelectedItems[0].Tag
        $tabs.SelectedTab=$dashboard
        OpenReport (NewReportQuery 'Update' $r.Title '' $r.Id)
    }
})
function DisposeStoppedQueries($queries) {
    for ($i=$queries.Count-1; $i -ge 0; $i--) {
        $old=$queries[$i]
        if (!$old.Stop.IsCompleted -or !$old.Async.IsCompleted) { continue }
        try { $old.PS.EndStop($old.Stop); [void]$old.PS.EndInvoke($old.Async) }
        catch [Management.Automation.PipelineStoppedException] {}
        catch { Write-Verbose $_.Exception.Message }
        finally { $old.PS.Dispose(); $queries.RemoveAt($i) }
    }
}
$reportTimer=[Windows.Forms.Timer]::new(); $reportTimer.Interval=500
$reportTimer.Add_Tick({
    DisposeStoppedQueries $retiringWork
    DisposeStoppedQueries $retiring
    $j=$script:reportJob
    if ($j -and $null -ne $j.PreviewQueue -and !$j.Async.IsCompleted -and !$script:reportData -and $script:reportPath -eq $j.Path) {
        $partial=$null
        if ($j.PreviewQueue.TryDequeue([ref]$partial)) {
            $script:reportData=$partial; $script:reportSource='Loading rollout counts ...'
            ShowReportData $partial
        }
    }
    if ($j -and $j.Async.IsCompleted) {
        try {
            $out=@($j.PS.EndInvoke($j.Async))
            if ($out.Count -ne 1) { throw 'Incomplete response from WSUS.' }
            $answer=$out[0]; $data=$answer.Data; $data | Add-Member -NotePropertyName Version -NotePropertyValue $j.Version
            if ($j.Version -eq (CacheVersion)) {
                foreach ($id in $answer.Metadata.Keys) { $reportMetadata[$id]=$answer.Metadata[$id] }
                if ($reportMetadata.Count -gt 1000) {
                    $oldMetadata=@($reportMetadata.GetEnumerator() | Sort-Object { $_.Value.Stamp } -Descending | Select-Object -Skip 1000)
                    foreach ($entry in $oldMetadata) { $reportMetadata.Remove($entry.Key) }
                }
                if ($answer.Source -eq 'WSUS query') {
                    foreach ($kind in $answer.Related.Keys) {
                        $key=CacheHash (ConvertTo-Json @($kind,'','','','') -Compress)
                        $indexes[$key]=@{Snapshot=$answer.Related[$kind];Version=$j.Version;Used=[datetime]::UtcNow.Ticks}
                    }
                }
                $indexes[$j.Key]=@{Snapshot=$answer.Snapshot; Version=$j.Version; Used=[datetime]::UtcNow.Ticks}
                while ($indexes.Count -gt 16) {
                    $oldest=$indexes.GetEnumerator() | Sort-Object { $_.Value.Used } | Select-Object -First 1
                    $indexes.Remove($oldest.Key)
                }
                $dest=ReportPagePath $j.Key $data.Page
                $reportPages[$dest]=@{Data=$data; Used=[datetime]::UtcNow.Ticks}
                if ($reportPages.Count -gt 32) {
                    $oldPage=$reportPages.GetEnumerator() | Sort-Object { $_.Value.Used } | Select-Object -First 1
                    $reportPages.Remove($oldPage.Key)
                }
                if ($script:reportPath -eq $j.Path) {
                    $script:reportSource=("{0} | {1:N2} s" -f $answer.Source,$answer.Seconds)
                    $script:reportQuery.Page=$data.Page; $script:reportPath=$dest
                    $script:reportData=$data; ShowReportData $data
                }
                $tmp=Join-Path $reportDir ([guid]::NewGuid().ToString()+'.tmp')
                try {
                    [IO.File]::WriteAllText($tmp,(ConvertTo-Json $data -Depth 6 -Compress),$encoding)
                    if ([IO.File]::Exists($dest)) { [IO.File]::Replace($tmp,$dest,[NullString]::Value) }
                    else { [IO.File]::Move($tmp,$dest) }
                    Get-ChildItem -LiteralPath $reportDir -Filter '*.json' -File | Sort-Object LastWriteTimeUtc -Descending |
                        Select-Object -Skip 128 | Remove-Item -ErrorAction SilentlyContinue
                } finally { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } }
            } else { $script:reportDirty=$true }
        } catch {
            if ($script:reportPath -eq $j.Path) {
                if ($script:reportData) { ShowReportData $script:reportData }
                else { $reportNote.Text=$script:reportQuery.Label }
                $reportNote.Text+=" | Refresh failed: $($_.Exception.GetBaseException().Message)"
            }
        } finally { $j.PS.Dispose(); $script:reportJob=$null; UpdateReportControls }
        $script:reportNext=[datetime]::UtcNow.AddSeconds(30)
        if ($script:reportDirty) {
            $script:reportDirty=$false; $forceNext=[bool]$script:reportForce; $script:reportForce=$false
            ReadReport $forceNext
        }
    } elseif (!$j -and !$script:active -and $tabs.SelectedTab -eq $dashboard -and [datetime]::UtcNow -ge $script:reportNext) {
        $script:reportNext=[datetime]::UtcNow.AddSeconds(30)
        ReadReport
    }
})
$tabs.Add_SelectedIndexChanged({
    $workspace.Panel1Collapsed=$tabs.SelectedTab -notin @($updates,$clients)
    if ($tabs.SelectedTab -eq $dashboard) { ReadReport }
    if ($tabs.SelectedTab -eq $tracking -and !$script:active) { StartWork 'Reporting status' }
})
$reportTimer.Start()
UpdateReportControls

$form.Add_Shown({ ReadReport; StartWork 'Groups' })
try { [void]$form.ShowDialog() } finally {
    $reportTimer.Dispose(); $poll.Dispose(); $timer.Dispose(); $form.Dispose(); $overviewValueFont.Dispose()
    DisposeStoppedQueries $retiringWork
    DisposeStoppedQueries $retiring
    $appIconImage.Dispose(); $appIconImageStream.Dispose(); $appIcon.Dispose(); $appIconStream.Dispose()
}
