#Requires -Version 5.1
$ErrorActionPreference='Stop'
$tokens=$null
$parseErrors=$null
$scriptPath=Join-Path $PSScriptRoot 'WSUS-Manager.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors) { throw ($parseErrors.Message -join [Environment]::NewLine) }

function Assert-Equal($actual,$expected,$description) {
    if ($actual -ne $expected) { throw "$description. Expected '$expected', received '$actual'." }
}
function Definition($name) {
    $node=$ast.Find({
        param($item)
        $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq $name
    },$true)
    [scriptblock]::Create($node.Extent.Text)
}
function ScriptAssignment($variable) {
    $node=$ast.Find({
        param($item)
        $item -is [Management.Automation.Language.AssignmentStatementAst] -and $item.Left.Extent.Text -eq $variable
    },$true)
    [scriptblock]::Create($node.Extent.Text)
}

& {
    . (Definition 'ApprovalPlan')
    . (Definition 'State')
    . (Definition 'Exclusion')
    function ReadRules {}
    function Latest($id) { $update }
    function Chain($group) { $group; if ($group.Id -eq $child.Id) { $parent } }
    function Scope($groups) { $groups[0] }
    $parent=[pscustomobject]@{Id=[guid]::NewGuid(); Name='Production'}
    $child=[pscustomobject]@{Id=[guid]::NewGuid(); Name='Pilot'}
    $parent | Add-Member ScriptMethod GetChildTargetGroups { $child }
    $child | Add-Member ScriptMethod GetChildTargetGroups {}
    $ws=[pscustomobject]@{}
    $ws | Add-Member ScriptMethod GetComputerTargetGroup { param($id) if ($id -eq $parent.Id) { $parent } else { $child } }
    $update=[pscustomobject]@{Id=[pscustomobject]@{RevisionNumber=7}; IsDeclined=$false}
    $update | Add-Member ScriptMethod GetUpdateApprovals { $testApprovals }
    $update | Add-Member ScriptMethod GetUpdateInstallationInfoPerComputerTarget {
        param($scope)
        $visited.Add($scope.Name)
        [pscustomobject]@{ComputerTargetId='same-client';UpdateInstallationState='NotInstalled';UpdateApprovalAction='NotApproved'}
    }
    $update | Add-Member ScriptMethod Approve {
        param($action,$group,$deadline)
        $writes[[string]$group.Id]=$deadline
    }
    $config=@{IsReplicaServer=$false}
    $visited=[Collections.Generic.List[string]]::new()
    $testApprovals=@()
    $job=@{Rows=@(
        [pscustomobject]@{Id='update';GroupId=$child.Id;Group=$child.Name;Revision=7;Status='No approval set';DeadlineUtc=[datetime]::UtcNow.AddDays(2)}
        [pscustomobject]@{Id='update';GroupId=$parent.Id;Group=$parent.Name;Revision=7;Status='No approval set';DeadlineUtc=[datetime]::UtcNow.AddDays(7)}
    )}
    $original=ApprovalPlan
    Assert-Equal $original.Count 1 'The same client must count once across groups'
    Assert-Equal $visited.Count 2 'A separately selected child must be evaluated once'
    Assert-Equal (ApprovalPlan).Fingerprint $original.Fingerprint 'An unchanged plan must have a stable fingerprint'
    $testApprovals=@([pscustomobject]@{ComputerTargetGroupId=[guid]::NewGuid(); Action='Install'; Deadline=[datetime]::UtcNow.AddDays(1)})
    Assert-Equal ((ApprovalPlan).Fingerprint -ne $original.Fingerprint) $true 'New approvals must invalidate the preview'
    $testApprovals=@()
    $writeNode=$ast.Find({
        param($item)
        $item -is [Management.Automation.Language.IfStatementAst] -and
            $item.Clauses[0].Item1.Extent.Text -eq '$job.Mode -eq ''Approval''' -and
            $item.Clauses[0].Item2.Extent.Text.Contains(".Approve('Install'")
    },$true)
    $writeApproval=[scriptblock]::Create($writeNode.Clauses[0].Item2.Extent.Text.Trim('{}'))
    $writes=@{}
    foreach ($r in $job.Rows) { & $writeApproval }
    Assert-Equal $writes[[string]$child.Id] $job.Rows[0].DeadlineUtc 'The pilot must receive its own deadline'
    Assert-Equal $writes[[string]$parent.Id] $job.Rows[1].DeadlineUtc 'Production must receive its own deadline'
    $r=$job.Rows[1]; $r.DeadlineUtc=$null
    & $writeApproval
    Assert-Equal $writes[[string]$parent.Id] ([datetime]::MaxValue) 'An explicit no-deadline plan must clear the WSUS deadline'
}

& {
    . (Definition 'CaseTime')
    . (Definition 'AddCaseEvent')
    . (Definition 'Get-CaseState')
    . (Definition 'TimeText')
    function FindCaseClient($name) { $candidate }
    $now=[datetime]::UtcNow
    $saved=@{Id=[guid]::NewGuid();Name='pc.example';Key=[guid]::NewGuid()
        Start=$now.AddHours(-1).ToString('o');RemovedUtc=$now.AddMinutes(-30).ToString('o')
        Sync=$now.AddHours(-2).Ticks;Report=$now.AddDays(-45).Ticks
        Removed=$true;RemovalState='Removed';MachineGuid='saved-machine';VerifiedId=''
        Groups=@([pscustomobject]@{Id=[guid]::NewGuid();Name='Pilot'})}
    $candidate=[pscustomobject]@{Id=[guid]::NewGuid();LastSyncTime=$now;LastReportedStatusTime=$now}
    $candidate | Add-Member ScriptMethod GetComputerTargetGroups {}
    $config=@{TargetingMode='Server'}
    $builtins=@()
    $state=Get-CaseState $saved
    Assert-Equal $state.Verify $true 'A new client ID must wait for identity verification'
    Assert-Equal $state.Pending $false 'An identity mismatch must stop polling'
    Assert-Equal $state.Missing.Count 0 'A new unverified client must have no restorable groups'
    $saved.VerifiedId=[string]$candidate.Id
    $state=Get-CaseState $saved
    Assert-Equal $state.Stage 'Groups missing' 'The verified client should expose the missing group'
    Assert-Equal $state.Missing.Count 1 'The saved pilot membership must be available for restoration'
    Assert-Equal $state.Timeline.Count 2 'Latest WSUS contact and report must be shown on the timeline'
    $config.TargetingMode='Client'
    $saved.ExpectedGroups=@('Pilot')
    $candidate | Add-Member NoteProperty RequestedTargetGroupNames @('Other')
    $state=Get-CaseState $saved
    Assert-Equal $state.Stage 'Client target groups missing' 'A missed configured group must be exposed even after the client reports'
    Assert-Equal $state.Missing.Count 0 'Client targeting must not offer manual membership restoration'
    Assert-Equal $state.RequestedGroups[0] 'Other' 'The reported group must remain distinct from the configured group'
    $saved.RemovalState='Prepared'; $saved.Removed=$false
    $state=Get-CaseState $saved
    Assert-Equal $state.Stage 'Removal outcome unknown' 'An interrupted removal must be recoverable'
    Assert-Equal $state.Retry $true 'An interrupted removal must allow a retry'
}

& {
    . (ScriptAssignment '$scanBlock')
    function Get-ItemProperty {
        param($Path)
        switch -Wildcard ($Path) {
            '*\AU' { @{UseWUServer=1} }
            '*\Cryptography' { @{MachineGuid='matched'} }
            '*\CurrentVersion\WindowsUpdate' { @{SusClientId='{test-client}'} }
            default { @{WUServer='https://wsus.example:8531';WUStatusServer='https://wsus.example:8531'
                TargetGroupEnabled=1;TargetGroup='Pilot;Production'} }
        }
    }
    $identity=& $scanBlock 'https://wsus.example:8531' $true
    Assert-Equal $identity.ClientId 'test-client' 'The endpoint ID must match the API format'
    Assert-Equal $identity.TargetGroup 'Pilot;Production' 'The endpoint precheck must read the configured groups'
    Assert-Equal $identity.TargetingEnabled $true 'The endpoint precheck must read client-side targeting'
    $rejected=$false
    try { & $scanBlock 'https://different.example:8531' $true } catch { $rejected=$true }
    Assert-Equal $rejected $true 'The scan must reject a different WSUS policy'
    $rejected=$false
    try { & $scanBlock 'https://wsus.example:8531' $false $false 'other-machine' } catch { $rejected=$_.Exception.Message -like '*identity changed*' }
    Assert-Equal $rejected $true 'The scan must reject an endpoint identity change before calling WUA'
}

& {
    . (Definition 'TestReAddGroups')
    $groups=@{Pilot=1;Production=1;Duplicate=2}
    $policy=@{TargetingEnabled=$true;TargetGroup=' Pilot ; Production;pilot; '}
    $names=@(TestReAddGroups $policy $groups 'Client')
    Assert-Equal $names.Count 2 'Client target groups must be trimmed and deduplicated'
    foreach ($invalid in 'Typo','Duplicate') {
        $policy.TargetGroup="Pilot;$invalid"
        $blocked=$false
        try { TestReAddGroups $policy $groups 'Client' } catch { $blocked=$_.Exception.Message -like "*$invalid*" }
        Assert-Equal $blocked $true 'Missing or ambiguous client groups must block ReAdd'
    }
    $policy.TargetingEnabled=$false; $policy.TargetGroup='Pilot'
    $blocked=$false
    try { TestReAddGroups $policy $groups 'Client' } catch { $blocked=$true }
    Assert-Equal $blocked $true 'Disabled client targeting must block ReAdd in client mode'
    Assert-Equal @(TestReAddGroups $policy $groups 'Server').Count 0 'Server targeting uses the saved WSUS membership'
}

& {
    . (Definition 'ResolveClientAddress')
    . (Definition 'CheckReachability')
    $local=[pscustomobject]@{Id='local-only';FullDomainName='localhost';IPAddress='127.0.0.1'}
    $check=CheckReachability $local
    Assert-Equal ($check.IpResult -like 'Reply*') $true 'The direct loopback probe must report its reply'
    Assert-Equal ($check.DnsResult -like '*127.0.0.1 = Reply*') $true 'The DNS address check must report its reply independently'
    Assert-Equal $check.Finding 'DNS matches WSUS IP' 'DNS agreement must be visible'
    $local.IPAddress='0.0.0.0'; $local.FullDomainName='0.0.0.0'
    $check=CheckReachability $local
    Assert-Equal $check.IpResult 'Unavailable' 'Unspecified WSUS addresses must not be probed'
    . (Definition 'OnlineLabel')
    Assert-Equal (OnlineLabel $null) 'Not checked' 'An untested target must have a neutral status'
    Assert-Equal (OnlineLabel @{Finding='DNS / WSUS IP mismatch';IpResult='Reply (0 ms)'}) 'Unverified' 'A reply from the wrong address must not produce a green status'
    Assert-Equal (OnlineLabel @{Finding='DNS matches WSUS IP';IpResult='No reply (TimedOut)'}) 'No reply' 'A timeout must have its own visible label'
    $ws=[pscustomobject]@{}
    $ws | Add-Member ScriptMethod GetComputerTarget { param($id) @{Id=$id;FullDomainName='localhost';IPAddress='127.0.0.1'} }
    $job=@{Mode='Online check';Rows=@(foreach ($id in 1..10) { @{Id=$id;Name='localhost'} });OnlineQueue=[Collections.Concurrent.ConcurrentQueue[object]]::new()}
    $branch=$ast.Find({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$job.Mode -eq ''Online check'''},$true)
    & ([scriptblock]::Create($branch.Extent.Text))
    Assert-Equal $job.OnlineQueue.Count 10 'Every selected computer must publish exactly one result'
    foreach ($reply in $job.OnlineQueue.ToArray()) {
        Assert-Equal (OnlineLabel $reply) 'Reachable' "Parallel loopback result must be green ($($reply.Finding), $($reply.IpResult))"
    }
}

& {
    . (ScriptAssignment '$reportWorker')
    $pc1=[pscustomobject]@{Id='first';FullDomainName='pc1.example';IPAddress='192.0.2.10';LastReportedStatusTime=[datetime]::UtcNow}
    $pc2=[pscustomobject]@{Id='second';FullDomainName='pc2.example';IPAddress='192.0.2.11';LastReportedStatusTime=[datetime]::UtcNow}
    $summaryRows=@(
        [pscustomobject]@{ComputerTargetId='first';NotInstalledCount=1;DownloadedCount=0;FailedCount=0}
        [pscustomobject]@{ComputerTargetId='second';NotInstalledCount=2;DownloadedCount=3;FailedCount=1}
        [pscustomobject]@{ComputerTargetId='absent';NotInstalledCount=10;DownloadedCount=0;FailedCount=0}
    )
    $serverFixture=[pscustomobject]@{}
    $serverFixture | Add-Member ScriptMethod GetComputerTargets { param($scope) $pc1; $pc2 }
    $serverFixture | Add-Member ScriptMethod GetSummariesPerComputerTarget {
        param($updates,$computers)
        if ($computers.IncludedInstallationStates -ne 'NotInstalled, Downloaded, Failed') { throw 'Wrong outstanding states.' }
        $summaryRows
    }
    function Import-Module {}
    function Get-WsusServer { $serverFixture }
    function New-Object($type) { @{IncludedInstallationStates='';IncludeDownstreamComputerTargets=$false} }
    $answer=& $reportWorker @{} @{Kind='Computers needing updates';Page=0}
    Assert-Equal $answer.Data.Total 2 'The report must include PCs when their WSUS metadata is available'
    Assert-Equal $answer.Data.Rows[0].Id 'second' 'The PC with the most outstanding updates must appear first'
    Assert-Equal $answer.Data.Rows[0].Cells[1] 6 'Outstanding must sum missing, downloaded, and failed states'
    Assert-Equal $answer.Data.Rows[0].Next 'PC' 'The report must link to an individual PC'
    $pc1 | Add-Member ScriptMethod GetUpdateInstallationInfoPerUpdate {
        [pscustomobject]@{UpdateInstallationState='NotInstalled';UpdateApprovalAction='NotApproved'}
    }
    $pc2 | Add-Member ScriptMethod GetUpdateInstallationInfoPerUpdate {
        [pscustomobject]@{UpdateInstallationState='Downloaded';UpdateApprovalAction='Install'}
    }
    $serverFixture | Add-Member ScriptMethod GetStatus {
        @{ComputerTargetCount=2;ComputerTargetsNeedingUpdatesCount=77;UpdatesNeedingFilesCount=3;UpdatesWithServerErrorsCount=2
            UnrecognizedClientRequestedTargetGroupNames=@('Misspelled','Misspelled')}
    }
    $subscription=[pscustomobject]@{}
    $subscription | Add-Member ScriptMethod GetLastSynchronizationInfo { @{Result='Succeeded';EndTime=[datetime]::UtcNow} }
    $serverFixture | Add-Member ScriptMethod GetSubscription { $subscription }
    $overview=& $reportWorker @{} @{Kind='Server';Page=0}
    foreach ($kind in 'Computers needing updates','Approved outstanding','Computers with errors','Unknown target groups') {
        $card=$overview.Data.Rows | Where-Object Next -eq $kind
        $detail=& $reportWorker @{} @{Kind=$kind;Page=0} $overview.Related[$kind]
        Assert-Equal $card.Cells[1] $detail.Data.Total "Dashboard card and drill-down must use the same snapshot for $kind"
    }
    Assert-Equal $overview.Related['Approved outstanding'].Entries.Count 1 'Only computers with an effective install approval count in rollout'
    Assert-Equal $overview.Related['Approved outstanding'].Entries[0].Cells[1] 1 'The approved figure must reflect this PC only'
    Assert-Equal $overview.Related['Unknown target groups'].Entries.Count 1 'Unknown client groups must be deduplicated'
    Assert-Equal ($overview.Data.Rows | Where-Object { $_.Cells[0] -eq 'Synchronization result' }).Cells[1] 'Succeeded' 'The synchronization result must be visible'
}

& {
    . (ScriptAssignment '$reportWorker')
    $now=[datetime]::UtcNow
    $a=@{UpdateId=@{UpdateId='u'};ComputerTargetGroupId='pilot';Deadline=$now.AddHours(-2);Action='Install'}
    $b=@{UpdateId=@{UpdateId='u'};ComputerTargetGroupId='prod';Deadline=$now.AddDays(2);Action='Install'}
    $c=@{UpdateId=@{UpdateId='other'};ComputerTargetGroupId='prod';Deadline=[datetime]::MaxValue;Action='Install'}
    function Record($id,$group,$state,$action) {
        $item=[pscustomobject]@{UpdateId=$id;UpdateApprovalTargetGroupId=$group;UpdateInstallationState=$state;UpdateApprovalAction=$action}
        $item | Add-Member ScriptMethod GetUpdate { @{Title='Security update';KnowledgebaseArticles=@('123')} }
        $item
    }
    $clients=@(foreach ($name in 'pc1','pc2') { [pscustomobject]@{Id=$name;FullDomainName=$name;LastReportedStatusTime=$now} })
    $clients[0] | Add-Member ScriptMethod GetUpdateInstallationInfoPerUpdate {
        Record 'u' 'pilot' 'Failed' 'Install'; Record 'u' 'prod' 'NotInstalled' 'NotApproved'
    }
    $clients[1] | Add-Member ScriptMethod GetUpdateInstallationInfoPerUpdate {
        Record 'u' 'prod' 'InstalledPendingReboot' 'Install'; Record 'other' 'prod' 'Downloaded' 'Install'
    }
    $fake=[pscustomobject]@{}
    $fake | Add-Member ScriptMethod GetUpdateApprovals { $a;$b;$c }
    $fake | Add-Member ScriptMethod GetComputerTargetGroups { @{Id='pilot';Name='Pilot'};@{Id='prod';Name='Production'} }
    $fake | Add-Member ScriptMethod GetComputerTargets { $clients }
    function New-Object($type) { @{} }
    function Import-Module {}
    function Get-WsusServer { $fake }
    $out=& $reportWorker @{} @{Kind='Deadlines';Page=0}
    Assert-Equal $out.Data.Total 3 'The deadline report must include each effectively approved pending installation'
    Assert-Equal $out.Related['Overdue deadlines'].Entries[0].Cells[5] 'Pilot' 'The overdue deadline must come from the effective pilot group'
    Assert-Equal $out.Related['Deadlines next 7 days'].Entries[0].Cells[5] 'Production' 'The same update must keep its distinct production deadline'
    Assert-Equal $out.Related['Restart pending'].Entries.Count 1 'Only a pending reboot belongs in the restart report'
    Assert-Equal @($out.Data.Rows | Where-Object { $_.Cells[4] -eq 'No deadline' }).Count 1 'Unlimited deadlines must stay distinct'
}

& {
    . (ScriptAssignment '$scanBlock')
    function Get-ItemProperty($path) { @{WUServer='https://fixture.invalid';WUStatusServer='https://fixture.invalid';UseWUServer=1} }
    function New-Object($ComObject) {
        $o=[pscustomobject]@{}
        if ($ComObject -eq 'Microsoft.Update.AutoUpdate') {
            $o | Add-Member ScriptMethod DetectNow { throw [UnauthorizedAccessException]::new('Detection denied') }
        } else {
            $o | Add-Member ScriptMethod CreateUpdateSearcher {
                $s=[pscustomobject]@{ServerSelection=0;Online=$false}
                $s | Add-Member ScriptMethod Search { @{ResultCode=2;Updates=@()} }; $s
            }
        }
        $o
    }
    $r=& $scanBlock 'https://fixture.invalid' $false $true
    Assert-Equal $r.Search 'Succeeded' 'Search outcome must be independent of detection'
    Assert-Equal $r.Detection 'Failed' 'Detection failure must survive a successful search'
    Assert-Equal ($r.DetectionError -like '*0x80070005*Detection denied*') $true 'Detection must retain the original HRESULT'
}

& {
    . (Definition 'ReadScanSources')
    function Test-Path { $true }
    function Get-ItemProperty($path,$LiteralPath) {
        if ($path -like '*Cryptography') { return @{MachineGuid='known'} }
        if ($LiteralPath -like '*\AU') { return @{UseUpdateClassPolicySource=$gate; UseWUServer=1} }
        @{SetPolicyDrivenUpdateSourceForQualityUpdates=0;SetPolicyDrivenUpdateSourceForFeatureUpdates=1;TargetGroup='Pilot'}
    }
    $gate=1
    $lines=@(ReadScanSources 'known' '')
    Assert-Equal ($lines -contains 'Quality updates: Windows Update') $true 'An enabled class value of zero must map to Windows Update'
    Assert-Equal ($lines -contains 'Feature updates: WSUS') $true 'An enabled class value of one must map to WSUS'
    $gate=0
    Assert-Equal (@(ReadScanSources 'known' '') -contains 'Quality updates: Default (class policy inactive, stored value 0)') $true 'An inactive source policy must be identified'
}

& {
    . (ScriptAssignment '$reportWorker')
    . (Definition 'ReportPageIsFresh')
    $CacheMinutes=5
    $now=[datetime]::UtcNow
    $snapshot=@{Title='Pilot'; Columns=@('Computer'); Stamp=$now.Ticks.ToString()
        Entries=@(0..100 | ForEach-Object { [pscustomobject]@{Cells=@("pc-$_")} })}
    function Import-Module { throw 'Paging a Computer list snapshot must not import WSUS.' }
    $answer=& $reportWorker @{} @{Kind='Computer list';Page=1} $snapshot
    Assert-Equal $answer.Data.Rows.Count 1 'The second page should have the final client only'
    Assert-Equal $answer.Data.Rows[0].Cells[0] 'pc-100' 'Paging must preserve the snapshot order'
    $data=@{Version='1';Stamp=$now.Ticks.ToString()}
    Assert-Equal (ReportPageIsFresh $data '1' $now.AddMinutes(4).Ticks) $true 'A fresh page should be reusable'
    Assert-Equal (ReportPageIsFresh $data '2' $now.Ticks) $false 'A changed cache generation should invalidate a page'
    Assert-Equal (ReportPageIsFresh $data '1' $now.AddMinutes(6).Ticks) $false 'An expired page should be refreshed'

    $pcSnapshot=@{Title='PC'; Columns=@('Update','Installation status','Effective approval','KB')
        Stamp=$now.Ticks.ToString(); Entries=@([pscustomobject]@{Id='cached-update';State='Failed';Action='Install'})}
    $metadata=@{'cached-update'=@{Title='Cached title';KB='1234';Stamp=$now.Ticks}}
    $answer=& $reportWorker @{} @{Kind='PC';Page=0;CacheTicks=[timespan]::FromMinutes(5).Ticks} $pcSnapshot $metadata
    Assert-Equal $answer.Data.Rows[0].Cells[0] 'Cached title' 'Metadata must be reused across PC views'
    Assert-Equal $answer.Metadata.Count 0 'Cached metadata must not be fetched again'
    Assert-Equal $answer.Source 'Result cache' 'Cached metadata must not require a connection'
}

& {
    . (Definition 'GetUpdateRows')
    . (Definition 'State')
    . (Definition 'TimeText')
    . (Definition 'Exclusion')
    $ProgressPreference='SilentlyContinue'
    function New-Object($type) { @{ApprovedComputerTargetGroups=[Collections.ArrayList]::new()} }
    function Latest($id) {
        if ($id -ne $ids.Needed) { throw 'Approved-update search must reuse its scoped catalogue' }
        $candidate=$updatesFixture | Where-Object { $_.Id.UpdateId -eq $id }
        $candidate | Add-Member ScriptMethod GetUpdateApprovals {}
        $candidate
    }
    function Chain($group) { $group; $fixtureParent }
    function Scope($groups) { $groups[0] }
    $fixtureParent=[pscustomobject]@{Id=[guid]::NewGuid();Name='Parent'}
    $fixtureChild=[pscustomobject]@{Id=[guid]::NewGuid();Name='Pilot'}
    $groups=@($fixtureChild)
    $ids=@{Approved=[guid]::NewGuid();Needed=[guid]::NewGuid();Stale=[guid]::NewGuid();Masked=[guid]::NewGuid()}
    $updatesFixture=foreach ($name in $ids.Keys) {
        [pscustomobject]@{Id=[pscustomobject]@{UpdateId=$ids[$name];RevisionNumber=2}
            Title=$name;IsDeclined=$false;IsSuperseded=$false;KnowledgebaseArticles=@()}
    }
    $summaryFixture=foreach ($name in $ids.Keys) {
        [pscustomobject]@{UpdateId=$ids[$name];DownloadedCount=0;FailedCount=0
            NotInstalledCount=$(if ($name -in @('Needed','Masked')) { 2 } else { 0 })}
    }
    $deadline=[datetime]::UtcNow.AddDays(2)
    $approvalsFixture=@(
        [pscustomobject]@{UpdateId=[pscustomobject]@{UpdateId=$ids.Approved;RevisionNumber=2};ComputerTargetGroupId=$fixtureChild.Id;Action='Install';Deadline=$deadline}
        [pscustomobject]@{UpdateId=[pscustomobject]@{UpdateId=$ids.Stale;RevisionNumber=1};ComputerTargetGroupId=$fixtureChild.Id;Action='Install';Deadline=$deadline}
        [pscustomobject]@{UpdateId=[pscustomobject]@{UpdateId=$ids.Masked;RevisionNumber=2};ComputerTargetGroupId=$fixtureParent.Id;Action='Install';Deadline=$deadline}
        [pscustomobject]@{UpdateId=[pscustomobject]@{UpdateId=$ids.Masked;RevisionNumber=2};ComputerTargetGroupId=$fixtureChild.Id;Action='NotApproved';Deadline=[datetime]::MaxValue}
    )
    $calls=@{Metadata=0;Approvals=0;Summaries=0}
    $ws=[pscustomobject]@{}
    $ws | Add-Member ScriptMethod GetUpdates {
        param($scope)
        if ($scope.ApprovedStates -ne 'LatestRevisionApproved' -or $scope.ApprovedComputerTargetGroups.Count -ne 2) {
            throw 'Bulk metadata must be restricted to the selected group and ancestor approvals.'
        }
        $calls.Metadata++; $updatesFixture | Where-Object { $_.Id.UpdateId -ne $ids.Needed }
    }
    $ws | Add-Member ScriptMethod GetUpdateApprovals { param($scope) $calls.Approvals++; $approvalsFixture }
    $ws | Add-Member ScriptMethod GetSummariesPerUpdate { param($updates,$computers) $calls.Summaries++; $summaryFixture }
    $job=@{IncludeApproved=$true}
    $us=@{}; $rules=@()
    $batch=GetUpdateRows
    $result=$batch.All
    Assert-Equal $calls.Metadata 1 'The update catalogue must be loaded in one call'
    Assert-Equal $calls.Approvals 1 'Approvals must be loaded in one call'
    Assert-Equal $calls.Summaries 1 'Summaries must be loaded once per selected group'
    Assert-Equal $result.Count 3 'Current approval, needed update, and explicitly unapproved update must remain visible'
    $approved=@($result | Where-Object Title -eq Approved)[0]
    Assert-Equal $approved.Status 'Install' 'Current approval must be retained with zero outstanding clients'
    Assert-Equal $approved.CurrentDeadline (TimeText $deadline) 'Direct deadline must remain visible'
    Assert-Equal (@($result | Where-Object Title -eq Masked)[0].Status) 'NotApproved' 'Direct action must override inherited approval'
    $many=@(foreach ($n in 1..55) {
        [pscustomobject]@{Id=[pscustomobject]@{UpdateId=[guid]::NewGuid();RevisionNumber=1}
            Title="Needed $n";IsDeclined=$false;IsSuperseded=$false;KnowledgebaseArticles=@()}
    })
    $summaryFixture=@(foreach ($u in $many) {
        [pscustomobject]@{UpdateId=$u.Id.UpdateId;NotInstalledCount=1;DownloadedCount=0;FailedCount=0}
    })
    $job.IncludeApproved=$false
    $ws | Add-Member -Force ScriptMethod GetUpdates {
        param($scope)
        if ($scope.IncludedInstallationStates -ne 'NotInstalled, Downloaded, Failed') { throw 'Large missing sets require a state-filtered catalogue' }
        $calls.Metadata++; $many
    }
    $approvalsFixture=@()
    $batch=GetUpdateRows
    Assert-Equal $batch.All.Count 55 'A large unapproved set must remain complete without individual lookups'
    Assert-Equal $calls.Metadata 2 'The large missing set needs just one additional scoped catalogue read'
}

& {
    . (Definition 'Write-Audit')
    . (ScriptAssignment '$worker')
    $local=Join-Path ([IO.Path]::GetTempPath()) ('WSUS-AuditTest-'+[guid]::NewGuid())
    [void][IO.Directory]::CreateDirectory($local)
    $custom=Join-Path $local 'Central fixture'
    $settings=Join-Path $local 'AuditLogSettings.json'
    $name='WSUS-test.jsonl'
    $localLog=Join-Path $local $name
    $blocked=Join-Path $local 'not-a-directory'
    try {
        $request=@{Mode='Log location';Options=@{Path=$custom};LogName=$name;Server='fixture'
            Operation='configure';LogSettings=$settings}
        $saved=& $worker $request
        Assert-Equal $saved.Directory $custom 'Saving the log destination must select the custom folder'
        Assert-Equal (ConvertFrom-Json ([IO.File]::ReadAllText($settings))).Directory $custom 'Log destination must persist'
        Assert-Equal ([IO.File]::Exists($saved.Log)) $true 'A successful setup must verify write access'
        [IO.File]::WriteAllText($blocked,'This is a file.')
        $state=@{Error=''}
        Write-Audit ([IO.Path]::Combine($blocked,$name)) 'fixture' 'probe' 'Audit fallback' 'OK' 'KB12345' $localLog $state 3>$null
        Assert-Equal ([bool]$state.Error) $true 'A failed custom log write must be recorded'
        Assert-Equal ([IO.File]::Exists($localLog)) $true 'Failed shared writes must be preserved in the local audit'
        $stream=[IO.FileStream]::new($saved.Log,'Open','Write','Read')
        try {
            $audit=@(& $worker @{Mode='Audit log';Folder=$local;Directory=$custom;From=(Get-Date).AddHours(-1)
                Until=(Get-Date).AddHours(1);UserFilter='';Query=''})
            Assert-Equal $audit.Count 2 'Audit search must read both destinations while a writer has the central file open'
        } finally { $stream.Dispose() }
        $search=@(& $worker @{Mode='Audit log';Folder=$local;Directory=$custom;From=(Get-Date).AddHours(-1)
            Until=(Get-Date).AddHours(1);UserFilter='';Query='KB12345'})
        Assert-Equal $search.Count 1 'Normalized KB filtering must also find fallback audit entries'
        $request.Options.Path='relative-folder'
        $rejected=$false
        try { & $worker $request } catch { $rejected=$_.Exception.Message -like '*absolute*' }
        Assert-Equal $rejected $true 'A relative central audit folder must be rejected'
        Assert-Equal (ConvertFrom-Json ([IO.File]::ReadAllText($settings))).Directory $custom 'Failed settings must preserve the previous destination'
    } finally {
        foreach ($path in $localLog,$settings,$blocked,([IO.Path]::Combine($custom,$name))) {
            if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
        }
        if ([IO.Directory]::Exists($custom)) { [IO.Directory]::Delete($custom) }
        [IO.Directory]::Delete($local)
    }
}

& {
    . (Definition 'GetWindowsUpdateEvents')
    $eventFixture=@{Calls=0;Behavior='Result'}
    function Get-ItemProperty {
        [CmdletBinding()]
        param($Path)
        if ($Path -like '*Cryptography') { @{MachineGuid='trusted-machine'} }
        else { @{SusClientId='{trusted-client}'} }
    }
    function Get-WinEvent {
        [CmdletBinding()]
        param($FilterHashtable,$MaxEvents)
        $eventFixture.Calls++
        $eventFixture.Filter=$FilterHashtable; $eventFixture.Max=$MaxEvents
        switch ($eventFixture.Behavior) {
            'Empty' { Write-Error -ErrorId 'NoMatchingEventsFound' -Message 'No events'; return }
            'Denied' { throw [UnauthorizedAccessException]::new('Access denied') }
        }
        [pscustomobject]@{TimeCreated=[datetime]::UtcNow;Id=20;LevelDisplayName='Error';Message='Simulated update failure'}
    }
    $since=[datetime]::UtcNow.AddHours(-24)
    $events=@(GetWindowsUpdateEvents $since 'trusted-machine' 'trusted-client' $true)
    Assert-Equal $events.Count 1 'The endpoint diagnostic must return the requested event'
    Assert-Equal $events[0].Id 20 'Event IDs must be preserved'
    Assert-Equal $eventFixture.Filter.LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' 'Only the requested channel may be read'
    Assert-Equal ($eventFixture.Filter.Level -join ',') '1,2,3' 'Errors-only mode must include critical, error and warning levels'
    Assert-Equal $eventFixture.Filter.StartTime $since 'The selected time window must be sent to the endpoint'
    Assert-Equal $eventFixture.Max 100 'The event query must cap results per endpoint'
    $rejected=$false
    try { GetWindowsUpdateEvents $since 'different-machine' '' $false } catch { $rejected=$true }
    Assert-Equal $rejected $true 'Case identity must be verified before reading events'
    Assert-Equal $eventFixture.Calls 1 'An identity mismatch must not query the event log'
    $eventFixture.Behavior='Empty'
    Assert-Equal @(GetWindowsUpdateEvents $since '' 'trusted-client' $false).Count 0 'An empty matching event log is a successful result'
    $eventFixture.Behavior='Denied'
    $denied=$false
    try { GetWindowsUpdateEvents $since '' 'trusted-client' $false } catch { $denied=$_.Exception.Message -like '*denied*' }
    Assert-Equal $denied $true 'Permission denial must be surfaced as an error'
}

& {
    . (Definition 'SelectTableRows')
    $rows=@(
        [pscustomobject]@{Id='embedded';Cells=@('Megalpha','Production',105)}
        [pscustomobject]@{Id='word';Cells=@('West Alpha','Lab',11)}
        [pscustomobject]@{Id='exact';Cells=@('ALPHA','Prod',2)}
        [pscustomobject]@{Id='prefix';Cells=@('Alpha-DB','Production',10)}
    )
    $ranked=SelectTableRows $rows 'alpha' -1 $false
    Assert-Equal ($ranked.Id -join ',') 'exact,prefix,word,embedded' 'Like search must rank exact and prefix matches above embedded matches'
    $crossColumn=SelectTableRows $rows 'PROD alpha' -1 $false
    Assert-Equal ($crossColumn.Id -join ',') 'exact,prefix,embedded' 'All terms must match, including across different columns'
    $numeric=SelectTableRows $rows 'alpha' 2 $false
    Assert-Equal ($numeric.Id -join ',') 'exact,prefix,word,embedded' 'Numeric columns must sort by value and not digit order'
    $descending=SelectTableRows $rows '' 2 $true
    Assert-Equal ($descending.Id -join ',') 'embedded,word,prefix,exact' 'Column sort must support descending order'
    $unmatched=SelectTableRows $rows 'not-present' -1 $false
    Assert-Equal $unmatched.Count 0 'An unmatched search must display no rows'
}

Write-Output 'WSUS-Manager regression checks passed.'
