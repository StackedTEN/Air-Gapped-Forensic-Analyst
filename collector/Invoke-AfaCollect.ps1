<#
.SYNOPSIS
  Invoke-AfaCollect — a read-only live triage collector for the Air-Gapped
  Forensic Analyst. Gathers high-value volatile and persistence artifacts from a
  running Windows host in minutes and writes a normalized collection package
  (artifacts + a manifest with SHA-256 hashes and chain-of-custody).

  This is live triage, NOT disk imaging — the model that scales to modern IR.
  It is strictly read-only: it reads process, network, registry, and event data
  using OS-native facilities and writes only to the output folder. It never
  modifies the target system.

.PARAMETER Profile
  quick   host, processes, network, autoruns, services, tasks, users, recent events
  full    quick + image-file hashes + DNS cache + SMB sessions

.PARAMETER ComputerName
  One or more remote hosts to triage over WinRM. Omit to collect locally.

.EXAMPLE
  .\Invoke-AfaCollect.ps1 -Profile quick -Operator "T.Nelson" -CaseId IR-2026-014
.EXAMPLE
  .\Invoke-AfaCollect.ps1 -ComputerName web-01,db-02 -Operator "T.Nelson" -CaseId IR-2026-014
#>
[CmdletBinding()]
param(
  [Alias('Profile')] [ValidateSet('quick','full')] [string]$CollectionProfile = 'quick',
  [string[]]$ComputerName,
  [string]$Operator = $env:USERNAME,
  [string]$CaseId = ("IR-" + (Get-Date -Format 'yyyyMMdd-HHmmss')),
  [int]$Days = 7,
  [int]$MaxEvents = 2000,
  [switch]$HashAll,
  [string]$OutputPath = (Join-Path (Get-Location) 'afa-collections')
)

$CollectorVersion = '1.0.0'

# Event IDs worth pulling for triage, by log.
$EventTargets = @(
  @{ Log = 'Security'; Ids = 4624,4625,4672,4688,4720,4726,4732,4698,1102 },
  @{ Log = 'System';   Ids = 7045,7040,104 },
  @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = 4104 }
)

# ---- the collection scriptblock; runs locally or on a remote host ----
$CollectCore = {
  param($CollectionProfile, $Days, $MaxEvents, $EventTargets, $HashAll)

  $warnings = New-Object System.Collections.ArrayList
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
             ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  if (-not $isAdmin) {
    [void]$warnings.Add("Collector was NOT run elevated; the Security event log (4624/4625/4688/4720/1102 …) likely could not be read. Re-run as Administrator for a complete picture.")
  }

  function Cat-RegKey([string]$key) {
    $k = $key.ToLower()
    if ($k -like '*\run') { 'run' }
    elseif ($k -like '*\services\*') { 'service' }
    elseif ($k -like '*usbstor*') { 'usbstor' }
    else { 'other' }
  }

  # Human-readable label per event id. Rendering $_.Message in the hot loop forces
  # Get-WinEvent to load each provider's message metadata and format the event —
  # the dominant cost of a "quick" collection. We build `detail` from this static
  # map plus cheap $_.Properties access instead, and never touch $_.Message.
  $EventLabels = @{
    4624 = 'An account was successfully logged on';     4625 = 'An account failed to log on'
    4672 = 'Special privileges assigned to new logon';  4688 = 'A new process has been created'
    4720 = 'A user account was created';                4726 = 'A user account was deleted'
    4732 = 'A member was added to a security-enabled local group'
    4698 = 'A scheduled task was created';              1102 = 'The audit log was cleared'
    7045 = 'A new service was installed';               7040 = 'Service start type was changed'
    104  = 'Event log was cleared';                     4104 = 'PowerShell script block logged'
  }

  # Only hash binaries that matter forensically (suspicious/non-OS locations),
  # unless -HashAll is set. This keeps the `full` profile fast.
  function Should-Hash([string]$path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $false }
    if ($HashAll) { return $true }
    $p = $path.ToLower()
    return ($p -like '*\users\public\*' -or $p -like '*\appdata\*' -or
            $p -like '*\windows\temp\*' -or $p -like '*\programdata\*' -or
            ($p -notlike "$($env:WINDIR.ToLower())\*" -and $p -notlike '*\program files*'))
  }

  $host_info = [ordered]@{
    computer   = $env:COMPUTERNAME
    os         = (Get-CimInstance Win32_OperatingSystem).Caption
    boot_time  = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
    current_user = "$env:USERDOMAIN\$env:USERNAME"
    collected_at = (Get-Date).ToUniversalTime().ToString('o')
  }

  # owner lookup: ONE bulk call. A per-process `Invoke-CimMethod GetOwner` round-trip
  # is the dominant cost of collection (hundreds of seconds for a few hundred procs);
  # `Get-Process -IncludeUserName` returns DOMAIN\User for every process at once.
  # (Requires elevation — when not admin we skip it; owners stay blank, as the
  # per-process GetOwner already did for most processes without admin.)
  $ownerById = @{}
  if ($isAdmin) {
    try {
      foreach ($gp in (Get-Process -IncludeUserName -ErrorAction Stop)) {
        if ($gp.UserName) { $ownerById[[int]$gp.Id] = [string]$gp.UserName }
      }
    } catch {
      [void]$warnings.Add("Bulk owner resolution (Get-Process -IncludeUserName) failed: $($_.Exception.Message.Trim())")
    }
  }

  # processes (read-only): pid, ppid, image, command line, owner
  $processes = Get-CimInstance Win32_Process | ForEach-Object {
    $pidInt = [int]$_.ProcessId
    [ordered]@{
      pid = $_.ProcessId; ppid = $_.ParentProcessId
      name = $_.Name; path = $_.ExecutablePath; cmdline = $_.CommandLine
      user = $(if ($ownerById.ContainsKey($pidInt)) { $ownerById[$pidInt] } else { '' })
      created = $(if ($_.CreationDate) { $_.CreationDate.ToString('o') } else { '' })
      hash = ''
    }
  }

  # optional: hash process images (slower) for the full profile
  if ($CollectionProfile -eq 'full') {
    foreach ($p in $processes) {
      if (Should-Hash $p.path) {
        try { $p.hash = (Get-FileHash -LiteralPath $p.path -Algorithm SHA256).Hash } catch {}
      }
    }
  }

  # network connections joined to owning process
  $procById = @{}; foreach ($p in $processes) { $procById[[int]$p.pid] = $p.name }
  $network = Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{
      proto = 'tcp'; local = "$($_.LocalAddress):$($_.LocalPort)"
      remote = "$($_.RemoteAddress):$($_.RemotePort)"; state = "$($_.State)"
      pid = $_.OwningProcess; process = $procById[[int]$_.OwningProcess]
    }
  }

  # autoruns / registry persistence (normalized rows)
  $registry = New-Object System.Collections.ArrayList
  $runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
  )
  foreach ($rk in $runKeys) {
    if (Test-Path $rk) {
      $props = Get-ItemProperty $rk
      foreach ($n in ($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
        $hive = if ($rk -like 'HKLM*') { 'HKLM' } else { 'HKCU' }
        [void]$registry.Add([ordered]@{
          hive = $hive; key = ($rk -replace '^HK..:\\',''); value_name = $n.Name
          value_data = "$($n.Value)"; last_write = ''; category = 'run'
        })
      }
    }
  }

  # services as registry-style rows (ImagePath + start type)
  $services = Get-CimInstance Win32_Service | ForEach-Object {
    [void]$registry.Add([ordered]@{
      hive='HKLM'; key="SYSTEM\CurrentControlSet\Services\$($_.Name)";
      value_name='ImagePath'; value_data="$($_.PathName)"; last_write=''; category='service'
    })
    $signed = ''
    if ($CollectionProfile -eq 'full' -and $_.PathName) {
      $img = ($_.PathName -replace '^"','' -split '"')[0]
      if (Should-Hash $img) {
        try { $signed = (Get-AuthenticodeSignature -LiteralPath $img).Status.ToString() } catch {}
      }
    }
    [ordered]@{ name=$_.Name; display=$_.DisplayName; path=$_.PathName;
                start=$_.StartMode; state=$_.State; account=$_.StartName; signature=$signed }
  }

  # program-execution evidence: distinct process images + executables dropped in
  # user-writable directories (the high-value triage subset; full disk = $MFT/Amcache later)
  $programs = New-Object System.Collections.ArrayList
  $seen = @{}
  foreach ($p in $processes) {
    if ($p.path -and -not $seen.ContainsKey($p.path)) {
      $seen[$p.path] = $true
      $sha1 = ''
      if (Should-Hash $p.path) {
        try { $sha1 = (Get-FileHash -LiteralPath $p.path -Algorithm SHA1).Hash } catch {}
      }
      [void]$programs.Add([ordered]@{ name=$p.name; path=$p.path; sha1=$sha1; first_run=$p.created })
    }
  }
  foreach ($d in @("$env:PUBLIC", "$env:WINDIR\Temp", "$env:LOCALAPPDATA\Temp")) {
    if (Test-Path $d) {
      Get-ChildItem -Path $d -Filter *.exe -Recurse -ErrorAction SilentlyContinue -Force |
        Select-Object -First 50 | ForEach-Object {
          if (-not $seen.ContainsKey($_.FullName)) {
            $seen[$_.FullName] = $true
            $sha1 = ''
            try { $sha1 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA1).Hash } catch {}
            [void]$programs.Add([ordered]@{ name=$_.Name; path=$_.FullName; sha1=$sha1;
              first_run=$_.CreationTimeUtc.ToString('o') })
          }
        }
    }
  }

  # USBSTOR (removable media history)
  $usbPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
  if (Test-Path $usbPath) {
    Get-ChildItem $usbPath -ErrorAction SilentlyContinue | ForEach-Object {
      $fn = (Get-ItemProperty (Join-Path $_.PSPath '*') -Name FriendlyName -ErrorAction SilentlyContinue).FriendlyName
      if ($fn) { [void]$registry.Add([ordered]@{
        hive='HKLM'; key=($_.PSChildName); value_name='FriendlyName'; value_data="$fn";
        last_write=''; category='usbstor' }) }
    }
  }

  # scheduled tasks (as events 4698-style rows so the analyzer maps them)
  $taskEvents = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' } |
    ForEach-Object {
      $action = ($_.Actions | ForEach-Object { $_.Execute } ) -join '; '
      [ordered]@{ ts=''; event_id=4698; channel='Scheduled'; computer=$env:COMPUTERNAME;
        user=$_.Principal.UserId; process='schtasks'; parent_process=''; cmdline=$action;
        dst_ip=''; detail="Scheduled task: $($_.TaskPath)$($_.TaskName) -> $action" }
    }

  # local users + admins
  $users = Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ name=$_.Name; enabled=[bool]$_.Enabled; last_logon=
      if ($_.LastLogon) { $_.LastLogon.ToString('o') } else { '' }; groups='' }
  }
  $admins = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Name
  foreach ($u in $users) { if ($admins -contains "$env:COMPUTERNAME\$($u.name)") { $u.groups = 'Administrators' } }

  # recent events (capped) in the analyzer's normalized shape
  $events = New-Object System.Collections.ArrayList
  $after = (Get-Date).AddDays(-$Days)
  $channelCounts = @{}
  foreach ($t in $EventTargets) {
    $before = $events.Count
    try {
      Get-WinEvent -FilterHashtable @{ LogName=$t.Log; Id=$t.Ids; StartTime=$after } -MaxEvents $MaxEvents -ErrorAction Stop |
        ForEach-Object {
          $eid = [int]$_.Id
          $props = $_.Properties               # already-parsed event data; no message rendering
          $proc = ''; $parent = ''; $cmd = ''; $acct = ''
          switch ($eid) {
            4688 {  # New Process: NewProcessName, ParentProcessName, CommandLine, SubjectUserName
              if ($props.Count -ge 6)  { $proc   = [string]$props[5].Value }
              if ($props.Count -ge 9)  { $cmd    = [string]$props[8].Value }
              if ($props.Count -ge 14) { $parent = [string]$props[13].Value }
              if ($props.Count -ge 2)  { $acct   = [string]$props[1].Value }
              if ($proc)   { $proc   = ($proc   -split '\\')[-1] }
              if ($parent) { $parent = ($parent -split '\\')[-1] }
            }
            { @(4624,4625) -contains $_ } { if ($props.Count -ge 6) { $acct = [string]$props[5].Value } }
            4672 { if ($props.Count -ge 2) { $acct = [string]$props[1].Value } }
            { @(4720,4726) -contains $_ } { if ($props.Count -ge 1) { $acct = [string]$props[0].Value } }
          }
          $label = $EventLabels[$eid]; if (-not $label) { $label = "Event $eid" }
          if ($eid -eq 4688) {
            $detail = "${label}: $proc"
            if ($cmd) { $detail += " - $cmd" }
          } elseif ($acct) {
            $detail = "$label (account: $acct)"
          } else {
            $detail = $label
          }
          [void]$events.Add([ordered]@{
            ts=$_.TimeCreated.ToUniversalTime().ToString('o'); event_id=$eid; channel=$t.Log;
            computer=$env:COMPUTERNAME; user=$acct; process=$proc; parent_process=$parent;
            cmdline=$cmd; dst_ip=''; detail=$detail })
        }
    } catch {
      if ($_.Exception.Message -notmatch 'No events were found') {
        [void]$warnings.Add("Could not read '$($t.Log)' log: $($_.Exception.Message.Trim())")
      }
    }
    $channelCounts[$t.Log] = $events.Count - $before
  }
  $events += $taskEvents
  if (($channelCounts['Security'] | ForEach-Object { $_ }) -eq 0) {
    [void]$warnings.Add("ZERO Security events were collected. The Security log is the most important IR source (logons, process creation, account changes, log clearing). This usually means the collector was not elevated. Results are INCOMPLETE.")
  }

  $extra = @{ channel_counts = $channelCounts }
  if ($CollectionProfile -eq 'full') {
    $extra.dns = Get-DnsClientCache -ErrorAction SilentlyContinue |
      Select-Object Entry, Data, @{n='type';e={$_.Type}}
  }

  [ordered]@{
    host = $host_info; processes = $processes; network = $network
    registry = $registry; services = $services; users = $users
    programs = $programs; events = $events; extra = $extra
    warnings = $warnings
  }
}

# ---- write a normalized package with manifest + chain-of-custody ----
function Write-Package($result, $targetName) {
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $dir = Join-Path $OutputPath ("{0}_{1}_{2}" -f $CaseId, $targetName, $stamp)
  New-Item -ItemType Directory -Force -Path $dir | Out-Null

  $files = @{
    'events.json'    = $result.events
    'registry.json'  = $result.registry
    'processes.json' = $result.processes
    'network.json'   = $result.network
    'users.json'     = $result.users
    'services.json'  = $result.services
    'programs.json'  = $result.programs
  }
  # write UTF-8 WITHOUT a BOM (PS 5.1 `Out-File -Encoding utf8` adds one, which
  # breaks strict JSON parsers); the analyzer also reads utf-8-sig as a backstop.
  $utf8 = New-Object System.Text.UTF8Encoding($false)
  $entries = @()
  foreach ($name in $files.Keys) {
    $path = Join-Path $dir $name
    [System.IO.File]::WriteAllText($path, (($files[$name] | ConvertTo-Json -Depth 6)), $utf8)
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $entries += [ordered]@{ name=$name; sha256=$hash; count=@($files[$name]).Count }
  }

  $manifest = [ordered]@{
    case_id = $CaseId; operator = $Operator; collector_version = $CollectorVersion
    profile = $CollectionProfile; host = $result.host
    collected_at = (Get-Date).ToUniversalTime().ToString('o')
    warnings = @($result.warnings); channel_counts = $result.extra.channel_counts
    files = $entries
  }
  [System.IO.File]::WriteAllText((Join-Path $dir 'manifest.json'),
    ($manifest | ConvertTo-Json -Depth 8), $utf8)

  # surface collection warnings to the operator immediately
  foreach ($w in @($result.warnings)) { Write-Warning $w }

  $zip = "$dir.zip"
  Compress-Archive -Path "$dir\*" -DestinationPath $zip -Force
  Write-Host "  package: $zip"
  return $zip
}

# ---- run locally or fan out over WinRM ----
$OutputPath = (New-Item -ItemType Directory -Force -Path $OutputPath).FullName
Write-Host "AFA triage collector v$CollectorVersion  profile=$CollectionProfile  case=$CaseId"

if ($ComputerName) {
  foreach ($cn in $ComputerName) {
    Write-Host "collecting from $cn ..."
    try {
      $res = Invoke-Command -ComputerName $cn -ScriptBlock $CollectCore `
        -ArgumentList $CollectionProfile, $Days, $MaxEvents, $EventTargets, $HashAll -ErrorAction Stop
      Write-Package $res $cn | Out-Null
    } catch { Write-Warning "  $cn failed: $_" }
  }
} else {
  Write-Host "collecting from localhost ..."
  $res = & $CollectCore $CollectionProfile $Days $MaxEvents $EventTargets $HashAll
  Write-Package $res $env:COMPUTERNAME | Out-Null
}

Write-Host "done. Analyze with:  python -m afa.cli attack --package <package.zip>"
