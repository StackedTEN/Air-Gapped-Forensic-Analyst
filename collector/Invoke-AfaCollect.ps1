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
  quick   host, processes, network, autoruns, services, tasks, users, recent events,
          WMI subscriptions, prefetch, file-system timeline (user-writable dirs), browser downloads
  full    quick + image-file hashes + DNS cache + shimcache/amcache offline-parse note

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

  # processes (read-only): pid, ppid, image, command line, owner
  $processes = Get-CimInstance Win32_Process | ForEach-Object {
    $owner = ($_ | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue)
    [ordered]@{
      pid = $_.ProcessId; ppid = $_.ParentProcessId
      name = $_.Name; path = $_.ExecutablePath; cmdline = $_.CommandLine
      user = if ($owner.User) { "$($owner.Domain)\$($owner.User)" } else { '' }
      created = if ($_.CreationDate) { $_.CreationDate.ToString('o') } else { '' }
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

  # --- deeper forensic sources (read-only live triage) ---------------------

  # WMI event-subscription persistence (T1546.003): filter -> consumer bindings.
  $wmi = New-Object System.Collections.ArrayList
  try {
    $filters   = @(Get-WmiObject -Namespace 'root\subscription' -Class __EventFilter -ErrorAction Stop)
    $consumers = @(Get-WmiObject -Namespace 'root\subscription' -Class __EventConsumer -ErrorAction SilentlyContinue)
    foreach ($b in @(Get-WmiObject -Namespace 'root\subscription' -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue)) {
      $fref = "$($b.Filter)"; $cref = "$($b.Consumer)"
      $f = $filters   | Where-Object { $fref -like "*Name=`"$($_.Name)`"*" } | Select-Object -First 1
      $c = $consumers | Where-Object { $cref -like "*Name=`"$($_.Name)`"*" } | Select-Object -First 1
      $cmd = ''
      if ($c) { $cmd = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ScriptText) { $c.ScriptText } else { '' } }
      [void]$wmi.Add([ordered]@{
        filter_name = if ($f) { $f.Name } else { '' }
        consumer_name = if ($c) { $c.Name } else { '' }
        consumer_type = if ($c) { $c.__CLASS } else { '' }
        query = if ($f) { "$($f.Query)" } else { '' }
        command = "$cmd" })
    }
  } catch {
    if ($_.Exception.Message -notmatch 'Invalid namespace') {
      [void]$warnings.Add("Could not enumerate WMI subscriptions: $($_.Exception.Message.Trim())")
    }
  }

  # Prefetch (read-only listing): execution evidence. Full run-count parsing is an
  # offline step; live triage records first/last run from the .pf file timestamps.
  $prefetch = New-Object System.Collections.ArrayList
  $pfDir = Join-Path $env:WINDIR 'Prefetch'
  if (Test-Path $pfDir) {
    Get-ChildItem -Path $pfDir -Filter *.pf -ErrorAction SilentlyContinue |
      Select-Object -First 512 | ForEach-Object {
        [void]$prefetch.Add([ordered]@{
          name = ($_.BaseName -split '-')[0]; path = ''; run_count = ''
          last_run = $_.LastWriteTimeUtc.ToString('o'); first_run = $_.CreationTimeUtc.ToString('o')
          prefetch_file = $_.Name })
      }
  } elseif ($isAdmin) {
    [void]$warnings.Add("Prefetch is empty or disabled (SysMain off); execution-frequency evidence unavailable.")
  }

  # File-system timeline of user-writable locations — a pragmatic $MFT subset that
  # pins dropper first-write times. Full $MFT parsing (MFTECmd) is an offline ingest path.
  $filesystem = New-Object System.Collections.ArrayList
  foreach ($d in @("$env:PUBLIC", "$env:WINDIR\Temp", "$env:LOCALAPPDATA\Temp",
                   "$env:ProgramData", "$env:USERPROFILE\Downloads")) {
    if (Test-Path $d) {
      Get-ChildItem -Path $d -Recurse -File -ErrorAction SilentlyContinue -Force |
        Select-Object -First 200 | ForEach-Object {
          [void]$filesystem.Add([ordered]@{
            path = $_.FullName; name = $_.Name
            created = $_.CreationTimeUtc.ToString('o'); modified = $_.LastWriteTimeUtc.ToString('o')
            mft_modified = ''; size = [int64]$_.Length; is_directory = $false })
        }
    }
  }

  # Browser delivery evidence. Live history DBs are locked by the running browser;
  # triage records the Downloads folder as a delivery proxy. Full URLs/referrers are
  # an offline ingest path (e.g. BrowsingHistoryView CSV -> `--browser`).
  $browser = New-Object System.Collections.ArrayList
  $dlDir = "$env:USERPROFILE\Downloads"
  if (Test-Path $dlDir) {
    Get-ChildItem -Path $dlDir -File -ErrorAction SilentlyContinue |
      Select-Object -First 200 | ForEach-Object {
        [void]$browser.Add([ordered]@{
          type = 'download'; url = ''; title = $_.Name
          timestamp = $_.CreationTimeUtc.ToString('o'); target_path = $_.FullName; browser = '(downloads folder)' })
      }
  }

  # Shimcache/Amcache: AppCompatCache is a binary registry blob and Amcache.hve is
  # locked live; both are parsed offline. Record presence and point to the ingest path.
  $shimcache = @()
  if ($CollectionProfile -eq 'full' -and
      (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache')) {
    [void]$warnings.Add("Shimcache/Amcache need offline parsing (AppCompatCacheParser / AmcacheParser); none parsed live. Ingest the parsed CSV with --shimcache.")
  }

  # recent events (capped) in the analyzer's normalized shape
  $events = New-Object System.Collections.ArrayList
  $after = (Get-Date).AddDays(-$Days)
  $channelCounts = @{}
  foreach ($t in $EventTargets) {
    $before = $events.Count
    try {
      Get-WinEvent -FilterHashtable @{ LogName=$t.Log; Id=$t.Ids; StartTime=$after } -MaxEvents $MaxEvents -ErrorAction Stop |
        ForEach-Object {
          [void]$events.Add([ordered]@{
            ts=$_.TimeCreated.ToUniversalTime().ToString('o'); event_id=$_.Id; channel=$t.Log;
            computer=$env:COMPUTERNAME; user=''; process=''; parent_process='';
            cmdline=''; dst_ip=''; detail=($_.Message -split "`n")[0].Trim() })
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
    prefetch = $prefetch; shimcache = $shimcache; filesystem = $filesystem
    browser = $browser; wmi = $wmi
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
    'prefetch.json'  = $result.prefetch
    'shimcache.json' = $result.shimcache
    'filesystem.json'= $result.filesystem
    'browser.json'   = $result.browser
    'wmi.json'       = $result.wmi
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
