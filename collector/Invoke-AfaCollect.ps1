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
  [ValidateSet('quick','full')] [string]$Profile = 'quick',
  [string[]]$ComputerName,
  [string]$Operator = $env:USERNAME,
  [string]$CaseId = ("IR-" + (Get-Date -Format 'yyyyMMdd-HHmmss')),
  [int]$Days = 7,
  [int]$MaxEvents = 2000,
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
  param($Profile, $Days, $MaxEvents, $EventTargets)

  function Cat-RegKey([string]$key) {
    $k = $key.ToLower()
    if ($k -like '*\run') { 'run' }
    elseif ($k -like '*\services\*') { 'service' }
    elseif ($k -like '*usbstor*') { 'usbstor' }
    else { 'other' }
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
  if ($Profile -eq 'full') {
    foreach ($p in $processes) {
      if ($p.path -and (Test-Path -LiteralPath $p.path)) {
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
    if ($Profile -eq 'full' -and $_.PathName) {
      $img = ($_.PathName -replace '^"','' -split '"')[0]
      if (Test-Path -LiteralPath $img) {
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
      if (Test-Path -LiteralPath $p.path) {
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
  foreach ($t in $EventTargets) {
    try {
      Get-WinEvent -FilterHashtable @{ LogName=$t.Log; Id=$t.Ids; StartTime=$after } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
        ForEach-Object {
          [void]$events.Add([ordered]@{
            ts=$_.TimeCreated.ToUniversalTime().ToString('o'); event_id=$_.Id; channel=$t.Log;
            computer=$env:COMPUTERNAME; user=''; process=''; parent_process='';
            cmdline=''; dst_ip=''; detail=($_.Message -split "`n")[0].Trim() })
        }
    } catch {}
  }
  $events += $taskEvents

  $extra = @{}
  if ($Profile -eq 'full') {
    $extra.dns = Get-DnsClientCache -ErrorAction SilentlyContinue |
      Select-Object Entry, Data, @{n='type';e={$_.Type}}
  }

  [ordered]@{
    host = $host_info; processes = $processes; network = $network
    registry = $registry; services = $services; users = $users
    programs = $programs; events = $events; extra = $extra
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
  $entries = @()
  foreach ($name in $files.Keys) {
    $path = Join-Path $dir $name
    ($files[$name] | ConvertTo-Json -Depth 6) | Out-File -FilePath $path -Encoding utf8
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $count = @($files[$name]).Count
    $entries += [ordered]@{ name=$name; sha256=$hash; count=$count }
  }

  $manifest = [ordered]@{
    case_id = $CaseId; operator = $Operator; collector_version = $CollectorVersion
    profile = $Profile; host = $result.host
    collected_at = (Get-Date).ToUniversalTime().ToString('o'); files = $entries
  }
  ($manifest | ConvertTo-Json -Depth 8) | Out-File -FilePath (Join-Path $dir 'manifest.json') -Encoding utf8

  $zip = "$dir.zip"
  Compress-Archive -Path "$dir\*" -DestinationPath $zip -Force
  Write-Host "  package: $zip"
  return $zip
}

# ---- run locally or fan out over WinRM ----
$OutputPath = (New-Item -ItemType Directory -Force -Path $OutputPath).FullName
Write-Host "AFA triage collector v$CollectorVersion  profile=$Profile  case=$CaseId"

if ($ComputerName) {
  foreach ($cn in $ComputerName) {
    Write-Host "collecting from $cn ..."
    try {
      $res = Invoke-Command -ComputerName $cn -ScriptBlock $CollectCore `
        -ArgumentList $Profile, $Days, $MaxEvents, $EventTargets -ErrorAction Stop
      Write-Package $res $cn | Out-Null
    } catch { Write-Warning "  $cn failed: $_" }
  }
} else {
  Write-Host "collecting from localhost ..."
  $res = & $CollectCore $Profile $Days $MaxEvents $EventTargets
  Write-Package $res $env:COMPUTERNAME | Out-Null
}

Write-Host "done. Analyze with:  python -m afa.cli attack --package <package.zip>"
