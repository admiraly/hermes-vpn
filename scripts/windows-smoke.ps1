# End-to-end smoke test on Windows: a real hermes-daemon with a real wintun
# adapter joins a relayed room with the headless echo peer
# (hermes-core/examples/echo_peer.rs), and Windows pings the peer's virtual
# IP — exercising the adapter, the L2/L3 shim, tunnels, the relay, and the
# daemon IPC. Then the same again with the daemon installed as a Windows
# service (service control + the named pipe's ACL).
#
# Run from the repo root in an elevated PowerShell after:
#   cargo build -p hermes-signaling -p hermes-relay -p hermes-daemon -p hermes-cli
#   cargo build -p hermes-core --example echo_peer
# with wintun.dll copied into target\debug.

$ErrorActionPreference = "Stop"
$Bin = (Resolve-Path "target\debug").Path
$Work = Join-Path $env:TEMP "hermes-smoke"
Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$env:RUST_LOG = "info"
$Hermes = Join-Path $Bin "hermes.exe"
$script:procs = @()

function Start-Bg($name, $exe, $arguments = @()) {
    $p = Start-Process -FilePath (Join-Path $Bin $exe) -ArgumentList $arguments -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $Work "$name.out") -RedirectStandardError (Join-Path $Work "$name.log")
    $script:procs += $p
    return $p
}

function Wait-Until($what, $seconds, [scriptblock]$cond) {
    for ($i = 0; $i -lt $seconds * 2; $i++) {
        if (& $cond) { return }
        Start-Sleep -Milliseconds 500
    }
    throw "timed out waiting for $what"
}

function Hermes([string[]]$cliArgs) {
    $out = & $Hermes @cliArgs 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "hermes $($cliArgs -join ' ') failed: $out" }
    return $out
}

# One full round: connect, create a relayed room, bring in the echo peer,
# and ping it (normal and full-MTU don't-fragment).
function Test-Round($label) {
    Wait-Until "daemon pipe ($label)" 30 { & $Hermes status *> $null; $LASTEXITCODE -eq 0 }
    Hermes @("add-server", "signaling", "local", "ws://127.0.0.1:8787/v1") | Out-Null
    Hermes @("use-signaling", "local") | Out-Null
    Hermes @("connect") | Out-Null
    $created = Hermes @("create", "smoke", "--mode", "relayed", "--relay", "127.0.0.1:8788")
    if ($created -notmatch "INVITE CODE: ([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})") { throw "no invite code in: $created" }
    $code = $Matches[1]

    $echoOut = Join-Path $Work "echo-$label.out"
    $echo = Start-Process -FilePath (Join-Path $Bin "examples\echo_peer.exe") `
        -ArgumentList @("ws://127.0.0.1:8787/v1", $code) -PassThru -NoNewWindow `
        -RedirectStandardOutput $echoOut -RedirectStandardError (Join-Path $Work "echo-$label.log")
    $script:procs += $echo
    Wait-Until "echo peer ($label)" 20 { (Test-Path $echoOut) -and ((Get-Content $echoOut -Raw) -match "ECHO-PEER") }
    $ip = ([regex]::Match((Get-Content $echoOut -Raw), "10\.42\.\d+\.\d+")).Value
    Wait-Until "relayed path to $ip ($label)" 30 { (Hermes @("status")) -match " relayed " }

    Write-Host (Hermes @("status"))
    $ok = $false
    for ($try = 0; $try -lt 5 -and -not $ok; $try++) {
        & ping.exe -n 3 -w 2000 $ip | Write-Host
        $ok = ($LASTEXITCODE -eq 0)
    }
    if (-not $ok) { throw "ping $ip failed ($label)" }
    & ping.exe -n 2 -w 2000 -l 1300 -f $ip | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "1300-byte don't-fragment ping failed ($label)" }

    Hermes @("leave") | Out-Null
    Stop-Process -Id $echo.Id -Force -ErrorAction SilentlyContinue
    Write-Host "PASS ($label): Windows reached the echo peer at $ip through wintun + relay"
}

$failed = $false
try {
    $env:HERMES_SIGNALING_BIND = "127.0.0.1:8787"
    Start-Bg "signaling" "hermes-signaling.exe" | Out-Null
    $env:HERMES_RELAY_BIND = "127.0.0.1:8788"
    Start-Bg "relay" "hermes-relay.exe" | Out-Null

    # Round 1: daemon run by hand (elevated).
    $env:HERMES_DATA_DIR = Join-Path $Work "daemon-data"
    $daemon = Start-Bg "daemon" "hermes-daemon.exe"
    Test-Round "foreground daemon"
    Stop-Process -Id $daemon.Id -Force
    Start-Sleep -Seconds 2
    Remove-Item Env:HERMES_DATA_DIR

    # Round 2: as a Windows service.
    & (Join-Path $Bin "hermes-daemon.exe") service install
    if ($LASTEXITCODE -ne 0) { throw "service install failed" }
    Test-Round "windows service"
}
catch {
    $failed = $true
    Write-Host "FAIL: $_"
}
finally {
    & (Join-Path $Bin "hermes-daemon.exe") service uninstall 2>&1 | Write-Host
    foreach ($p in $script:procs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    if ($failed) {
        Get-ChildItem $Work -Filter *.log | ForEach-Object { Write-Host "== $($_.Name)"; Get-Content $_.FullName -Tail 60 }
        $svcLog = Join-Path $env:ProgramData "Hermes\daemon.log"
        if (Test-Path $svcLog) { Write-Host "== service daemon.log"; Get-Content $svcLog -Tail 60 }
        exit 1
    }
}
