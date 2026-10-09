# Installs the freshly built installer silently and checks the result, then
# installs it again over itself (the upgrade path) and uninstalls. Run in an
# elevated PowerShell after `tauri build --config src-tauri/tauri.installer.conf.json`.
$ErrorActionPreference = "Stop"
$setup = (Get-ChildItem target/release/bundle/nsis -Filter *-setup.exe | Select-Object -First 1).FullName
if (-not $setup) { throw "no installer found" }
$dir = Join-Path $env:ProgramFiles "Hermes"

function Check($what, [bool]$ok) {
    if (-not $ok) { throw "FAILED: $what" }
    Write-Host "ok: $what"
}

function Install {
    $p = Start-Process $setup -ArgumentList "/S" -Wait -PassThru
    Check "installer exited 0 (got $($p.ExitCode))" ($p.ExitCode -eq 0)
}

function Verify-Installed {
    foreach ($f in "hermes-daemon.exe", "hermes.exe", "wintun.dll", "uninstall.exe") {
        Check "$f is installed" (Test-Path (Join-Path $dir $f))
    }
    Check "the app is installed" ([bool](Get-ChildItem $dir -Filter "*.exe" | Where-Object { $_.Name -notin "hermes-daemon.exe", "hermes.exe", "uninstall.exe" }))
    for ($i = 0; $i -lt 30; $i++) {
        $svc = Get-Service HermesDaemon -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { break }
        Start-Sleep -Seconds 1
    }
    Check "service HermesDaemon is running" ($svc -and $svc.Status -eq "Running")
    Check "service starts at boot" ((Get-CimInstance Win32_Service -Filter "Name='HermesDaemon'").StartMode -eq "Auto")
    $path = (Get-CimInstance Win32_Service -Filter "Name='HermesDaemon'").PathName
    Check "service path is quoted ($path)" ($path.StartsWith('"'))
    # The CLI talks to the service over its pipe, without elevation tricks.
    $out = & (Join-Path $dir "hermes.exe") status 2>&1 | Out-String
    Check "CLI reaches the service: $out" ($LASTEXITCODE -eq 0)
    $rule = netsh advfirewall firewall show rule name="Hermes daemon" | Out-String
    Check "firewall rule exists" ($rule -match "Hermes daemon")
}

Install
Verify-Installed

Write-Host "--- upgrade (install over the top)"
Install
Verify-Installed

Write-Host "--- uninstall"
$u = Start-Process (Join-Path $dir "uninstall.exe") -ArgumentList "/S", "_?=$dir" -Wait -PassThru
Check "uninstaller exited 0 (got $($u.ExitCode))" ($u.ExitCode -eq 0)
Check "service is gone" (-not (Get-Service HermesDaemon -ErrorAction SilentlyContinue))
Check "firewall rule is gone" ((netsh advfirewall firewall show rule name="Hermes daemon" | Out-String) -notmatch "Rule Name")
Check "daemon exe is gone" (-not (Test-Path (Join-Path $dir "hermes-daemon.exe")))
Write-Host "PASS"
# netsh (above) exits 1 when the rule it looked for is gone, which is the expected
# result; do not let that leak out as the script's exit code.
exit 0
