# Stage everything the Windows installer bundles next to the desktop app:
# the daemon, the CLI and wintun.dll. Run from the repo root before
# `tauri build --config src-tauri/tauri.installer.conf.json` (the release
# workflow does; so can you).
#
#   pwsh packaging/windows/stage.ps1
param([string]$Out = "hermes-ui/src-tauri/installer-stage")

$ErrorActionPreference = "Stop"
# https://www.wintun.net - prebuilt, signed DLL; redistributable unmodified.
$WintunVersion = "0.14.1"
$WintunSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

cargo build --release --locked -p hermes-daemon -p hermes-cli
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

New-Item -ItemType Directory -Force $Out | Out-Null
$tmp = Join-Path ([IO.Path]::GetTempPath()) "hermes-wintun-$([guid]::NewGuid())"
New-Item -ItemType Directory $tmp | Out-Null
try {
    $zip = Join-Path $tmp "wintun.zip"
    Invoke-WebRequest "https://www.wintun.net/builds/wintun-$WintunVersion.zip" -OutFile $zip
    $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($hash -ne $WintunSha256) { throw "wintun.zip checksum mismatch: $hash" }
    Expand-Archive $zip -DestinationPath $tmp
    Copy-Item (Join-Path $tmp "wintun/bin/amd64/wintun.dll") $Out
    Copy-Item (Join-Path $tmp "wintun/LICENSE.txt") (Join-Path $Out "wintun-LICENSE.txt")
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
Copy-Item target/release/hermes-daemon.exe, target/release/hermes.exe $Out
Copy-Item LICENSE.md $Out
Get-ChildItem $Out
