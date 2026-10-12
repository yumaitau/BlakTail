#Requires -RunAsAdministrator
# Install (or with -Uninstall remove) the Windows BlakTail agent service.
#
# Enrol first from an elevated prompt, with wintun.dll beside blaktaild.exe
# (fetch-wintun.ps1 puts it there):
#   .\blaktaild.exe up --coord https://coord.example:8443 --coord-ca C:\BlakTail\ca.crt
# Stop that console agent with Ctrl+C once it reports "joined", then:
#   .\install-blaktail-service.ps1 -Binary .\blaktaild.exe -CoordCa C:\BlakTail\ca.crt
#
# The service runs `blaktaild run --service`, never takes a join key on the
# command line, logs to blaktaild.log in the state directory, and on stop
# removes its MagicDNS rule, routes and WinTun adapter.
param(
  [string]$Binary,
  [string]$ServiceName = "BlakTail",
  # Same --coord-ca used at enrolment, when the coordinator uses a private CA.
  [string]$CoordCa,
  # blaktaild's default state directory on Windows.
  [string]$StateDir = (Join-Path $env:ProgramData "BlakTail"),
  # A wintun.dll to copy beside blaktaild.exe first (it is verified either way).
  [string]$Wintun,
  # Stop and delete the service and its firewall rule. Enrolment and state
  # stay; run `blaktaild down` to revoke the node.
  [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3

# wintun.dll 0.14.1 (https://www.wintun.net), per architecture; see fetch-wintun.ps1.
$WintunSha256 = @(
  "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce", # amd64
  "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80", # arm64
  "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931", # x86
  "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9"  # arm
)
$FirewallRule = "BlakTail-$ServiceName-WireGuard"

function Remove-BlakTailService {
  $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($existing) {
    if ($existing.Status -ne "Stopped") {
      Stop-Service -Name $ServiceName -Force
      $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(60))
    }
    sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete $ServiceName failed ($LASTEXITCODE)." }
    for ($i = 0; $i -lt 20 -and (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue); $i++) {
      Start-Sleep -Milliseconds 500
    }
  }
  Get-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

if ($Uninstall) {
  Remove-BlakTailService
  Write-Output "BlakTail service $ServiceName removed. State in $StateDir is kept; 'blaktaild down' revokes the node."
  return
}

if (-not $Binary) { throw "-Binary is required (path to blaktaild.exe)." }
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
  throw "blaktaild.exe was not found at $Binary."
}
$resolved = (Resolve-Path -LiteralPath $Binary).Path
$binaryDir = Split-Path -Parent $resolved

# blaktaild loads wintun.dll only from its own directory.
$dll = Join-Path $binaryDir "wintun.dll"
if ($Wintun) {
  Copy-Item -LiteralPath (Resolve-Path -LiteralPath $Wintun).Path -Destination $dll -Force
}
if (-not (Test-Path -LiteralPath $dll -PathType Leaf)) {
  throw "wintun.dll is missing beside $resolved. Run: .\fetch-wintun.ps1 -Destination `"$binaryDir`""
}
$dllHash = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant()
if ($WintunSha256 -notcontains $dllHash) {
  throw "$dll is not the WinTun 0.14.1 release (SHA-256 $dllHash). Run fetch-wintun.ps1."
}
$signature = Get-AuthenticodeSignature -LiteralPath $dll
if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch "CN=WireGuard LLC") {
  throw "$dll is not validly signed by WireGuard LLC ($($signature.Status))."
}

$command = "`"$resolved`" run --service=$ServiceName"
if ($CoordCa) {
  $command += " --coord-ca `"$((Resolve-Path -LiteralPath $CoordCa).Path)`""
}
if ($StateDir -ne (Join-Path $env:ProgramData "BlakTail")) {
  $command += " --state-dir `"$StateDir`""
}

# The private key and node token live here: SYSTEM and Administrators only,
# like the 0700 state directory on Linux and macOS. blaktaild applies the
# same ACL itself; this also covers files left by older builds.
if (-not (Test-Path -LiteralPath (Join-Path $StateDir "state.json"))) {
  throw "No enrolment in $StateDir. Run 'blaktaild up' from an elevated prompt first."
}
function Invoke-Icacls {
  icacls.exe @args | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not restrict access to $StateDir (icacls $args)." }
}
Invoke-Icacls $StateDir /setowner "*S-1-5-32-544" /T /C /Q
# Protect the directory itself, then make everything inside inherit from it.
# (Granting "(OI)(CI)" with /T would leave files whose entries were all
# inherited with an empty ACL that nobody, the service included, can open.)
Invoke-Icacls $StateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /Q
if (Get-ChildItem -LiteralPath $StateDir -Force) {
  Invoke-Icacls (Join-Path $StateDir "*") /reset /T /C /Q
}

Remove-BlakTailService

# New-Service takes the command line as one string. Passing it through
# sc.exe binPath= loses the embedded quotes under Windows PowerShell 5.1.
New-Service -Name $ServiceName -BinaryPathName $command -DisplayName "BlakTail" `
  -StartupType Automatic `
  -Description "Organisation private network agent. Enrolment stays in the local state directory." | Out-Null
# Restart after a crash: 5 s, then 30 s, then every 60 s; reset after a day.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe failure $ServiceName failed ($LASTEXITCODE)." }

# Direct WireGuard paths need inbound UDP to the agent's socket.
New-NetFirewallRule -Name $FirewallRule -DisplayName "BlakTail agent ($ServiceName) WireGuard UDP" `
  -Direction Inbound -Program $resolved -Protocol UDP -Action Allow -Profile Any | Out-Null

Start-Service -Name $ServiceName
$service = Get-Service -Name $ServiceName
try {
  $service.WaitForStatus("Running", [TimeSpan]::FromSeconds(60))
} catch {
  throw "Service $ServiceName did not reach Running; see $(Join-Path $StateDir 'blaktaild.log')."
}
Write-Output "BlakTail service $ServiceName is running. Log: $(Join-Path $StateDir 'blaktaild.log')"
Write-Output "Sign in: blaktail-windows sign-in https://console.example"
Write-Output "Send a file: blaktaild share send --url http://host:5647/label/file.txt --file .\file.txt"
