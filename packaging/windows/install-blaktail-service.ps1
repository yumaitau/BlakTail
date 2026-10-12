#Requires -RunAsAdministrator
# Install the Windows BlakTail agent as a service.
# Enrol first from an elevated prompt:
#   .\blaktaild.exe up --coord https://coord.example:8443 --coord-ca C:\BlakTail\ca.crt
# Then point -Binary at that same blaktaild.exe. The service runs `run`
# and does not take a join key on the command line.
param(
  [Parameter(Mandatory = $true)]
  [string]$Binary,
  [string]$ServiceName = "BlakTail",
  # Same --coord-ca used at enrolment, when the coordinator uses a private CA.
  [string]$CoordCa,
  # blaktaild's default state directory on Windows.
  [string]$StateDir = (Join-Path $env:ProgramData "BlakTail")
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
  throw "blaktaild.exe was not found at $Binary."
}
$resolved = (Resolve-Path -LiteralPath $Binary).Path
$command = "`"$resolved`" run"
if ($CoordCa) {
  $command += " --coord-ca `"$((Resolve-Path -LiteralPath $CoordCa).Path)`""
}

# The private key and node token live here: SYSTEM and Administrators only,
# like the 0700 state directory on Linux and macOS.
if (Test-Path -LiteralPath $StateDir) {
  icacls.exe $StateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /Q | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Could not restrict access to $StateDir."
  }
}
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
  sc.exe delete $ServiceName | Out-Null
  Start-Sleep -Seconds 1
}
# New-Service takes the command line as one string. Passing it through
# sc.exe binPath= loses the embedded quotes under Windows PowerShell 5.1.
New-Service -Name $ServiceName -BinaryPathName $command -DisplayName "BlakTail" `
  -StartupType Automatic `
  -Description "Organisation private network agent. Enrolment stays in the local state directory." | Out-Null
Start-Service -Name $ServiceName
Write-Output "BlakTail service started."
Write-Output "Sign in: blaktail-windows sign-in https://console.example"
Write-Output "Send a file: blaktaild share send --url http://host:5647/label/file.txt --file .\file.txt"
