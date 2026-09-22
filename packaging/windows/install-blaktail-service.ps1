# Install the Windows BlakTail agent as a service.
# Enrol first from an elevated prompt:
#   .\blaktaild.exe up --coord https://coord.example:8443 --coord-ca C:\BlakTail\ca.crt
# Then point -Binary at that same blaktaild.exe. The service runs `run`
# and does not take a join key on the command line.
param(
  [Parameter(Mandatory = $true)]
  [string]$Binary,
  [string]$ServiceName = "BlakTail"
)

$ErrorActionPreference = "Stop"
$resolved = (Resolve-Path $Binary).Path
if (-not (Test-Path $resolved)) {
  throw "blaktaild.exe was not found."
}
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
  sc.exe delete $ServiceName | Out-Null
  Start-Sleep -Seconds 1
}
sc.exe create $ServiceName binPath= "`"$resolved`" run" start= auto DisplayName= "BlakTail"
if ($LASTEXITCODE -ne 0) {
  throw "Windows could not create the BlakTail service."
}
sc.exe description $ServiceName "Organisation private network agent. Enrolment stays in the local state directory."
Start-Service -Name $ServiceName
Write-Output "BlakTail service started. Send a file with: blaktaild share send --url http://host:5647/label/file.txt --file .\file.txt"
