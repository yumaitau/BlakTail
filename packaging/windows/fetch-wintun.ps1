# Fetch the official WinTun driver DLL and place it beside blaktaild.exe.
#
# blaktaild loads wintun.dll only from its own directory. This downloads the
# WinTun 0.14.1 release from wintun.net, refuses it unless the zip matches the
# pinned SHA-256 (the value published on https://www.wintun.net), extracts the
# DLL for this machine's architecture, checks its SHA-256 and its WireGuard LLC
# Authenticode signature, and copies it to -Destination.
#
#   .\fetch-wintun.ps1 -Destination C:\Path\To\BlakTail
#   .\fetch-wintun.ps1 -Destination .\dist -Arch arm64
#   .\fetch-wintun.ps1 -Destination .\dist -ZipPath .\wintun-0.14.1.zip   # offline
param(
  [Parameter(Mandatory = $true)]
  [string]$Destination,
  [ValidateSet("amd64", "arm64", "x86", "arm")]
  [string]$Arch,
  # A previously downloaded wintun-0.14.1.zip; it is verified the same way.
  [string]$ZipPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3

$Version = "0.14.1"
$Url = "https://www.wintun.net/builds/wintun-$Version.zip"
# Published on https://www.wintun.net next to the download.
$ZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
# wintun/bin/<arch>/wintun.dll inside that zip.
$DllSha256 = @{
  amd64 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
  arm64 = "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"
  x86   = "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931"
  arm   = "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9"
}

if (-not $Arch) {
  $machine = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  $Arch = switch ($machine) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    "x86" { "x86" }
    default { throw "Unknown processor architecture '$machine'; pass -Arch." }
  }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("blaktail-wintun-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  if ($ZipPath) {
    $zip = (Resolve-Path -LiteralPath $ZipPath).Path
  } else {
    $zip = Join-Path $work "wintun-$Version.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Write-Output "Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $zip -UseBasicParsing
  }
  $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $ZipSha256) {
    throw "wintun-$Version.zip SHA-256 is $actual, expected $ZipSha256. Not using it."
  }

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $entryName = "wintun/bin/$Arch/wintun.dll"
  $extracted = Join-Path $work "wintun.dll"
  $archive = [IO.Compression.ZipFile]::OpenRead($zip)
  try {
    $entry = $archive.Entries | Where-Object { $_.FullName -eq $entryName } | Select-Object -First 1
    if (-not $entry) { throw "$entryName is missing from the WinTun zip." }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $extracted, $true)
  } finally {
    $archive.Dispose()
  }

  $dllHash = (Get-FileHash -LiteralPath $extracted -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($dllHash -ne $DllSha256[$Arch]) {
    throw "wintun.dll ($Arch) SHA-256 is $dllHash, expected $($DllSha256[$Arch])."
  }
  $signature = Get-AuthenticodeSignature -LiteralPath $extracted
  if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch "CN=WireGuard LLC") {
    throw "wintun.dll is not validly signed by WireGuard LLC ($($signature.Status))."
  }

  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  $target = Join-Path (Resolve-Path -LiteralPath $Destination).Path "wintun.dll"
  Copy-Item -LiteralPath $extracted -Destination $target -Force
  Write-Output "wintun.dll $Version ($Arch) verified and copied to $target"
  Write-Output "SHA-256 $dllHash"
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
