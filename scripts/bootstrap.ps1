$ErrorActionPreference = 'Stop'
$appDir = Split-Path -Parent $PSScriptRoot
$dataDir = if ($env:EXPOSURE_DATA_DIR) { $env:EXPOSURE_DATA_DIR } else { Join-Path $env:LOCALAPPDATA 'Exposure Desk' }
$nodeExe = Get-Command node.exe -ErrorAction SilentlyContinue
if ($nodeExe) { $runtimeVersion = & $nodeExe.Source --version; if ($runtimeVersion -match '^v(24|25|26)\.') { & $nodeExe.Source (Join-Path $PSScriptRoot 'launch.mjs'); exit $LASTEXITCODE } }
$version = '24.18.1'
$architecture = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'x64' }
$runtimeDir = Join-Path $dataDir 'runtime'
$cachedNode = Join-Path $runtimeDir "node-v$version-win-$architecture\node.exe"
if (!(Test-Path -LiteralPath $cachedNode)) {
  Write-Host "Installing official Node.js $version for this user. No system-wide changes."
  New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
  $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $security = New-Object System.Security.AccessControl.DirectorySecurity
  $security.SetAccessRuleProtection($true, $false)
  $security.SetOwner($principal)
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit', [System.Security.AccessControl.PropagationFlags]::None, 'Allow')
  $security.AddAccessRule($rule)
  Set-Acl -LiteralPath $dataDir -AclObject $security
  $name = "node-v$version-win-$architecture.zip"
  $base = "https://nodejs.org/dist/v$version/"
  $archive = Join-Path $runtimeDir $name
  $checksums = (Invoke-WebRequest -UseBasicParsing -Uri ($base + 'SHASUMS256.txt')).Content
  $line = ($checksums -split "`n" | Where-Object { $_.Trim().EndsWith($name) } | Select-Object -First 1)
  if (!$line) { throw 'Official checksum unavailable; download refused.' }
  $expected = ($line.Trim() -split '\s+')[0]
  Invoke-WebRequest -UseBasicParsing -Uri ($base + $name) -OutFile $archive
  if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected.ToLowerInvariant()) { throw 'Node download checksum mismatch.' }
  Expand-Archive -LiteralPath $archive -DestinationPath $runtimeDir -Force
}
& $cachedNode (Join-Path $PSScriptRoot 'launch.mjs')
exit $LASTEXITCODE
