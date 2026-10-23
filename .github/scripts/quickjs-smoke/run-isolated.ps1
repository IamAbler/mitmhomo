param(
    [Parameter(Mandatory = $true)]
    [string]$Executable,

    [Parameter(Mandatory = $true)]
    [string]$IsolationRoot
)

$ErrorActionPreference = 'Stop'

$testDirectory = Join-Path $IsolationRoot ("m61d-quickjs-clean-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null

$isolatedExecutable = Join-Path $testDirectory 'quickjs-smoke.exe'
Copy-Item -LiteralPath $Executable -Destination $isolatedExecutable

$files = @(Get-ChildItem -LiteralPath $testDirectory -File)
if ($files.Count -ne 1 -or $files[0].Name -ne 'quickjs-smoke.exe') {
    throw "Isolation directory must contain only quickjs-smoke.exe; found $($files.Count) file(s)."
}

$system32 = Join-Path $env:SystemRoot 'System32'
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $isolatedExecutable
$startInfo.WorkingDirectory = $testDirectory
$startInfo.UseShellExecute = $false
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$startInfo.EnvironmentVariables['PATH'] = $system32

Write-Host "ISOLATED_DIRECTORY=$testDirectory"
Write-Host "ISOLATED_FILE_COUNT=$($files.Count)"
Write-Host "ISOLATED_PATH=$system32"
Write-Host 'ISOLATION_BOUNDARY=PATH is restricted, but Windows system directories and loader search rules remain available.'

$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $startInfo
if (-not $process.Start()) {
    throw 'Failed to start isolated QuickJS smoke executable.'
}

$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()
if (-not $process.WaitForExit(30000)) {
    $process.Kill()
    throw 'Isolated QuickJS smoke executable timed out after 30 seconds.'
}

$stdout = $stdoutTask.GetAwaiter().GetResult()
$stderr = $stderrTask.GetAwaiter().GetResult()
if ($stdout) {
    Write-Host $stdout.TrimEnd()
}
if ($stderr) {
    [Console]::Error.WriteLine($stderr.TrimEnd())
}
if ($process.ExitCode -ne 0) {
    throw "Isolated QuickJS smoke executable exited with code $($process.ExitCode)."
}

Write-Host 'ISOLATED_QUICKJS_SMOKE=PASS'
