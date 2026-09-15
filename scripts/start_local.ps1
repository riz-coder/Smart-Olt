param([switch]$DatabaseOnly)
$ErrorActionPreference = 'Stop'
$appRoot = Split-Path -Parent $PSScriptRoot
$pgRoot = Join-Path (Split-Path -Parent $appRoot) 'postgres-local'
$pgCtl = Join-Path $pgRoot 'pgsql\bin\pg_ctl.exe'
$pgData = Join-Path $pgRoot 'data'
if (-not (Test-Path -LiteralPath $pgCtl) -or -not (Test-Path -LiteralPath (Join-Path $pgData 'PG_VERSION'))) {
    throw 'Local PostgreSQL has not been initialized. See docs/PostgreSQL_Deployment.md.'
}
& $pgCtl -D $pgData status *> $null
if ($LASTEXITCODE -ne 0) {
    $pgArguments = '-D "{0}" -l "{1}" -w start' -f $pgData, (Join-Path $pgRoot 'server.log')
    $pgProcess = Start-Process -FilePath $pgCtl -ArgumentList $pgArguments -WindowStyle Hidden -Wait -PassThru
    if ($pgProcess.ExitCode -ne 0) { throw 'PostgreSQL failed to start. Check postgres-local/server.log.' }
}
if ($DatabaseOnly) { return }
$appPython = Join-Path $appRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $appPython)) {
    $appPython = Join-Path (Split-Path -Parent $appRoot) 'myvenv\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $appPython)) { throw 'Install the Python environment and requirements first.' }
Set-Location -LiteralPath $appRoot
& $appPython manage.py runserver
exit $LASTEXITCODE
