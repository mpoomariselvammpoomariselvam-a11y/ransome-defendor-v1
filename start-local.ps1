$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backend = Join-Path $root "Backend\ransome_backend"
$python = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
  $python = Join-Path $root "Backend\.venv\Scripts\python.exe"
}
if (-not (Test-Path $python)) {
  Write-Error "Python venv not found. Create one in Backend\ransome_backend and install requirements.txt."
  exit 1
}
Set-Location $backend
& $python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
