$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker is not installed or is not available in PATH.' }
docker compose version | Out-Null
$envFile = Join-Path $here '.env'
if (-not (Test-Path $envFile)) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $password = [Convert]::ToBase64String($bytes).Replace('+','A').Replace('/','B').Replace('=','C')
    "GUAC_DB_PASSWORD=$password" | Set-Content -Path $envFile -Encoding ASCII
}
$initFile = Join-Path $here 'init\001-guacamole-schema.sql'
if (-not (Test-Path $initFile)) {
    docker pull guacamole/guacamole:1.6.0
    docker run --rm guacamole/guacamole:1.6.0 /opt/guacamole/bin/initdb.sh --postgresql | Set-Content -Path $initFile -Encoding UTF8
}
docker compose up -d
Write-Host 'Guacamole started locally at http://127.0.0.1:8080/guacamole/' -ForegroundColor Green
Write-Host 'Your HTTPS reverse proxy must map /guacamole/ to this local address.' -ForegroundColor Yellow
