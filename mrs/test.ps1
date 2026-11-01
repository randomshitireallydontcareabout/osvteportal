$ErrorActionPreference = 'Stop'

Write-Host 'Checking Guacamole upstream...' -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri 'http://127.0.0.1:8080/guacamole/' -UseBasicParsing -TimeoutSec 15
    Write-Host "Upstream status: $($response.StatusCode)" -ForegroundColor Green
}
catch {
    Write-Host 'Guacamole is not reachable at http://127.0.0.1:8080/guacamole/' -ForegroundColor Red
    Write-Host 'Start the Guacamole Docker stack before restarting the web app.' -ForegroundColor Yellow
    throw
}

Write-Host 'The Flask proxy feature is ready. Restart the MRS web app, then open /guacamole/.' -ForegroundColor Green
