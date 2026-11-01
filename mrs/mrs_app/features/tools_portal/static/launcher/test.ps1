param(
    [switch]$Install,
    [switch]$Uninstall,
    [Parameter(Position = 0)]
    [string]$LaunchUrl
)

$ErrorActionPreference = 'Stop'
$ProtocolName = 'osvrdp'
$InstallDirectory = Join-Path $env:LOCALAPPDATA 'OSVRDPLauncher'
$InstalledScript = Join-Path $InstallDirectory 'test.ps1'
$ProtocolKey = "HKCU:\Software\Classes\$ProtocolName"
$SourceScript = $PSCommandPath

function Show-Message([string]$Message, [string]$Title = 'OSV Remote Access Launcher', [string]$Icon = 'Information') {
    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        [System.Windows.MessageBox]::Show($Message, $Title, 'OK', $Icon) | Out-Null
    }
    catch {
        Write-Host $Message
    }
}

function Install-Launcher {
    if ([string]::IsNullOrWhiteSpace($SourceScript) -or -not (Test-Path -LiteralPath $SourceScript)) {
        throw 'Unable to locate the launcher script. Extract the ZIP first, then run test.ps1 from the extracted folder.'
    }

    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    Copy-Item -LiteralPath $SourceScript -Destination $InstalledScript -Force

    New-Item -Path $ProtocolKey -Force | Out-Null
    Set-Item -Path $ProtocolKey -Value 'URL:OSV Remote Desktop Launcher'
    New-ItemProperty -Path $ProtocolKey -Name 'URL Protocol' -Value '' -PropertyType String -Force | Out-Null

    $iconKey = "$ProtocolKey\DefaultIcon"
    New-Item -Path $iconKey -Force | Out-Null
    Set-Item -Path $iconKey -Value "$env:SystemRoot\System32\mstsc.exe,0"

    $commandKey = "$ProtocolKey\shell\open\command"
    New-Item -Path $commandKey -Force | Out-Null
    $command = 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" "%1"' -f $InstalledScript
    Set-Item -Path $commandKey -Value $command

    $registered = (Get-Item -Path $commandKey).GetValue('')
    if ($registered -ne $command) {
        throw 'The protocol registration could not be verified.'
    }

    Show-Message "OSV Remote Access Launcher was installed for the current Windows user.`n`nReturn to the web portal, enter a target, and click Launch Remote Desktop."
}

function Uninstall-Launcher {
    if (Test-Path $ProtocolKey) {
        Remove-Item -Path $ProtocolKey -Recurse -Force
    }
    if (Test-Path $InstallDirectory) {
        Remove-Item -Path $InstallDirectory -Recurse -Force
    }
    Show-Message 'OSV Remote Access Launcher was removed.'
}

function Get-QueryValues([uri]$Uri) {
    $values = @{}
    foreach ($pair in $Uri.Query.TrimStart('?') -split '&') {
        if (-not $pair) { continue }
        $parts = $pair -split '=', 2
        $key = [uri]::UnescapeDataString($parts[0]).ToLowerInvariant()
        $value = if ($parts.Count -gt 1) { [uri]::UnescapeDataString($parts[1]) } else { '' }
        $values[$key] = $value
    }
    return $values
}

function Test-ApprovedHost([string]$HostName) {
    if ([string]::IsNullOrWhiteSpace($HostName) -or $HostName.Length -gt 253) { return $false }
    if ($HostName -notmatch '^[A-Za-z0-9.-]+$') { return $false }

    $parsedIp = $null
    if ([System.Net.IPAddress]::TryParse($HostName, [ref]$parsedIp)) {
        if ($parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
        return (
            $HostName -match '^10\.' -or
            $HostName -match '^192\.168\.' -or
            $HostName -match '^172\.(1[6-9]|2[0-9]|3[01])\.'
        )
    }

    return $HostName -match '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'
}

function Start-RdpFromUrl([string]$UrlText) {
    if ([string]::IsNullOrWhiteSpace($UrlText)) { throw 'No launch URL was supplied.' }

    $uri = [uri]$UrlText
    if ($uri.Scheme -ne $ProtocolName) { throw 'The URL does not use the approved osvrdp protocol.' }

    $query = Get-QueryValues $uri
    $hostName = $query['host']
    $portText = if ($query.ContainsKey('port')) { $query['port'] } else { '3389' }
    $displayMode = if ($query.ContainsKey('mode')) { $query['mode'].ToLowerInvariant() } else { 'fullscreen' }

    if (-not (Test-ApprovedHost $hostName)) {
        throw 'The host is invalid. Use a private IPv4 address or an approved hostname.'
    }

    $port = 0
    if (-not [int]::TryParse($portText, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw 'The RDP port must be between 1 and 65535.'
    }

    $mstsc = Join-Path $env:SystemRoot 'System32\mstsc.exe'
    if (-not (Test-Path -LiteralPath $mstsc)) { throw 'Windows Remote Desktop Connection was not found.' }

    $arguments = New-Object System.Collections.Generic.List[string]
    $arguments.Add("/v:$hostName`:$port")
    if ($displayMode -eq 'fullscreen') { $arguments.Add('/f') }
    if ($query.ContainsKey('multimon') -and $query['multimon'] -eq '1') { $arguments.Add('/multimon') }
    if ($query.ContainsKey('admin') -and $query['admin'] -eq '1') { $arguments.Add('/admin') }

    Start-Process -FilePath $mstsc -ArgumentList $arguments.ToArray()
}

try {
    if ($Install) { Install-Launcher }
    elseif ($Uninstall) { Uninstall-Launcher }
    elseif ($LaunchUrl) { Start-RdpFromUrl $LaunchUrl }
    else {
        Write-Host 'Install with:' -ForegroundColor Cyan
        Write-Host 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test.ps1 -Install'
    }
}
catch {
    Show-Message $_.Exception.Message 'OSV Remote Access Launcher' 'Error'
    exit 1
}
