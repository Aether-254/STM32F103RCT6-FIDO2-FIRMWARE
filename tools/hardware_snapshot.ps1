# Enumeration only: no connect, halt, reset, flash, erase, or SD writes.
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output = Join-Path $root 'build\evidence'
New-Item -ItemType Directory -Path $output -Force | Out-Null
Push-Location $root
try {
    $probeLog = Join-Path $output 'probes.log'
    $found = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        "Enumeration attempt $attempt" | Out-File -FilePath $probeLog -Append
        $lines = & uv run --locked --group hardware pyocd list --probes 2>&1
        $code = $LASTEXITCODE
        $lines | Tee-Object -FilePath $probeLog -Append
        if ($code -ne 0) { throw 'Probe enumeration failed' }
        if (($lines -join "`n") -match 'FS-00000000') { $found = $true; break }
        if ($attempt -lt 3) { Start-Sleep -Milliseconds 500 }
    }
    if (!$found) { throw 'Expected probe not visible in this snapshot; no target operation attempted' }
    & uv run --locked --group hardware pyocd list --targets --name stm32f103 2>&1 |
        Tee-Object -FilePath (Join-Path $output 'target-support.log')
    if ($LASTEXITCODE -ne 0) { throw 'Target-support enumeration failed' }
    Get-PnpDevice -PresentOnly | Where-Object {
        $_.InstanceId -like 'USB\*' -or $_.FriendlyName -match 'fido|CMSIS|DAP'
    } | Select-Object Status,Class,FriendlyName,InstanceId | ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath (Join-Path $output 'pnp.json')
    & uv run --locked --group hardware python -c `
        "import ctypes; from fido2.hid import list_descriptors; print('IsUserAnAdmin:',ctypes.windll.shell32.IsUserAnAdmin()); print('Accessible FIDO HID:',list(list_descriptors()))" 2>&1 |
        Tee-Object -FilePath (Join-Path $output 'fido-access.log')
    if ($LASTEXITCODE -ne 0) { throw 'FIDO-access enumeration failed' }
} finally { Pop-Location }
