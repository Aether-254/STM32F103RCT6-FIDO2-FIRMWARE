param(
    [ValidateSet('Debug','Release')][string]$Configuration = 'Debug',
    [switch]$RunTests
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dev = [IO.Path]::GetFullPath((Join-Path $root '..'))
$toolchain = Join-Path $dev 'ARMGNUToolchain\bin'
$ninja = Join-Path $dev 'ninja.exe'
if (!(Test-Path -LiteralPath (Join-Path $toolchain 'arm-none-eabi-gcc.exe'))) { throw 'ARM compiler missing' }
if (!(Test-Path -LiteralPath $ninja)) { throw 'Ninja missing' }
$msp = Get-Content -LiteralPath (Join-Path $root 'Core\Src\stm32f1xx_hal_msp.c') -Raw
$mspCode = [regex]::Replace($msp, '(?s)/\*.*?\*/|//[^\r\n]*', '')
if ($mspCode -match '__HAL_AFIO_REMAP_SWJ_DISABLE\s*\(' -or
    $mspCode -notmatch '__HAL_AFIO_REMAP_SWJ_NOJTAG\s*\(') { throw 'SWD preservation guard failed' }
$ioc = Get-Content -LiteralPath (Join-Path $root 'fido2-key.ioc') -Raw
if ($ioc -match 'No_Debug' -or $ioc -notmatch 'PA13.Signal=SYS_JTMS-SWDIO' -or
    $ioc -notmatch 'PA14.Signal=SYS_JTCK-SWCLK') { throw 'CubeMX debug pin configuration unsafe' }
$oldPath = $env:PATH
$env:PATH = "$toolchain;$dev;$env:PATH"
Push-Location $root
try {
    $evidence = Join-Path $root 'build\evidence'
    New-Item -ItemType Directory -Path $evidence -Force | Out-Null
    & cmake --preset $Configuration "-DCMAKE_MAKE_PROGRAM=$($ninja.Replace('\','/'))" 2>&1 |
        Tee-Object -FilePath (Join-Path $evidence "configure-$Configuration.log")
    if ($LASTEXITCODE -ne 0) { throw 'CMake configure failed' }
    & cmake --build --preset $Configuration 2>&1 |
        Tee-Object -FilePath (Join-Path $evidence "build-$Configuration.log")
    if ($LASTEXITCODE -ne 0) { throw 'Firmware build failed' }
    # Read the ACTUAL link map, not only linker-script source. Reserved pages
    # must stay outside the application region; this guard never accesses target.
    $mapPath = Join-Path $root "build\$Configuration\fido2-key.map"
    $mapText = Get-Content -LiteralPath $mapPath -Raw
    foreach ($region in @(
        @{ Name='FLASH'; Origin='08000000'; Length='0003e800' },
        @{ Name='KEYROOT'; Origin='0803e800'; Length='00000800' },
        @{ Name='KEYJOURNAL'; Origin='0803f000'; Length='00001000' }
    )) {
        $pattern = '(?m)^' + $region.Name + '\s+0x' + $region.Origin + '\s+0x' + $region.Length + '\s'
        if ($mapText -notmatch $pattern) { throw "Unexpected link map partition: $($region.Name)" }
    }
    @{
        map=$mapPath; application_start='0x08000000'; application_end='0x0803e800';
        root_start='0x0803e800'; root_end='0x0803f000';
        journal_start='0x0803f000'; journal_end='0x08040000'; hardware_writes=$false
    } | ConvertTo-Json | Out-File -FilePath (Join-Path $evidence "layout-$Configuration.json")
    $elf = Join-Path $root "build\$Configuration\fido2-key.elf"
    $bin = Join-Path $root "build\$Configuration\fido2-key.bin"
    & (Join-Path $toolchain 'arm-none-eabi-objcopy.exe') -O binary $elf $bin
    if ($LASTEXITCODE -ne 0) { throw 'Binary extraction failed' }
    & (Join-Path $toolchain 'arm-none-eabi-size.exe') $elf 2>&1 |
        Tee-Object -FilePath (Join-Path $evidence "size-$Configuration.log")
    if ($LASTEXITCODE -ne 0) { throw 'Size inspection failed' }
    Get-FileHash -LiteralPath $elf,$bin -Algorithm SHA256 | Format-List |
        Out-File -FilePath (Join-Path $evidence "hashes-$Configuration.txt")
    if ($RunTests) {
        & uv run --locked --group test python -m pytest tests -q --maxfail=1 `
            --junitxml=build/evidence/host-tests.xml 2>&1 |
            Tee-Object -FilePath (Join-Path $evidence 'host-tests.log')
        if ($LASTEXITCODE -ne 0) { throw 'Host tests failed' }
    }
    Write-Output 'Local build finished. NO firmware was downloaded and NO hardware was written.'
} finally {
    Pop-Location
    $env:PATH = $oldPath
}
