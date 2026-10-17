# Build on Windows with the repository's Rust toolchain, MSVC C++ tools and the pinned .NET SDK.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$stage = "$root\build\windows\x64"
$output = "$root\dist\windows\x64"
$target = 'x86_64-pc-windows-msvc'
# --- Helpers ---

function Run([string] $Program, [string[]] $Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed ($LASTEXITCODE): $Arguments" }
}

# --- Validation and tests ---

function Test-Code {
    Write-Host 'Checking Rust code'
    Run rustc @('--version')
    Run cargo @('fmt', '--all', '--check')
    $packages = @('-p', 'ito-shared', '-p', 'ito-agent-core', '-p', 'ito-agent-windows', '-p', 'ito-tray')
    Run cargo (@('clippy', '--locked', '--target', $target) + $packages + @('--all-targets', '--', '-D', 'warnings'))
    Run cargo (@('test', '--locked', '--target', $target) + $packages)
}

# --- Release binaries and third-party notices ---

function Build-Binaries {
    Write-Host 'Building Windows binaries'
    # Always invoke Cargo; it decides which compilation work is stale.
    Run cargo @('build', '--release', '--locked', '--target', $target, '-p', 'ito-agent-windows', '-p', 'ito-tray') | Out-Host
    $metadata = (Run cargo @('metadata', '--locked', '--no-deps', '--format-version', '1')) | ConvertFrom-Json
    $version = ($metadata.packages | Where-Object name -eq 'ito-agent-windows').version
    if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Windows packages require a three-part numeric version' }
    $builtVersion = Run "$root\target\$target\release\ito-agent.exe" @('--version')
    if ($builtVersion -ne "ito-agent $version") { throw "Stale agent binary ($builtVersion); clean the Windows release build and rebuild" }
    Copy-Item "$root\target\$target\release\ito-agent.exe", "$root\target\$target\release\ito-tray.exe", "$root\LICENSE.txt" $stage
    return $version
}
function Write-Notices {
    Write-Host 'Generating third-party notices'
    $about = "$root\build\windows\tools\bin\cargo-about.exe"
    if (-not (Test-Path $about)) {
        Run cargo @('install', '--locked', '--version', '0.9.2', '--features', 'cli', '--root', "$root\build\windows\tools", 'cargo-about')
    }
    Run $about @('generate', '--locked', '--fail', '--target', $target, '--manifest-path', 'crates/tray-windows/Cargo.toml', '--config', 'about.toml', 'about.hbs', '-o', "$stage\THIRD_PARTY_NOTICES.md")
}

# --- WireGuard MSI prerequisite ---

function Get-WireGuardMsi {
    Write-Host 'Resolving the latest WireGuard release'
    $downloads = 'https://download.wireguard.com/windows-client/'
    # Basic parsing: Windows PowerShell 5.1 otherwise needs Internet Explorer, which non-interactive
    # sessions lack.
    $listing = Invoke-WebRequest $downloads -UseBasicParsing
    $latest = [regex]::Matches($listing.Content, 'wireguard-amd64-(\d+(?:\.\d+){1,3})\.msi') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object { [version]$_ } -Unique | Select-Object -Last 1
    if (-not $latest) { throw 'No current WireGuard amd64 MSI found' }
    $wireguardName = "wireguard-amd64-$latest.msi"
    $wireguard = "$stage\$wireguardName"
    if (-not (Test-Path $wireguard)) {
        try { Invoke-WebRequest "$downloads$wireguardName" -OutFile $wireguard -UseBasicParsing }
        catch { Remove-Item $wireguard -ErrorAction SilentlyContinue; throw }
    }
    $signature = Get-AuthenticodeSignature $wireguard
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'CN=WireGuard LLC(?:,|$)') {
        Remove-Item $wireguard
        throw 'WireGuard MSI signature is not valid for WireGuard LLC'
    }
    return $wireguardName
}

# --- WiX MSI and Burn bundle ---

function New-Packages([string] $Version, [string] $WireGuardMsi) {
    Write-Host 'Building MSI and setup bundle'
    Push-Location $PSScriptRoot
    try {
        Run dotnet @('--version')
        Run dotnet @('restore', 'bundle/ItoSetup.wixproj', '--locked-mode')
        Run dotnet @('build', 'bundle/ItoSetup.wixproj', '--no-restore', '-c', 'Release', "-p:ProductVersion=$version", "-p:WireGuardMsi=$WireGuardMsi")
        Copy-Item 'package/bin/Release/Ito.msi' "$output\Ito-$Version-x64.msi"
        Copy-Item 'bundle/bin/Release/ItoSetup.exe' "$output\ItoSetup-$Version-x64.exe"
    } finally { Pop-Location }
}
function Write-Checksums([string] $Version, [string] $WireGuardMsi) {
    Write-Host 'Recording package and prerequisite hashes'
    # Build provenance only: discovery always selects the latest release on the next build.
    @{
        file = $WireGuardMsi
        sha256 = (Get-FileHash "$stage\$WireGuardMsi" -Algorithm SHA256).Hash.ToLowerInvariant()
    } | ConvertTo-Json | Set-Content "$output\wireguard.json" -Encoding utf8
    Get-FileHash "$output\Ito-$Version-x64.msi", "$output\ItoSetup-$Version-x64.exe" -Algorithm SHA256 |
        ForEach-Object { '{0}  {1}' -f $_.Hash.ToLowerInvariant(), (Split-Path $_.Path -Leaf) } |
        Set-Content "$output\SHA256SUMS" -Encoding ascii
}

# --- Build pipeline ---

New-Item -ItemType Directory -Force $stage, $output | Out-Null
Push-Location $root
$previousFlags = $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS
try {
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = '-C target-feature=+crt-static'
    Test-Code
    $version = Build-Binaries
    Write-Notices
    $wireguardName = Get-WireGuardMsi
    New-Packages $version $wireguardName
    Write-Checksums $version $wireguardName
    Write-Host "Packages: $output"
} finally {
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = $previousFlags
    Pop-Location
}
