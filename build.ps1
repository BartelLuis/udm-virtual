<#
.SYNOPSIS
Builds the original firmware through an existing WSL distribution.
.DESCRIPTION
Relative paths refer to this script's directory. Absolute Windows drive paths
are converted with wslpath; absolute Linux paths are passed through unchanged.
The output directory must not exist. Select -Profile virtual for the gateway.
#>
param(
    [string]$Distro = 'Debian',
    [string]$Output = 'build',
    [ValidateRange(8,256)][int]$StateSizeGiB = 32,
    [ValidateSet('lab','virtual')][string]$Profile = 'lab',
    [string]$Firmware = ''
)
$ErrorActionPreference = 'Stop'

function ConvertTo-BuildLinuxPath([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'Build path must not be empty.' }
    $normalized = $Value.Replace('\', '/')
    if ($normalized -match '^[A-Za-z]:[^/]') {
        throw 'Drive-relative paths are ambiguous; use an absolute Windows path or a project-relative path.'
    }
    if ($normalized -match '^[A-Za-z]:/' -or $normalized.StartsWith('//')) {
        $converted = & wsl -d $Distro -- wslpath -a $normalized
        if ($LASTEXITCODE -ne 0) { throw "WSL path conversion failed: $Value" }
        $normalized = ($converted | Out-String).Trim()
        if (-not $normalized.StartsWith('/')) { throw "WSL returned no absolute Linux path: $Value" }
    }
    elseif ($normalized -match '^[A-Za-z]:$') {
        throw 'Use a complete absolute Windows path, not a drive name.'
    }
    return $normalized
}

$linuxRoot = ConvertTo-BuildLinuxPath $PSScriptRoot
$linuxOutput = ConvertTo-BuildLinuxPath $Output
$buildArguments = @('-d', $Distro, '--cd', $linuxRoot, '--', 'python3', 'build.py',
    '--output', $linuxOutput, '--state-size-gib', $StateSizeGiB, '--profile', $Profile)
if ($Firmware) { $buildArguments += @('--firmware', (ConvertTo-BuildLinuxPath $Firmware)) }
& wsl @buildArguments
if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE" }
