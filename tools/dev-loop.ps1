<#
.SYNOPSIS
  Sync the project to WSL and run a make target. Single-command dev loop.

.DESCRIPTION
  Saves the edit-copy-test cycle from manual `cp /mnt/c/.../...` steps:

    edit on Windows  →  .\tools\dev-loop.ps1  →  results in your terminal

  Mechanism: uses Windows-bundled `wsl.exe` to (a) rsync the project from
  /mnt/c into ~/code on the WSL ext4 filesystem (10-50× faster than working
  from /mnt/c directly), then (b) run the requested make target with sudo
  and PATH preserved so cargo + the venv stay visible.

.PARAMETER Target
  The make target to run inside WSL. Defaults to test-synthetic.
  Common: test (mock), test-gpu, test-synthetic, test-python, all.

.PARAMETER Distro
  WSL distro name. Defaults to the WSL default distro. Use `wsl --list -v`
  to see what's installed.

.PARAMETER WslRepoPath
  Where to keep the synced copy inside WSL. Defaults to ~/code/<repo-name>.

.PARAMETER NoSync
  Skip rsync. Useful when you just changed run-only files and don't need
  another sync; or to re-run the last build.

.PARAMETER Clean
  Run `make clean` before the target. Forces a full rebuild.

.PARAMETER SaveLog
  Tee the entire run output to a file on the Windows side.

.EXAMPLE
  .\tools\dev-loop.ps1
  # Sync + run `make test-synthetic`

.EXAMPLE
  .\tools\dev-loop.ps1 test-gpu -Clean
  # Clean rebuild then run real-CUDA test

.EXAMPLE
  .\tools\dev-loop.ps1 test-synthetic -SaveLog .\runs\state_v1.txt
  # Capture the validator output for later commit

.NOTES
  - Run from the repo root (so the script can find Makefile) OR from
    .\tools\ — the script auto-detects either way.
  - Requires WSL2 with rsync installed (`sudo apt-get install rsync`).
  - First sudo prompt asks for your WSL password; subsequent calls within
    the cached window (5 min by default) skip it. To eliminate the prompt
    entirely, add NOPASSWD for your user — see tools/README.md.
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Target = "test-synthetic",
    [string]$Distro = "",
    [string]$WslRepoPath = "",
    [switch]$NoSync,
    [switch]$Clean,
    [switch]$SyncOnly,        # rsync the repo + normalize, then exit — user runs make manually
    [string]$SaveLog = ""
)

# Keep Stop semantics for PS-native errors (typos, missing files), but
# DON'T let stderr output from external commands (gcc warnings, etc.)
# abort the run. PowerShell's default Stop-on-native-stderr is a known
# trap — particularly painful here because every compiler warning
# arrives via stderr.
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false   # PowerShell 7+
# For PS 5.1 (older), we additionally wrap native calls in try/catch
# blocks that drop the synthetic error record below.

# -- Locate the project root on Windows side ------------------------------

$WinRepoPath = $PSScriptRoot
if (-not (Test-Path (Join-Path $WinRepoPath "Makefile"))) {
    # Probably running from .\tools\ — go up one
    $WinRepoPath = Split-Path $WinRepoPath -Parent
}
if (-not (Test-Path (Join-Path $WinRepoPath "Makefile"))) {
    Write-Error "Can't find Makefile. Run this from the project root or .\tools\."
}

# Build the WSL-side path equivalent of the Windows path.
# C:\Users\Foo\bar  ->  /mnt/c/Users/Foo/bar
$drive = $WinRepoPath.Substring(0,1).ToLower()
$rest  = $WinRepoPath.Substring(2) -replace '\\', '/'
$WinRepoPathWsl = "/mnt/$drive$rest"

# Default destination: ~/code/<repo-basename>
if (-not $WslRepoPath) {
    $repoName = Split-Path $WinRepoPath -Leaf
    $WslRepoPath = "`$HOME/code/$repoName"   # backtick-escaped so wsl bash expands it
}

# -- Pick the distro -------------------------------------------------------
# We don't try to *detect* the default distro because wsl.exe writes
# UTF-16 output that's a pain to parse from PowerShell. If -Distro is
# omitted we just pass nothing to wsl.exe, which uses the default.

$wslDistroArgs = @()
if ($Distro) {
    $wslDistroArgs = @("-d", $Distro)
}
$DistroDisplay = if ($Distro) { $Distro } else { "(default)" }

Write-Host ""
Write-Host "=== dev-loop ===" -ForegroundColor Cyan
Write-Host "  distro       : $DistroDisplay"
Write-Host "  win  path    : $WinRepoPath"
Write-Host "  wsl  src     : $WinRepoPathWsl"
Write-Host "  wsl  dest    : $WslRepoPath"
Write-Host "  make target  : $Target"
if ($Clean)  { Write-Host "  clean        : yes" }
if ($NoSync) { Write-Host "  sync         : skipped" }
if ($SaveLog) { Write-Host "  log to       : $SaveLog" }
Write-Host ""

# -- Rsync ---------------------------------------------------------------

# Exclusions: build artifacts (regenerated in WSL), git history (huge),
# cargo target (~1 GB), python caches.
$rsyncExcludes = @(
    "--exclude=bin/",
    "--exclude=obj/",
    "--exclude=src/symbolize/target/",
    "--exclude=.git/",
    "--exclude=*.o", "--exclude=*.so", "--exclude=*.a",
    "--exclude=__pycache__/", "--exclude=*.pyc",
    "--exclude=.vscode/", "--exclude=.idea/"
) -join " "

if (-not $NoSync) {
    Write-Host "=== rsync ===" -ForegroundColor Cyan

    $rsyncBash = @"
set -e
mkdir -p $WslRepoPath
rsync -a --delete $rsyncExcludes '$WinRepoPathWsl/' '$WslRepoPath/'
echo 'rsync ok ('`$(find $WslRepoPath -type f | wc -l)' files in dest)'
"@

    & wsl.exe @wslDistroArgs -- bash -c $rsyncBash
    if ($LASTEXITCODE -ne 0) {
        Write-Error "rsync failed (exit $LASTEXITCODE). Is rsync installed? sudo apt-get install rsync"
    }
}

# -- Normalize shell scripts' line endings -------------------------------
#
# After rsync from /mnt/c, any .sh files that were saved with CRLF on
# Windows will still have CRLF in WSL. Bash chokes on `#!/usr/bin/env bash\r`
# and on `\r` accumulating onto variable values inside the script. Strip
# them once, in-place, before we invoke the runner.
$normalizeBash = 'find ' + $WslRepoPath + '/tools ' + $WslRepoPath + '/tests -type f \( -name "*.sh" -o -name "*.py" \) -exec sed -i ''s/\r$//'' {} +'
& wsl.exe @wslDistroArgs -- bash -c $normalizeBash | Out-Null

# -- Run the build/test via the in-repo runner script --------------------
#
# All the bash logic lives in tools/dev-loop-runner.sh — that file has
# real LF line endings (it was written by Write tool, not heredoc'd
# through PowerShell), and the runner handles venv activation, PATH
# cleanup, and sudo invocation. PowerShell just triggers it.
$runnerArgs = $Target
if ($Clean) { $runnerArgs += ' --clean' }
$makeBash = 'cd ' + $WslRepoPath + ' && bash tools/dev-loop-runner.sh ' + $runnerArgs

# Sync-only mode: stop here, print the manual command for the user to run.
if ($SyncOnly) {
    Write-Host ""
    Write-Host "=== sync-only: skipping test run ===" -ForegroundColor Yellow
    Write-Host "  to run the test manually inside WSL:"
    Write-Host "    wsl -- bash -c 'cd $WslRepoPath && bash tools/dev-loop-runner.sh $Target'"
    Write-Host "  or just:"
    Write-Host "    wsl"
    Write-Host "    cd ~/code/local-ai-perf-analysis"
    Write-Host "    bash tools/dev-loop-runner.sh $Target"
    exit 0
}

Write-Host ""
Write-Host "=== make $Target ===" -ForegroundColor Cyan

# Use a try/catch around the native invocation so PowerShell 5.1's
# stderr-as-error behavior doesn't kill the run on compiler warnings.
$prevPref = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    if ($SaveLog) {
        $logDir = Split-Path $SaveLog -Parent
        if ($logDir -and -not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        & wsl.exe @wslDistroArgs -- bash -c $makeBash 2>&1 | Tee-Object -FilePath $SaveLog
    } else {
        & wsl.exe @wslDistroArgs -- bash -c $makeBash 2>&1
    }
} finally {
    $ErrorActionPreference = $prevPref
}

# Trust make's exit code, not whether stderr was used.
$exit = $LASTEXITCODE
Write-Host ""
if ($exit -eq 0) {
    Write-Host "=== done (exit 0) ===" -ForegroundColor Green
} else {
    Write-Host "=== done (exit $exit) ===" -ForegroundColor Red
}
exit $exit
