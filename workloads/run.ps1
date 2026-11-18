<#
.SYNOPSIS
  Run one workload scenario under etw-collector and print the joined report.

.EXAMPLE
  # elevated PowerShell, from the repo root
  .\workloads\run.ps1 -Scenario .\workloads\scenarios\w0_single_request_sweep.json -Model llama3.2:3b -Duration 120

.NOTES
  The collector records for a fixed -Duration (seconds) because it has no
  remote stop. Set it a little longer than the scenario takes; the report
  says how many requests fell inside the trace. Use -NoCollector for a
  timing-only run (no elevation needed).
#>
param(
    [Parameter(Mandatory = $true)][string]$Scenario,
    [Parameter(Mandatory = $true)][string]$Model,
    [string]$Backend = (Join-Path $PSScriptRoot "backends\ollama.json"),
    [int]$Duration = 180,
    [string]$OutDir = (Join-Path $PSScriptRoot "..\runs\workloads"),
    [string]$Tag = "",
    [ValidateSet("off", "sample", "full")][string]$Stacks = "off",
    [switch]$NoCollector,
    [string]$Python = "python"
)
$ErrorActionPreference = "Stop"

$name = [IO.Path]::GetFileNameWithoutExtension($Scenario)
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$run = if ($Tag) { "$name-$Tag-$stamp" } else { "$name-$stamp" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = Join-Path (Resolve-Path $OutDir).Path $run

$collector = Join-Path $PSScriptRoot "..\windows\etw-collector\target\release\etw-collector.exe"
$proc = $null
if (-not $NoCollector) {
    if (-not (Test-Path $collector)) {
        throw "etw-collector.exe not found at $collector. Build it (cargo build --release) or pass -NoCollector."
    }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        Write-Warning "Not elevated: the collector will record GPU spans only (no CPU scheduling, faults or TCP)."
    }
    $be = Get-Content $Backend -Raw | ConvertFrom-Json
    $cargs = @()
    # Trace the agent as well as the backend: the driver (and the tools and
    # hogs it spawns) is a Python process, and the collector samples Python
    # stacks only in processes it was told to trace.
    $names = @($be.process_names) + @("python", [IO.Path]::GetFileNameWithoutExtension($Python)) | Select-Object -Unique
    foreach ($n in $names) { $cargs += @("--process-name", $n) }
    $cargs += @("--follow-children", "--duration", "$Duration", "--output", "$out.json", "--save-raw", "$out.raw.jsonl")
    if ($Stacks -ne "off") { $cargs += "--stacks=$Stacks" }
    # Start-Process does not quote arguments; paths here can contain spaces.
    $argline = ($cargs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $proc = Start-Process -FilePath $collector -ArgumentList $argline -NoNewWindow -PassThru `
        -RedirectStandardError "$out.collector.log"
    Start-Sleep -Seconds 3   # let the ETW sessions start before the first request
}

& $Python (Join-Path $PSScriptRoot "driver.py") $Scenario --backend $Backend --model $Model --out $out
$rc = $LASTEXITCODE

$report = Join-Path $PSScriptRoot "report.py"
if ($proc) {
    Write-Host "waiting for the collector to finish its $Duration s window ..."
    $proc.WaitForExit()
    Get-Content "$out.collector.log" -Tail 25
    & $Python $report "$out.sidecar.jsonl" --trace "$out.json" --raw "$out.raw.jsonl" --csv "$out.csv"
} else {
    & $Python $report "$out.sidecar.jsonl" --csv "$out.csv"
}
Write-Host "outputs: $out.*"
exit $rc
