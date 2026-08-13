#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('win-x64')]
    [string]$Runtime = 'win-x64',

    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$SolutionPath = Join-Path $RepositoryRoot 'NetWatch.sln'
$ProjectPath = Join-Path $RepositoryRoot 'src\NetWatch.Console\NetWatch.Console.csproj'
$ArtifactsRoot = Join-Path $RepositoryRoot 'artifacts'

[xml]$project = Get-Content -LiteralPath $ProjectPath -Raw
$versionNode = $project.SelectSingleNode('/Project/PropertyGroup/Version')
if ($null -eq $versionNode -or [string]::IsNullOrWhiteSpace($versionNode.InnerText)) {
    throw 'NetWatch.Console.csproj içinde Version bulunamadı.'
}

$Version = $versionNode.InnerText.Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
    throw "Geçersiz proje sürümü: $Version"
}

$ReleaseDirectory = Join-Path $ArtifactsRoot "v$Version"
$StagingDirectory = Join-Path $ArtifactsRoot ".staging-v$Version-$PID"

if (Test-Path -LiteralPath $ReleaseDirectory) {
    if (-not $Force) {
        throw "Yayın klasörü zaten var: $ReleaseDirectory. Üzerine yazmak için -Force kullanın."
    }

    Remove-Item -LiteralPath $ReleaseDirectory -Recurse -Force
}

if (Test-Path -LiteralPath $StagingDirectory) {
    Remove-Item -LiteralPath $StagingDirectory -Recurse -Force
}

New-Item -ItemType Directory -Path $StagingDirectory -Force | Out-Null

function Invoke-DotNet {
    param([Parameter(Mandatory)][string[]]$Arguments)

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet komutu başarısız oldu: dotnet $($Arguments -join ' ')"
    }
}

try {
    Invoke-DotNet @('restore', $SolutionPath)
    Invoke-DotNet @('test', $SolutionPath, '--no-restore', '-c', 'Release')
    Invoke-DotNet @(
        'publish', $ProjectPath,
        '--no-restore',
        '-c', 'Release',
        '-r', $Runtime,
        '--self-contained', 'true',
        '-p:PublishSingleFile=true',
        '-p:DebugType=None',
        '-o', $StagingDirectory
    )

    $ExecutablePath = Join-Path $StagingDirectory 'netwatch.exe'
    if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
        throw 'Yayın netwatch.exe üretmedi.'
    }

    $ReportedVersion = (& $ExecutablePath --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $ReportedVersion -notmatch "^$([regex]::Escape($Version))(?:\+|$)") {
        throw "Binary sürümü proje sürümüyle eşleşmiyor. Beklenen: $Version; gerçek: $ReportedVersion"
    }

    $HelpText = (& $ExecutablePath --help | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw 'Yayın binary yardım komutu başarısız oldu.'
    }

    $RequiredOptions = @(
        '--watch-ip',
        '--protocol',
        '--markdown-log',
        '--agent-session',
        '--jsonl',
        '--include-http-body',
        '--http-body-bytes',
        '--check-update',
        '--update'
    )
    $MissingOptions = @($RequiredOptions | Where-Object { $HelpText -notmatch [regex]::Escape($_) })
    if ($MissingOptions.Count -gt 0) {
        throw "Yayın binary gerekli seçenekleri içermiyor: $($MissingOptions -join ', ')"
    }

    New-Item -ItemType Directory -Path $ReleaseDirectory -Force | Out-Null
    $ReleaseExecutablePath = Join-Path $ReleaseDirectory 'netwatch.exe'
    Move-Item -LiteralPath $ExecutablePath -Destination $ReleaseExecutablePath

    $Hash = (Get-FileHash -LiteralPath $ReleaseExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $ChecksumPath = Join-Path $ReleaseDirectory 'netwatch.exe.sha256'
    [IO.File]::WriteAllText($ChecksumPath, "$Hash  netwatch.exe`n", [Text.Encoding]::ASCII)

    Write-Host ''
    Write-Host "NetWatch v$Version yayın paketi doğrulandı." -ForegroundColor Green
    Write-Host "  $ReleaseExecutablePath"
    Write-Host "  $ChecksumPath"
}
finally {
    Remove-Item -LiteralPath $StagingDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
