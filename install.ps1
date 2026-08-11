#requires -Version 5.1

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repository = if ($env:NETWATCH_REPOSITORY) { $env:NETWATCH_REPOSITORY } else { 'AybarsBarut/WireSniffer' }
if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw 'NETWATCH_REPOSITORY owner/repository biçiminde olmalıdır.'
}

$ReleaseBaseUrl = "https://github.com/$Repository/releases/latest/download"
$InstallDirectory = Join-Path $env:LOCALAPPDATA 'NetWatch'
$ExecutablePath = Join-Path $InstallDirectory 'netwatch.exe'
$NpcapVersion = '1.88'
$NpcapUrl = "https://npcap.com/dist/npcap-$NpcapVersion.exe"

function Test-Npcap {
    return $null -ne (Get-Service -Name 'npcap' -ErrorAction SilentlyContinue)
}

function Install-NpcapInteractive {
    Write-Host ''
    Write-Host 'NetWatch ham paket yakalamak için Npcap sürücüsüne ihtiyaç duyar.' -ForegroundColor Yellow
    Write-Host 'Ücretsiz Npcap lisansı sessiz kuruluma izin vermediği için resmi kurucu etkileşimli açılacaktır.' -ForegroundColor Yellow
    $answer = Read-Host 'Npcap resmi sitesinden indirilip kurulacak. Onaylıyor musunuz? (E/H)'
    if ($answer -notmatch '^[Ee]$') {
        throw 'Npcap kurulumu kullanıcı tarafından iptal edildi.'
    }

    $installerPath = Join-Path ([IO.Path]::GetTempPath()) "npcap-$NpcapVersion.exe"
    try {
        Invoke-WebRequest -Uri $NpcapUrl -OutFile $installerPath -UseBasicParsing
        $signature = Get-AuthenticodeSignature -FilePath $installerPath
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
            $signature.SignerCertificate.Subject -notmatch 'Nmap Software') {
            throw 'Npcap kurucusunun dijital imzası doğrulanamadı.'
        }

        Write-Host 'Npcap kurucusu açılıyor. Kurulum sihirbazını tamamlayın...' -ForegroundColor Cyan
        try {
            $process = Start-Process -FilePath $installerPath -Wait -PassThru
        }
        catch {
            throw 'Npcap kurucusu başlatılamadı. PowerShell penceresini yönetici olarak açıp kurulumu yeniden deneyin.'
        }

        if ($process.ExitCode -ne 0 -or -not (Test-Npcap)) {
            throw "Npcap kurulumu tamamlanamadı (çıkış kodu: $($process.ExitCode))."
        }
    }
    finally {
        Remove-Item -LiteralPath $installerPath -Force -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Npcap)) {
    Install-NpcapInteractive
}

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
$downloadPath = Join-Path ([IO.Path]::GetTempPath()) "netwatch-$PID.exe"
$checksumPath = "$downloadPath.sha256"

try {
    Write-Host 'NetWatch indiriliyor...' -ForegroundColor Cyan
    Invoke-WebRequest -Uri "$ReleaseBaseUrl/netwatch.exe" -OutFile $downloadPath -UseBasicParsing
    Invoke-WebRequest -Uri "$ReleaseBaseUrl/netwatch.exe.sha256" -OutFile $checksumPath -UseBasicParsing

    $checksumText = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
    if ($checksumText -notmatch '(?i)^([a-f0-9]{64})(?:\s+\*?netwatch\.exe)?$') {
        throw 'Yayın checksum dosyası geçersiz biçimde.'
    }

    $expectedHash = $Matches[1].ToUpperInvariant()
    $actualHash = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) {
        throw 'SHA256 doğrulaması başarısız. İndirilen dosya kurulmadı.'
    }

    Move-Item -LiteralPath $downloadPath -Destination $ExecutablePath -Force
}
finally {
    Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $checksumPath -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
if ($pathEntries -notcontains $InstallDirectory) {
    $newPath = (@($pathEntries) + $InstallDirectory) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
}

if (($env:Path -split ';') -notcontains $InstallDirectory) {
    $env:Path = "$env:Path;$InstallDirectory"
}

Write-Host ''
Write-Host 'NetWatch başarıyla kuruldu.' -ForegroundColor Green
Write-Host 'Yeni bir terminal açıp şu komutla başlayın:' -ForegroundColor White
Write-Host '  netwatch --list-interfaces' -ForegroundColor Cyan
Write-Host ''
Write-Warning 'Bu araç yalnızca kendi cihazınızda ve yasal/yetkili ağ tanılama amacıyla kullanılmalıdır.'
