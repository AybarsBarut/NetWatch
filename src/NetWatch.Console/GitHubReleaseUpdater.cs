using System.Diagnostics;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetWatch.ConsoleApp;

internal static class GitHubReleaseUpdater
{
    private const string LatestReleaseUrl = "https://api.github.com/repos/AybarsBarut/NetWatch/releases/latest";
    private const long MaximumExecutableBytes = 128L * 1024 * 1024;
    private static readonly HttpClient HttpClient = CreateHttpClient();

    public static async Task<int> RunAsync(bool installUpdate, CancellationToken cancellationToken)
    {
        try
        {
            var currentVersion = GetCurrentVersion();
            var release = await GetLatestReleaseAsync(cancellationToken).ConfigureAwait(false);
            if (release.Version <= currentVersion)
            {
                Console.WriteLine($"NetWatch güncel: v{FormatVersion(currentVersion)}");
                return 0;
            }

            Console.WriteLine(
                $"Yeni NetWatch sürümü bulundu: v{FormatVersion(currentVersion)} -> v{FormatVersion(release.Version)}");
            if (!installUpdate)
            {
                Console.WriteLine("Güncellemek için: netwatch --update");
                return 0;
            }

            var executablePath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(executablePath) ||
                !string.Equals(Path.GetFileName(executablePath), "netwatch.exe", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Otomatik güncelleme yalnızca netwatch.exe olarak yayımlanmış uygulamada kullanılabilir. " +
                    "Kaynaktan çalıştırıyorsanız yeni sürümü derleyin veya kurucuyu yeniden çalıştırın.");
            }

            var stagingDirectory = Path.Combine(
                Path.GetTempPath(),
                $"netwatch-update-{Guid.NewGuid():N}");
            Directory.CreateDirectory(stagingDirectory);
            var keepStagingDirectory = false;
            try
            {
                var stagedExecutablePath = Path.Combine(stagingDirectory, "netwatch.exe");
                var checksumPath = Path.Combine(stagingDirectory, "netwatch.exe.sha256");
                await DownloadFileAsync(release.ExecutableUrl, stagedExecutablePath, MaximumExecutableBytes, cancellationToken)
                    .ConfigureAwait(false);
                await DownloadFileAsync(release.ChecksumUrl, checksumPath, 4096, cancellationToken)
                    .ConfigureAwait(false);

                var checksumText = await File.ReadAllTextAsync(checksumPath, cancellationToken).ConfigureAwait(false);
                var expectedHash = ReleaseMetadataParser.ParseChecksum(checksumText);
                await using (var executableStream = File.OpenRead(stagedExecutablePath))
                {
                    var actualHash = Convert.ToHexString(await SHA256.HashDataAsync(executableStream, cancellationToken)
                        .ConfigureAwait(false));
                    if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException("İndirilen netwatch.exe için SHA256 doğrulaması başarısız.");
                    }
                }

                var productVersion = FileVersionInfo.GetVersionInfo(stagedExecutablePath).ProductVersion;
                if (!ReleaseMetadataParser.ProductVersionMatches(productVersion, release.Version))
                {
                    throw new InvalidDataException(
                        $"İndirilen binary sürümü release etiketiyle eşleşmiyor: {productVersion ?? "bilinmiyor"}");
                }

                ScheduleReplacement(stagedExecutablePath, Path.GetFullPath(executablePath));
                keepStagingDirectory = true;
                Console.WriteLine(
                    $"NetWatch v{FormatVersion(release.Version)} doğrulandı. " +
                    "Program kapandıktan sonra güncelleme tamamlanacak; ardından netwatch komutunu yeniden çalıştırın.");
                return 0;
            }
            finally
            {
                if (!keepStagingDirectory)
                {
                    Directory.Delete(stagingDirectory, recursive: true);
                }
            }
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or InvalidDataException or
                                   IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.Error.WriteLine($"Güncelleme hatası: {ex.Message}");
            return 5;
        }
    }

    private static async Task<GitHubReleaseMetadata> GetLatestReleaseAsync(CancellationToken cancellationToken)
    {
        using var response = await HttpClient.GetAsync(LatestReleaseUrl, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ReleaseMetadataParser.Parse(json);
    }

    private static async Task DownloadFileAsync(
        Uri uri,
        string destinationPath,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        using var response = await HttpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > 0 and var contentLength && contentLength > maximumBytes)
        {
            throw new InvalidDataException($"Güncelleme dosyası izin verilen boyutu aşıyor: {uri}");
        }

        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var destination = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            81920,
            FileOptions.Asynchronous);
        var buffer = new byte[81920];
        long totalBytes = 0;
        while (true)
        {
            var bytesRead = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }

            totalBytes += bytesRead;
            if (totalBytes > maximumBytes)
            {
                throw new InvalidDataException($"Güncelleme dosyası izin verilen boyutu aşıyor: {uri}");
            }

            await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
        }
    }

    private static void ScheduleReplacement(string stagedExecutablePath, string destinationPath)
    {
        const string script = """
            $ErrorActionPreference = 'Stop'
            $targetProcessId = [int]$args[0]
            $stagedPath = $args[1]
            $destinationPath = $args[2]
            $stagingDirectory = Split-Path -Parent $stagedPath
            $backupPath = "$destinationPath.previous"
            Wait-Process -Id $targetProcessId -ErrorAction SilentlyContinue
            $updated = $false
            for ($attempt = 0; $attempt -lt 20 -and -not $updated; $attempt++) {
                try {
                    if (Test-Path -LiteralPath $destinationPath) {
                        Copy-Item -LiteralPath $destinationPath -Destination $backupPath -Force
                    }
                    Move-Item -LiteralPath $stagedPath -Destination $destinationPath -Force
                    $updated = $true
                }
                catch {
                    Start-Sleep -Milliseconds 250
                }
            }
            if ($updated) {
                Remove-Item -LiteralPath $stagingDirectory -Recurse -Force -ErrorAction SilentlyContinue
            }
            """;

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-WindowStyle");
        startInfo.ArgumentList.Add("Hidden");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);
        startInfo.ArgumentList.Add(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        startInfo.ArgumentList.Add(stagedExecutablePath);
        startInfo.ArgumentList.Add(destinationPath);

        if (Process.Start(startInfo) is null)
        {
            throw new InvalidOperationException("Güncelleme yardımcı işlemi başlatılamadı.");
        }
    }

    private static Version GetCurrentVersion() =>
        Assembly.GetEntryAssembly()?.GetName().Version ?? new Version(0, 0, 0);

    private static string FormatVersion(Version version) =>
        $"{version.Major}.{version.Minor}.{Math.Max(version.Build, 0)}";

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("NetWatch", "1.0"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return client;
    }
}

internal sealed record GitHubReleaseMetadata(
    Version Version,
    Uri ExecutableUrl,
    Uri ChecksumUrl);

internal static class ReleaseMetadataParser
{
    private static readonly Regex ReleaseVersionPattern = new(
        "^v?(?<version>\\d+\\.\\d+\\.\\d+)$",
        RegexOptions.CultureInvariant);
    private static readonly Regex ChecksumPattern = new(
        "^(?<hash>[a-fA-F0-9]{64})(?:\\s+\\*?netwatch\\.exe)?$",
        RegexOptions.CultureInvariant);

    public static GitHubReleaseMetadata Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (!root.TryGetProperty("tag_name", out var tagElement) ||
            !root.TryGetProperty("assets", out var assets) ||
            assets.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("GitHub release yanıtı gerekli alanları içermiyor.");
        }

        var tag = tagElement.GetString();
        var version = ParseReleaseVersion(tag);
        var executableUrls = FindAssetUrls(assets, "netwatch.exe");
        var checksumUrls = FindAssetUrls(assets, "netwatch.exe.sha256");
        if (executableUrls.Count != 1 || checksumUrls.Count != 1)
        {
            throw new InvalidDataException("Son GitHub release gerekli ve benzersiz NetWatch dosyalarını içermiyor.");
        }

        return new GitHubReleaseMetadata(version, executableUrls[0], checksumUrls[0]);
    }

    public static string ParseChecksum(string checksumText)
    {
        var match = ChecksumPattern.Match(checksumText.Trim());
        if (!match.Success)
        {
            throw new InvalidDataException("Release checksum dosyası geçersiz biçimde.");
        }

        return match.Groups["hash"].Value.ToUpperInvariant();
    }

    public static bool ProductVersionMatches(string? productVersion, Version releaseVersion)
    {
        if (string.IsNullOrWhiteSpace(productVersion))
        {
            return false;
        }

        var expected = $"{releaseVersion.Major}.{releaseVersion.Minor}.{releaseVersion.Build}";
        return string.Equals(productVersion, expected, StringComparison.Ordinal) ||
               productVersion.StartsWith($"{expected}+", StringComparison.Ordinal);
    }

    private static Version ParseReleaseVersion(string? tag)
    {
        var match = ReleaseVersionPattern.Match(tag ?? string.Empty);
        if (!match.Success || !Version.TryParse(match.Groups["version"].Value, out var version))
        {
            throw new InvalidDataException($"Geçersiz GitHub release etiketi: {tag ?? "boş"}");
        }

        return version;
    }

    private static List<Uri> FindAssetUrls(JsonElement assets, string expectedName)
    {
        var urls = new List<Uri>();
        foreach (var asset in assets.EnumerateArray())
        {
            if (!asset.TryGetProperty("name", out var nameElement) ||
                !string.Equals(nameElement.GetString(), expectedName, StringComparison.Ordinal))
            {
                continue;
            }

            if (!asset.TryGetProperty("browser_download_url", out var urlElement))
            {
                throw new InvalidDataException($"Release asset URL'si eksik: {expectedName}");
            }

            var value = urlElement.GetString();
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"Release asset URL'si güvenilir değil: {value ?? "boş"}");
            }

            urls.Add(uri);
        }

        return urls;
    }
}
