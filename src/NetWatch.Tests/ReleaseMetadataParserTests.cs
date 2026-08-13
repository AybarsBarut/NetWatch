using NetWatch.ConsoleApp;

namespace NetWatch.Tests;

public sealed class ReleaseMetadataParserTests
{
    [Fact]
    public void ParseReadsVersionAndRequiredAssets()
    {
        const string json = """
            {
              "tag_name": "v0.2.0",
              "assets": [
                {
                  "name": "netwatch.exe",
                  "browser_download_url": "https://github.com/AybarsBarut/NetWatch/releases/download/v0.2.0/netwatch.exe"
                },
                {
                  "name": "netwatch.exe.sha256",
                  "browser_download_url": "https://github.com/AybarsBarut/NetWatch/releases/download/v0.2.0/netwatch.exe.sha256"
                }
              ]
            }
            """;

        var release = ReleaseMetadataParser.Parse(json);

        Assert.Equal(new Version(0, 2, 0), release.Version);
        Assert.Equal("netwatch.exe", Path.GetFileName(release.ExecutableUrl.LocalPath));
        Assert.Equal("netwatch.exe.sha256", Path.GetFileName(release.ChecksumUrl.LocalPath));
    }

    [Fact]
    public void ParseRejectsMissingChecksumAsset()
    {
        const string json = """
            {
              "tag_name": "v0.2.0",
              "assets": [
                {
                  "name": "netwatch.exe",
                  "browser_download_url": "https://github.com/AybarsBarut/NetWatch/releases/download/v0.2.0/netwatch.exe"
                }
              ]
            }
            """;

        Assert.Throws<InvalidDataException>(() => ReleaseMetadataParser.Parse(json));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"tag_name\":\"v0.2.0\"}")]
    [InlineData("{\"tag_name\":\"v0.2.0\",\"assets\":{}}")]
    public void ParseRejectsMalformedReleaseMetadata(string json)
    {
        Assert.Throws<InvalidDataException>(() => ReleaseMetadataParser.Parse(json));
    }

    [Theory]
    [InlineData("https://example.com/netwatch.exe")]
    [InlineData("http://github.com/AybarsBarut/NetWatch/netwatch.exe")]
    public void ParseRejectsUntrustedAssetUrl(string executableUrl)
    {
        var json = $$"""
            {
              "tag_name": "v0.2.0",
              "assets": [
                {
                  "name": "netwatch.exe",
                  "browser_download_url": "{{executableUrl}}"
                },
                {
                  "name": "netwatch.exe.sha256",
                  "browser_download_url": "https://github.com/AybarsBarut/NetWatch/releases/download/v0.2.0/netwatch.exe.sha256"
                }
              ]
            }
            """;

        Assert.Throws<InvalidDataException>(() => ReleaseMetadataParser.Parse(json));
    }

    [Fact]
    public void ParseChecksumAcceptsGeneratedFormat()
    {
        const string hash = "a1551da6a0662a49a86eeb228a609ccbb132a6c1e2e6ebcd2927fd486a9aa07c";

        var result = ReleaseMetadataParser.ParseChecksum($"{hash}  netwatch.exe\n");

        Assert.Equal(hash.ToUpperInvariant(), result);
    }

    [Theory]
    [InlineData("0.2.0", true)]
    [InlineData("0.2.0+abcdef", true)]
    [InlineData("0.1.2+abcdef", false)]
    [InlineData(null, false)]
    public void ProductVersionMustMatchRelease(string? productVersion, bool expected)
    {
        Assert.Equal(
            expected,
            ReleaseMetadataParser.ProductVersionMatches(productVersion, new Version(0, 2, 0)));
    }
}
