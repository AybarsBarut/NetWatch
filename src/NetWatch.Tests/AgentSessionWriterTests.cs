using NetWatch.Core.Parsing;
using NetWatch.Core.Storage;

namespace NetWatch.Tests;

public sealed class AgentSessionWriterTests
{
    [Fact]
    public async Task SessionWriter_CreatesAgentReadableArtifactsWithoutRawPayload()
    {
        var directory = Path.Combine(Path.GetTempPath(), "netwatch-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var startedAt = DateTimeOffset.UtcNow;
            var metadata = new CaptureSessionMetadata(
                "1.0", startedAt, "test", "if-1", "Test interface", "host 192.0.2.10",
                "192.0.2.10", "HTTP", false, "test notice");
            await using (var writer = new AgentSessionWriter(directory, metadata))
            {
                var packet = new PacketInfo(
                    1, startedAt, "192.0.2.10:50000", "198.51.100.20:80", "HTTP", 123,
                    "GET http://example.test/", new byte[] { 1, 2, 3 },
                    "192.0.2.10", "198.51.100.20", 50_000, 80);
                await writer.WriteAsync(packet);
            }

            var eventLines = await File.ReadAllLinesAsync(Path.Combine(directory, "events.jsonl"));
            Assert.Single(eventLines);
            Assert.Contains("\"protocol\":\"HTTP\"", eventLines[0]);
            Assert.DoesNotContain("rawData", eventLines[0], StringComparison.OrdinalIgnoreCase);
            Assert.True(File.Exists(Path.Combine(directory, "session.json")));
            Assert.True(File.Exists(Path.Combine(directory, "summary.json")));
            Assert.Contains("# NetWatch trafik günlüğü", await File.ReadAllTextAsync(Path.Combine(directory, "traffic.md")));
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
