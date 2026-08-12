using System.Text;
using System.Text.Json;
using NetWatch.Core.Analysis;
using NetWatch.Core.Parsing;

namespace NetWatch.Core.Storage;

public sealed class AgentSessionWriter : IAsyncDisposable
{
    private readonly DateTimeOffset startedAt;
    private readonly string summaryPath;
    private readonly StreamWriter eventWriter;
    private readonly MarkdownTrafficWriter markdownWriter;
    private readonly Dictionary<string, long> protocolCounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> anomalyCounts = new(StringComparer.OrdinalIgnoreCase);
    private long packetCount;
    private long totalBytes;
    private bool disposed;

    public AgentSessionWriter(string directoryPath, CaptureSessionMetadata metadata)
    {
        var directory = Directory.CreateDirectory(Path.GetFullPath(directoryPath)).FullName;
        startedAt = metadata.StartedAt;
        summaryPath = Path.Combine(directory, "summary.json");
        var sessionPath = Path.Combine(directory, "session.json");
        var eventsPath = Path.Combine(directory, "events.jsonl");
        var markdownPath = Path.Combine(directory, "traffic.md");
        var artifacts = new[] { sessionPath, eventsPath, markdownPath, summaryPath };
        var existingArtifacts = artifacts.Where(File.Exists).Select(Path.GetFileName).ToArray();
        if (existingArtifacts.Length > 0)
        {
            throw new IOException(
                "Agent oturum klasörü yeni veya boş olmalıdır. Mevcut dosyalar: " +
                string.Join(", ", existingArtifacts));
        }

        using (var stream = new FileStream(sessionPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            JsonSerializer.Serialize(stream, metadata, NetWatchJsonContext.Default.CaptureSessionMetadata);
        }

        eventWriter = new StreamWriter(
            new FileStream(eventsPath, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite),
            new UTF8Encoding(false));
        markdownWriter = new MarkdownTrafficWriter(markdownPath, metadata);
    }

    public async ValueTask WriteAsync(PacketInfo packet, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var packetEvent = PacketEvent.FromPacket(packet);
        var json = JsonSerializer.Serialize(packetEvent, NetWatchJsonContext.Default.PacketEvent);
        await eventWriter.WriteLineAsync(json.AsMemory(), cancellationToken).ConfigureAwait(false);
        await eventWriter.FlushAsync(cancellationToken).ConfigureAwait(false);
        await markdownWriter.WriteAsync(packet, cancellationToken).ConfigureAwait(false);

        packetCount++;
        totalBytes += packet.Length;
        protocolCounts[packet.Protocol] = protocolCounts.GetValueOrDefault(packet.Protocol) + 1;
        foreach (var anomaly in packet.Anomalies ?? Array.Empty<AnomalyFinding>())
        {
            anomalyCounts[anomaly.Code] = anomalyCounts.GetValueOrDefault(anomaly.Code) + 1;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        await eventWriter.DisposeAsync().ConfigureAwait(false);
        await markdownWriter.DisposeAsync().ConfigureAwait(false);

        var summary = new CaptureSessionSummary(
            "1.0",
            startedAt,
            DateTimeOffset.UtcNow,
            packetCount,
            totalBytes,
            protocolCounts,
            anomalyCounts);
        await using var stream = new FileStream(summaryPath, FileMode.Create, FileAccess.Write, FileShare.Read);
        await JsonSerializer.SerializeAsync(
            stream,
            summary,
            NetWatchJsonContext.Default.CaptureSessionSummary).ConfigureAwait(false);
    }
}
