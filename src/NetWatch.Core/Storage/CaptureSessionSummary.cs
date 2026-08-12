namespace NetWatch.Core.Storage;

public sealed record CaptureSessionSummary(
    string SchemaVersion,
    DateTimeOffset StartedAt,
    DateTimeOffset FinishedAt,
    long PacketCount,
    long TotalBytes,
    IReadOnlyDictionary<string, long> ProtocolCounts,
    IReadOnlyDictionary<string, long> AnomalyCounts);
