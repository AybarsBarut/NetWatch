using NetWatch.Core.Analysis;

namespace NetWatch.Core.Parsing;

public sealed record PacketInfo(
    long Number,
    DateTimeOffset Timestamp,
    string Source,
    string Destination,
    string Protocol,
    int Length,
    string Summary,
    byte[] RawData,
    string? SourceAddress = null,
    string? DestinationAddress = null,
    ushort? SourcePort = null,
    ushort? DestinationPort = null,
    HttpMessage? Http = null,
    IReadOnlyList<AnomalyFinding>? Anomalies = null);
