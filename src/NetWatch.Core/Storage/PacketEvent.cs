using NetWatch.Core.Analysis;
using NetWatch.Core.Parsing;

namespace NetWatch.Core.Storage;

public sealed record PacketEvent(
    string SchemaVersion,
    string Type,
    long Number,
    DateTimeOffset Timestamp,
    string Source,
    string Destination,
    string? SourceAddress,
    string? DestinationAddress,
    ushort? SourcePort,
    ushort? DestinationPort,
    string Protocol,
    int Length,
    string Summary,
    HttpMessage? Http,
    IReadOnlyList<AnomalyFinding> Anomalies)
{
    public static PacketEvent FromPacket(PacketInfo packet) => new(
        "1.0",
        "packet",
        packet.Number,
        packet.Timestamp,
        packet.Source,
        packet.Destination,
        packet.SourceAddress,
        packet.DestinationAddress,
        packet.SourcePort,
        packet.DestinationPort,
        packet.Protocol,
        packet.Length,
        packet.Summary,
        packet.Http,
        packet.Anomalies ?? Array.Empty<AnomalyFinding>());
}
