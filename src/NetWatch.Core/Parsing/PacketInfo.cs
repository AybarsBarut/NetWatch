namespace NetWatch.Core.Parsing;

public sealed record PacketInfo(
    long Number,
    DateTimeOffset Timestamp,
    string Source,
    string Destination,
    string Protocol,
    int Length,
    string Summary,
    byte[] RawData);
