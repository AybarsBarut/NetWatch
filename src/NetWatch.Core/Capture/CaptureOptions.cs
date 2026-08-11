namespace NetWatch.Core.Capture;

public sealed record CaptureOptions(
    string InterfaceId,
    string? Filter = null,
    bool Promiscuous = false,
    int ReadTimeoutMilliseconds = 1_000,
    int ChannelCapacity = 8_192);
