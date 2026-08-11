using PacketDotNet;

namespace NetWatch.Core.Capture;

public sealed record CapturedFrame(
    DateTimeOffset Timestamp,
    LinkLayers LinkLayer,
    byte[] Data,
    int OriginalLength);
