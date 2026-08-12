using System.Text.Json.Serialization;

namespace NetWatch.Core.Storage;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = false,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(CaptureSessionMetadata))]
[JsonSerializable(typeof(CaptureSessionSummary))]
[JsonSerializable(typeof(PacketEvent))]
public sealed partial class NetWatchJsonContext : JsonSerializerContext;
