namespace NetWatch.Core.Storage;

public sealed record CaptureSessionMetadata(
    string SchemaVersion,
    DateTimeOffset StartedAt,
    string Provider,
    string InterfaceId,
    string InterfaceDescription,
    string? CaptureFilter,
    string? WatchedIp,
    string? PeerIp,
    string? SourceIp,
    string? DestinationIp,
    int? Port,
    string? ProtocolFilter,
    bool IncludesHttpBody,
    string PrivacyNotice);
