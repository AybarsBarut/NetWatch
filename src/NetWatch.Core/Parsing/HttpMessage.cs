namespace NetWatch.Core.Parsing;

public sealed record HttpMessage(
    string Kind,
    string Version,
    string? Method,
    string? Target,
    int? StatusCode,
    string? ReasonPhrase,
    string? Host,
    IReadOnlyDictionary<string, string> Headers,
    string? BodyPreview,
    bool BodyTruncated,
    bool ContainsSensitiveHeaders);
