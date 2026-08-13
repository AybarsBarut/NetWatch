namespace NetWatch.ConsoleApp;

internal sealed record AppOptions(
    bool ListInterfaces,
    string? Interface,
    string? Filter,
    string? WatchIp,
    string? PeerIp,
    string? SourceIp,
    string? DestinationIp,
    int? Port,
    string? Protocols,
    FileInfo? SaveFile,
    FileInfo? MarkdownLog,
    DirectoryInfo? AgentSessionDirectory,
    string Mode,
    bool Promiscuous,
    bool Plain,
    bool JsonLines,
    bool IncludeHttpBody,
    int MaximumHttpBodyBytes,
    int MaxPackets);
