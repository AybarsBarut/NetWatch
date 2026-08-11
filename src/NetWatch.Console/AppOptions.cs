namespace NetWatch.ConsoleApp;

internal sealed record AppOptions(
    bool ListInterfaces,
    string? Interface,
    string? Filter,
    FileInfo? SaveFile,
    string Mode,
    bool Promiscuous,
    bool Plain,
    int MaxPackets);
