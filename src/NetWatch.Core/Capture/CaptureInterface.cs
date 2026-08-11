namespace NetWatch.Core.Capture;

public sealed record CaptureInterface(
    string Id,
    string Name,
    string Description,
    IReadOnlyList<string> Addresses);
