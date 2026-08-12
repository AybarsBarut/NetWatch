namespace NetWatch.Core.Analysis;

public sealed record AnomalyFinding(
    string Code,
    string Severity,
    string Message);
