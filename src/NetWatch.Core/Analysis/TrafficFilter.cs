using NetWatch.Core.Parsing;

namespace NetWatch.Core.Analysis;

public sealed class TrafficFilter
{
    private static readonly HashSet<string> AllowedProtocols = new(StringComparer.OrdinalIgnoreCase)
    {
        "ARP", "DNS", "HTTP", "ICMP", "ICMPV6", "TCP", "TLS", "UDP", "MALFORMED"
    };

    private readonly HashSet<string>? protocols;

    public TrafficFilter(string? protocolList)
    {
        if (string.IsNullOrWhiteSpace(protocolList))
        {
            return;
        }

        protocols = protocolList.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(item => item.ToUpperInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var invalid = protocols.Where(item => !AllowedProtocols.Contains(item)).ToArray();
        if (invalid.Length > 0)
        {
            throw new ArgumentException(
                $"Desteklenmeyen protokol: {string.Join(", ", invalid)}. " +
                $"Desteklenenler: {string.Join(", ", AllowedProtocols.Order())}.",
                nameof(protocolList));
        }
    }

    public bool Matches(PacketInfo packet) => protocols is null || protocols.Contains(packet.Protocol);
}
