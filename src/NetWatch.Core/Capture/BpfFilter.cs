using System.Text.RegularExpressions;
using System.Net;

namespace NetWatch.Core.Capture;

public static partial class BpfFilter
{
    public static string? CombineWithHost(string? filter, string? address)
    {
        var normalized = Normalize(filter);
        if (string.IsNullOrWhiteSpace(address))
        {
            return normalized;
        }

        if (!IPAddress.TryParse(address, out var parsedAddress))
        {
            throw new ArgumentException("--watch-ip geçerli bir IPv4 veya IPv6 adresi olmalıdır.", nameof(address));
        }

        var hostFilter = $"host {parsedAddress}";
        return normalized is null ? hostFilter : $"({normalized}) and {hostFilter}";
    }

    public static string? Normalize(string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return null;
        }

        var normalized = Whitespace().Replace(filter.Trim(), " ");
        if (normalized.Length > 1_024)
        {
            throw new ArgumentException("BPF filtresi en fazla 1024 karakter olabilir.", nameof(filter));
        }

        if (normalized.Any(character => char.IsControl(character)))
        {
            throw new ArgumentException("BPF filtresi kontrol karakteri içeremez.", nameof(filter));
        }

        return normalized;
    }

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}
