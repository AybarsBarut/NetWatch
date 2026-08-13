using System.Text.RegularExpressions;
using System.Net;

namespace NetWatch.Core.Capture;

public static partial class BpfFilter
{
    public static string? Build(
        string? filter,
        string? watchIp,
        string? peerIp,
        string? sourceIp,
        string? destinationIp,
        int? port)
    {
        var normalized = Normalize(filter);
        var watchedAddress = ParseAddress(watchIp, "--watch-ip");
        var peerAddress = ParseAddress(peerIp, "--peer-ip");
        var sourceAddress = ParseAddress(sourceIp, "--source-ip");
        var destinationAddress = ParseAddress(destinationIp, "--destination-ip");

        if (peerAddress is not null && watchedAddress is null)
        {
            throw new ArgumentException("--peer-ip yalnızca --watch-ip ile birlikte kullanılabilir.");
        }

        if (peerAddress is not null && peerAddress.Equals(watchedAddress))
        {
            throw new ArgumentException("--watch-ip ve --peer-ip farklı adresler olmalıdır.");
        }

        if (watchedAddress is not null && (sourceAddress is not null || destinationAddress is not null))
        {
            throw new ArgumentException(
                "--watch-ip/--peer-ip ile --source-ip/--destination-ip birlikte kullanılamaz.");
        }

        if (port is < 1 or > 65_535)
        {
            throw new ArgumentException("--port 1 ile 65535 arasında olmalıdır.");
        }

        var clauses = new List<string>();
        var hasScope = watchedAddress is not null || sourceAddress is not null ||
            destinationAddress is not null || port is not null;
        if (normalized is not null)
        {
            clauses.Add(hasScope ? $"({normalized})" : normalized);
        }

        if (watchedAddress is not null && peerAddress is not null)
        {
            clauses.Add($"(host {watchedAddress} and host {peerAddress})");
        }
        else if (watchedAddress is not null)
        {
            clauses.Add($"host {watchedAddress}");
        }

        if (sourceAddress is not null)
        {
            clauses.Add($"src host {sourceAddress}");
        }

        if (destinationAddress is not null)
        {
            clauses.Add($"dst host {destinationAddress}");
        }

        if (port is not null)
        {
            clauses.Add($"port {port.Value}");
        }

        return clauses.Count == 0 ? null : string.Join(" and ", clauses);
    }

    public static string? CombineWithHost(string? filter, string? address)
    {
        return Build(filter, address, null, null, null, null);
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

    private static IPAddress? ParseAddress(string? address, string optionName)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return null;
        }

        if (!IPAddress.TryParse(address, out var parsedAddress))
        {
            throw new ArgumentException($"{optionName} geçerli bir IPv4 veya IPv6 adresi olmalıdır.");
        }

        return parsedAddress;
    }

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}
