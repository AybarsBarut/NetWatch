using System.Net;
using PacketDotNet;
using NetWatch.Core.Capture;

namespace NetWatch.Core.Parsing;

public sealed class PacketParser : IPacketParser
{
    private readonly bool includeHttpBody;
    private readonly int maximumHttpBodyBytes;

    public PacketParser(bool includeHttpBody = false, int maximumHttpBodyBytes = 4_096)
    {
        if (maximumHttpBodyBytes is < 0 or > 65_536)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumHttpBodyBytes),
                "HTTP gövde önizleme sınırı 0 ile 65536 bayt arasında olmalıdır.");
        }

        this.includeHttpBody = includeHttpBody;
        this.maximumHttpBodyBytes = maximumHttpBodyBytes;
    }

    public PacketInfo Parse(long number, CapturedFrame frame)
    {
        try
        {
            var packet = Packet.ParsePacket(frame.LinkLayer, frame.Data);
            var arp = packet.Extract<ArpPacket>();
            if (arp is not null)
            {
                return Create(number, frame,
                    arp.SenderProtocolAddress.ToString(),
                    arp.TargetProtocolAddress.ToString(),
                    "ARP",
                    $"{arp.Operation}: {arp.SenderProtocolAddress} → {arp.TargetProtocolAddress}");
            }

            var ip = packet.Extract<IPPacket>();
            if (ip is null)
            {
                return Create(number, frame, "-", "-", packet.GetType().Name.Replace("Packet", string.Empty), "Ham çerçeve");
            }

            var source = ip.SourceAddress.ToString();
            var destination = ip.DestinationAddress.ToString();

            var tcp = packet.Extract<TcpPacket>();
            if (tcp is not null)
            {
                source = FormatEndpoint(ip.SourceAddress, tcp.SourcePort);
                destination = FormatEndpoint(ip.DestinationAddress, tcp.DestinationPort);

                if (HttpMessageParser.TryParse(
                    tcp.PayloadData,
                    includeHttpBody,
                    maximumHttpBodyBytes,
                    out var http) && http is not null)
                {
                    var httpSummary = http.Kind == "request"
                        ? $"{http.Method} {FormatHttpTarget(http)}"
                        : $"{http.Version} {http.StatusCode} {http.ReasonPhrase}".TrimEnd();
                    return Create(
                        number,
                        frame,
                        source,
                        destination,
                        "HTTP",
                        httpSummary,
                        ip.SourceAddress.ToString(),
                        ip.DestinationAddress.ToString(),
                        tcp.SourcePort,
                        tcp.DestinationPort,
                        http);
                }

                if (TlsClientHello.TryGetServerName(tcp.PayloadData, out var serverName))
                {
                    return Create(
                        number,
                        frame,
                        source,
                        destination,
                        "TLS",
                        $"Client Hello (SNI: {serverName})",
                        ip.SourceAddress.ToString(),
                        ip.DestinationAddress.ToString(),
                        tcp.SourcePort,
                        tcp.DestinationPort);
                }

                var flags = GetTcpFlags(tcp);
                var summary = flags.Length == 0
                    ? $"Seq={tcp.SequenceNumber} Ack={tcp.AcknowledgmentNumber}"
                    : $"[{flags}] Seq={tcp.SequenceNumber} Ack={tcp.AcknowledgmentNumber}";
                return Create(
                    number,
                    frame,
                    source,
                    destination,
                    "TCP",
                    summary,
                    ip.SourceAddress.ToString(),
                    ip.DestinationAddress.ToString(),
                    tcp.SourcePort,
                    tcp.DestinationPort);
            }

            var udp = packet.Extract<UdpPacket>();
            if (udp is not null)
            {
                source = FormatEndpoint(ip.SourceAddress, udp.SourcePort);
                destination = FormatEndpoint(ip.DestinationAddress, udp.DestinationPort);
                if ((udp.SourcePort == 53 || udp.DestinationPort == 53) &&
                    DnsMessage.TrySummarize(udp.PayloadData, out var dnsSummary))
                {
                    return Create(
                        number,
                        frame,
                        source,
                        destination,
                        "DNS",
                        dnsSummary,
                        ip.SourceAddress.ToString(),
                        ip.DestinationAddress.ToString(),
                        udp.SourcePort,
                        udp.DestinationPort);
                }

                return Create(
                    number,
                    frame,
                    source,
                    destination,
                    "UDP",
                    $"Len={udp.PayloadData.Length}",
                    ip.SourceAddress.ToString(),
                    ip.DestinationAddress.ToString(),
                    udp.SourcePort,
                    udp.DestinationPort);
            }

            var icmp = packet.Extract<IcmpV4Packet>();
            if (icmp is not null)
            {
                return Create(
                    number,
                    frame,
                    source,
                    destination,
                    "ICMP",
                    icmp.TypeCode.ToString(),
                    ip.SourceAddress.ToString(),
                    ip.DestinationAddress.ToString());
            }

            var icmpv6 = packet.Extract<IcmpV6Packet>();
            if (icmpv6 is not null)
            {
                return Create(
                    number,
                    frame,
                    source,
                    destination,
                    "ICMPv6",
                    $"Type={icmpv6.Type} Code={icmpv6.Code}",
                    ip.SourceAddress.ToString(),
                    ip.DestinationAddress.ToString());
            }

            return Create(
                number,
                frame,
                source,
                destination,
                ip.Protocol.ToString(),
                "IP paketi",
                ip.SourceAddress.ToString(),
                ip.DestinationAddress.ToString());
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException)
        {
            return Create(number, frame, "-", "-", "MALFORMED", $"Ayrıştırılamadı: {ex.Message}");
        }
    }

    internal static string GetTcpFlags(TcpPacket tcp)
    {
        var flags = new List<string>(6);
        if (tcp.Synchronize) flags.Add("SYN");
        if (tcp.Acknowledgment) flags.Add("ACK");
        if (tcp.Push) flags.Add("PSH");
        if (tcp.Finished) flags.Add("FIN");
        if (tcp.Reset) flags.Add("RST");
        if (tcp.Urgent) flags.Add("URG");
        return string.Join(',', flags);
    }

    private static PacketInfo Create(
        long number,
        CapturedFrame frame,
        string source,
        string destination,
        string protocol,
        string summary,
        string? sourceAddress = null,
        string? destinationAddress = null,
        ushort? sourcePort = null,
        ushort? destinationPort = null,
        HttpMessage? http = null) => new(
            number,
            frame.Timestamp,
            source,
            destination,
            protocol,
            frame.OriginalLength,
            summary,
            frame.Data,
            sourceAddress,
            destinationAddress,
            sourcePort,
            destinationPort,
            http);

    private static string FormatHttpTarget(HttpMessage http)
    {
        if (string.IsNullOrWhiteSpace(http.Host) || string.IsNullOrWhiteSpace(http.Target) ||
            Uri.IsWellFormedUriString(http.Target, UriKind.Absolute))
        {
            return http.Target ?? "/";
        }

        return $"http://{http.Host}{(http.Target.StartsWith('/') ? string.Empty : "/")}{http.Target}";
    }

    private static string FormatEndpoint(IPAddress address, ushort port) =>
        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{address}]:{port}"
            : $"{address}:{port}";
}
