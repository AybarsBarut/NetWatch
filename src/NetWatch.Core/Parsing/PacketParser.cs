using System.Net;
using PacketDotNet;
using NetWatch.Core.Capture;

namespace NetWatch.Core.Parsing;

public sealed class PacketParser : IPacketParser
{
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

                if (TlsClientHello.TryGetServerName(tcp.PayloadData, out var serverName))
                {
                    return Create(number, frame, source, destination, "TLS", $"Client Hello (SNI: {serverName})");
                }

                var flags = GetTcpFlags(tcp);
                var summary = flags.Length == 0
                    ? $"Seq={tcp.SequenceNumber} Ack={tcp.AcknowledgmentNumber}"
                    : $"[{flags}] Seq={tcp.SequenceNumber} Ack={tcp.AcknowledgmentNumber}";
                return Create(number, frame, source, destination, "TCP", summary);
            }

            var udp = packet.Extract<UdpPacket>();
            if (udp is not null)
            {
                source = FormatEndpoint(ip.SourceAddress, udp.SourcePort);
                destination = FormatEndpoint(ip.DestinationAddress, udp.DestinationPort);
                if ((udp.SourcePort == 53 || udp.DestinationPort == 53) &&
                    DnsMessage.TrySummarize(udp.PayloadData, out var dnsSummary))
                {
                    return Create(number, frame, source, destination, "DNS", dnsSummary);
                }

                return Create(number, frame, source, destination, "UDP", $"Len={udp.PayloadData.Length}");
            }

            var icmp = packet.Extract<IcmpV4Packet>();
            if (icmp is not null)
            {
                return Create(number, frame, source, destination, "ICMP", icmp.TypeCode.ToString());
            }

            var icmpv6 = packet.Extract<IcmpV6Packet>();
            if (icmpv6 is not null)
            {
                return Create(number, frame, source, destination, "ICMPv6", $"Type={icmpv6.Type} Code={icmpv6.Code}");
            }

            return Create(number, frame, source, destination, ip.Protocol.ToString(), "IP paketi");
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
        string summary) => new(
            number,
            frame.Timestamp,
            source,
            destination,
            protocol,
            frame.OriginalLength,
            summary,
            frame.Data);

    private static string FormatEndpoint(IPAddress address, ushort port) =>
        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{address}]:{port}"
            : $"{address}:{port}";
}
