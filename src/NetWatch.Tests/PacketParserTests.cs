using System.Net;
using System.Net.NetworkInformation;
using NetWatch.Core.Capture;
using NetWatch.Core.Parsing;
using PacketDotNet;

namespace NetWatch.Tests;

public sealed class PacketParserTests
{
    [Fact]
    public void Parse_SummarizesTcpFlagCombination()
    {
        var tcp = new TcpPacket(50_000, 443)
        {
            Synchronize = true,
            Acknowledgment = true,
            SequenceNumber = 100,
            AcknowledgmentNumber = 200
        };
        var ip = new IPv4Packet(IPAddress.Parse("192.0.2.10"), IPAddress.Parse("198.51.100.20"))
        {
            PayloadPacket = tcp
        };
        var ethernet = new EthernetPacket(
            PhysicalAddress.Parse("001122334455"),
            PhysicalAddress.Parse("AABBCCDDEEFF"),
            EthernetType.IPv4)
        {
            PayloadPacket = ip
        };
        var frame = new CapturedFrame(DateTimeOffset.UtcNow, LinkLayers.Ethernet, ethernet.Bytes, ethernet.Bytes.Length);

        var result = new PacketParser().Parse(1, frame);

        Assert.Equal("TCP", result.Protocol);
        Assert.Equal("192.0.2.10:50000", result.Source);
        Assert.Equal("198.51.100.20:443", result.Destination);
        Assert.Contains("[SYN,ACK]", result.Summary);
    }
}
