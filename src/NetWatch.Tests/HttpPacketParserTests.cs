using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using NetWatch.Core.Capture;
using NetWatch.Core.Parsing;
using PacketDotNet;

namespace NetWatch.Tests;

public sealed class HttpPacketParserTests
{
    [Fact]
    public void Parse_ExtractsHttpRequestAndRedactsSensitiveHeaders()
    {
        const string request =
            "POST /api/temperature HTTP/1.1\r\n" +
            "Host: prototype.local\r\n" +
            "Authorization: Bearer secret-token\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: 12\r\n\r\n" +
            "{\"value\":42}";

        var result = new PacketParser(includeHttpBody: true).Parse(
            1,
            CreateTcpFrame(Encoding.UTF8.GetBytes(request)));

        Assert.Equal("HTTP", result.Protocol);
        Assert.NotNull(result.Http);
        Assert.Equal("request", result.Http.Kind);
        Assert.Equal("POST", result.Http.Method);
        Assert.Equal("/api/temperature", result.Http.Target);
        Assert.Equal("prototype.local", result.Http.Host);
        Assert.Equal("[REDACTED]", result.Http.Headers["Authorization"]);
        Assert.True(result.Http.ContainsSensitiveHeaders);
        Assert.Equal("{\"value\":42}", result.Http.BodyPreview);
        Assert.DoesNotContain("secret-token", result.Summary);
    }

    [Fact]
    public void Parse_DoesNotIncludeBodyUnlessExplicitlyEnabled()
    {
        const string request = "POST / HTTP/1.1\r\nHost: local\r\n\r\nsecret-body";

        var result = new PacketParser().Parse(1, CreateTcpFrame(Encoding.ASCII.GetBytes(request)));

        Assert.Equal("HTTP", result.Protocol);
        Assert.Null(result.Http!.BodyPreview);
    }

    private static CapturedFrame CreateTcpFrame(byte[] payload)
    {
        var tcp = new TcpPacket(50_000, 80) { PayloadData = payload };
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
        return new CapturedFrame(DateTimeOffset.UtcNow, LinkLayers.Ethernet, ethernet.Bytes, ethernet.Bytes.Length);
    }
}
