using NetWatch.Core.Analysis;
using NetWatch.Core.Parsing;

namespace NetWatch.Tests;

public sealed class TrafficAnalysisTests
{
    [Fact]
    public void Analyze_FlagsHttpServerErrorForWatchedDevice()
    {
        var http = new HttpMessage(
            "response", "HTTP/1.1", null, null, 503, "Unavailable", null,
            new Dictionary<string, string>(), null, false, false);
        var packet = CreatePacket("198.51.100.20", "192.0.2.10", 80, 50_000, "HTTP", "HTTP/1.1 503", http);

        var result = new TrafficAnomalyDetector("192.0.2.10").Analyze(packet);

        Assert.Contains(result.Anomalies!, item => item.Code == "http_server_error" && item.Severity == "critical");
    }

    [Fact]
    public void Analyze_FlagsPossiblePortScanAtThreshold()
    {
        var detector = new TrafficAnomalyDetector("192.0.2.10", portScanThreshold: 3);
        PacketInfo? result = null;
        for (ushort port = 80; port < 83; port++)
        {
            result = detector.Analyze(CreatePacket(
                "192.0.2.10", "198.51.100.20", 50_000, port, "TCP", "[SYN] Seq=1"));
        }

        Assert.Contains(result!.Anomalies!, item => item.Code == "possible_port_scan");
    }

    [Fact]
    public void TrafficFilter_AllowsCommaSeparatedProtocols()
    {
        var filter = new TrafficFilter("http, dns");

        Assert.True(filter.Matches(CreatePacket("a", "b", null, null, "HTTP", "GET /")));
        Assert.False(filter.Matches(CreatePacket("a", "b", null, null, "TCP", "SYN")));
    }

    private static PacketInfo CreatePacket(
        string sourceAddress,
        string destinationAddress,
        ushort? sourcePort,
        ushort? destinationPort,
        string protocol,
        string summary,
        HttpMessage? http = null) => new(
            1,
            DateTimeOffset.UtcNow,
            sourceAddress,
            destinationAddress,
            protocol,
            100,
            summary,
            Array.Empty<byte>(),
            sourceAddress,
            destinationAddress,
            sourcePort,
            destinationPort,
            http);
}
