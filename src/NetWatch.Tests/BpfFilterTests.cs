using NetWatch.Core.Capture;

namespace NetWatch.Tests;

public sealed class BpfFilterTests
{
    [Fact]
    public void Normalize_CollapsesWhitespace()
    {
        var result = BpfFilter.Normalize("  tcp   port  443  ");

        Assert.Equal("tcp port 443", result);
    }

    [Fact]
    public void Normalize_RejectsOversizedFilter()
    {
        var filter = new string('x', 1_025);

        Assert.Throws<ArgumentException>(() => BpfFilter.Normalize(filter));
    }

    [Fact]
    public void CombineWithHost_ComposesValidatedIpFilter()
    {
        var result = BpfFilter.CombineWithHost("tcp port 80", "192.0.2.15");

        Assert.Equal("(tcp port 80) and host 192.0.2.15", result);
    }

    [Fact]
    public void CombineWithHost_RejectsInvalidAddress()
    {
        Assert.Throws<ArgumentException>(() => BpfFilter.CombineWithHost(null, "not-an-ip"));
    }

    [Fact]
    public void Build_ComposesBidirectionalPeerFilter()
    {
        var result = BpfFilter.Build(
            null,
            "192.0.2.10",
            "198.51.100.20",
            null,
            null,
            null);

        Assert.Equal("(host 192.0.2.10 and host 198.51.100.20)", result);
    }

    [Fact]
    public void Build_CombinesPeerPortAndCustomFilter()
    {
        var result = BpfFilter.Build(
            "tcp or udp",
            "192.0.2.10",
            "198.51.100.20",
            null,
            null,
            443);

        Assert.Equal(
            "(tcp or udp) and (host 192.0.2.10 and host 198.51.100.20) and port 443",
            result);
    }

    [Fact]
    public void Build_ComposesDirectionalIpFilter()
    {
        var result = BpfFilter.Build(
            null,
            null,
            null,
            "192.0.2.10",
            "198.51.100.20",
            null);

        Assert.Equal("src host 192.0.2.10 and dst host 198.51.100.20", result);
    }

    [Fact]
    public void Build_NormalizesIpv6Addresses()
    {
        var result = BpfFilter.Build(
            null,
            null,
            null,
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8::2",
            53);

        Assert.Equal("src host 2001:db8::1 and dst host 2001:db8::2 and port 53", result);
    }

    [Fact]
    public void Build_RequiresWatchIpForPeerIp()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            BpfFilter.Build(null, null, "198.51.100.20", null, null, null));

        Assert.Contains("--watch-ip", exception.Message);
    }

    [Fact]
    public void Build_RejectsIdenticalWatchAndPeerAddresses()
    {
        Assert.Throws<ArgumentException>(() =>
            BpfFilter.Build(null, "192.0.2.10", "192.0.2.10", null, null, null));
    }

    [Fact]
    public void Build_RejectsWatchAndDirectionalModesTogether()
    {
        Assert.Throws<ArgumentException>(() =>
            BpfFilter.Build(null, "192.0.2.10", null, null, "198.51.100.20", null));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65_536)]
    public void Build_RejectsInvalidPort(int port)
    {
        Assert.Throws<ArgumentException>(() =>
            BpfFilter.Build(null, null, null, null, null, port));
    }

    [Theory]
    [InlineData("source")]
    [InlineData("destination")]
    public void Build_RejectsInvalidDirectionalAddress(string direction)
    {
        var source = direction == "source" ? "not-an-ip" : null;
        var destination = direction == "destination" ? "not-an-ip" : null;

        Assert.Throws<ArgumentException>(() =>
            BpfFilter.Build(null, null, null, source, destination, null));
    }
}
