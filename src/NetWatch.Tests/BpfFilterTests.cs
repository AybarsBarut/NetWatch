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
}
