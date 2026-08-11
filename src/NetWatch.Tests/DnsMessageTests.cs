using System.Text;
using NetWatch.Core.Parsing;

namespace NetWatch.Tests;

public sealed class DnsMessageTests
{
    [Fact]
    public void TrySummarize_ParsesAQuery()
    {
        var payload = BuildQuery("example.com", 1);

        var parsed = DnsMessage.TrySummarize(payload, out var summary);

        Assert.True(parsed);
        Assert.Equal("Query A example.com", summary);
    }

    private static byte[] BuildQuery(string host, ushort type)
    {
        using var stream = new MemoryStream();
        stream.Write(new byte[] { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });
        foreach (var label in host.Split('.'))
        {
            stream.WriteByte((byte)label.Length);
            stream.Write(Encoding.ASCII.GetBytes(label));
        }

        stream.WriteByte(0);
        stream.WriteByte((byte)(type >> 8));
        stream.WriteByte((byte)type);
        stream.Write(new byte[] { 0x00, 0x01 });
        return stream.ToArray();
    }
}
