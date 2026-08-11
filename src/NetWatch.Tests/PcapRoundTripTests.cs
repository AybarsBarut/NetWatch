using NetWatch.Core.Capture;
using NetWatch.Core.Storage;
using PacketDotNet;

namespace NetWatch.Tests;

public sealed class PcapRoundTripTests
{
    [Fact]
    public async Task WriterAndReader_PreserveFrames()
    {
        var timestamp = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).AddTicks(123_450);
        var frame = new CapturedFrame(timestamp, LinkLayers.Ethernet, new byte[] { 1, 2, 3, 4 }, 64);
        await using var stream = new MemoryStream();

        await using (var writer = new PcapWriter(stream))
        {
            await writer.WriteAsync(frame);
        }

        stream.Position = 0;
        var frames = PcapReader.Read(stream);

        var read = Assert.Single(frames);
        Assert.Equal(frame.Timestamp, read.Timestamp);
        Assert.Equal(frame.LinkLayer, read.LinkLayer);
        Assert.Equal(frame.Data, read.Data);
        Assert.Equal(frame.OriginalLength, read.OriginalLength);
    }
}
