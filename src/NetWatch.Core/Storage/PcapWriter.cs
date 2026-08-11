using System.Buffers.Binary;
using PacketDotNet;
using NetWatch.Core.Capture;

namespace NetWatch.Core.Storage;

public sealed class PcapWriter : IAsyncDisposable
{
    private readonly Stream stream;
    private readonly bool leaveOpen;
    private LinkLayers? linkLayer;
    private bool disposed;

    public PcapWriter(string path)
        : this(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read), false)
    {
    }

    internal PcapWriter(Stream stream, bool leaveOpen = true)
    {
        this.stream = stream;
        this.leaveOpen = leaveOpen;
    }

    public async ValueTask WriteAsync(CapturedFrame frame, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (linkLayer is null)
        {
            linkLayer = frame.LinkLayer;
            await WriteGlobalHeaderAsync(frame.LinkLayer, cancellationToken).ConfigureAwait(false);
        }
        else if (linkLayer != frame.LinkLayer)
        {
            throw new InvalidOperationException("Klasik pcap dosyasında bağlantı katmanı yakalama sırasında değişemez.");
        }

        var timestamp = frame.Timestamp.ToUniversalTime();
        var seconds = (uint)timestamp.ToUnixTimeSeconds();
        var microseconds = (uint)((timestamp.Ticks % TimeSpan.TicksPerSecond) / 10);
        var header = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0, 4), seconds);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4, 4), microseconds);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8, 4), (uint)frame.Data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12, 4), (uint)frame.OriginalLength);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(frame.Data, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        await stream.FlushAsync().ConfigureAwait(false);
        if (!leaveOpen)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task WriteGlobalHeaderAsync(LinkLayers layer, CancellationToken cancellationToken)
    {
        var header = new byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0, 4), 0xA1B2C3D4);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(4, 2), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(6, 2), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(16, 4), 65_535);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(20, 4), (uint)layer);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
    }
}
