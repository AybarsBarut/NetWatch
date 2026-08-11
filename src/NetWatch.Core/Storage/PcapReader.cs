using System.Buffers.Binary;
using PacketDotNet;
using NetWatch.Core.Capture;

namespace NetWatch.Core.Storage;

public static class PcapReader
{
    public static IReadOnlyList<CapturedFrame> Read(Stream stream)
    {
        Span<byte> global = stackalloc byte[24];
        ReadExactly(stream, global);
        if (BinaryPrimitives.ReadUInt32LittleEndian(global[..4]) != 0xA1B2C3D4)
        {
            throw new InvalidDataException("Yalnızca little-endian, mikro-saniye çözünürlüklü pcap desteklenir.");
        }

        var linkLayer = (LinkLayers)BinaryPrimitives.ReadUInt32LittleEndian(global[20..24]);
        var frames = new List<CapturedFrame>();
        Span<byte> packetHeader = stackalloc byte[16];

        while (true)
        {
            var firstByte = stream.ReadByte();
            if (firstByte < 0)
            {
                break;
            }

            packetHeader[0] = (byte)firstByte;
            ReadExactly(stream, packetHeader[1..]);

            var seconds = BinaryPrimitives.ReadUInt32LittleEndian(packetHeader[..4]);
            var microseconds = BinaryPrimitives.ReadUInt32LittleEndian(packetHeader[4..8]);
            var capturedLength = BinaryPrimitives.ReadUInt32LittleEndian(packetHeader[8..12]);
            var originalLength = BinaryPrimitives.ReadUInt32LittleEndian(packetHeader[12..16]);
            if (capturedLength > 16 * 1024 * 1024)
            {
                throw new InvalidDataException("Pcap paketi güvenli boyut sınırını aşıyor.");
            }

            var data = new byte[capturedLength];
            ReadExactly(stream, data);
            var timestamp = DateTimeOffset.FromUnixTimeSeconds(seconds).AddTicks(microseconds * 10L);
            frames.Add(new CapturedFrame(timestamp, linkLayer, data, checked((int)originalLength)));
        }

        return frames;
    }

    private static void ReadExactly(Stream stream, Span<byte> buffer)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = stream.Read(buffer[read..]);
            if (count == 0)
            {
                throw new EndOfStreamException();
            }

            read += count;
        }
    }
}
