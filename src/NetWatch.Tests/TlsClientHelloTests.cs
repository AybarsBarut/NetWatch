using System.Buffers.Binary;
using System.Text;
using NetWatch.Core.Parsing;

namespace NetWatch.Tests;

public sealed class TlsClientHelloTests
{
    [Fact]
    public void TryGetServerName_ParsesSniExtension()
    {
        var payload = BuildClientHello("api.example.com");

        var parsed = TlsClientHello.TryGetServerName(payload, out var serverName);

        Assert.True(parsed);
        Assert.Equal("api.example.com", serverName);
    }

    private static byte[] BuildClientHello(string host)
    {
        var hostBytes = Encoding.ASCII.GetBytes(host);
        var extensionDataLength = 5 + hostBytes.Length;
        var extensionLength = 4 + extensionDataLength;
        var bodyLength = 43 + 2 + extensionLength;
        var recordLength = 4 + bodyLength;
        var payload = new byte[5 + recordLength];

        payload[0] = 0x16;
        payload[1] = 0x03;
        payload[2] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(3, 2), (ushort)recordLength);
        payload[5] = 0x01;
        payload[6] = (byte)(bodyLength >> 16);
        payload[7] = (byte)(bodyLength >> 8);
        payload[8] = (byte)bodyLength;

        var cursor = 9;
        payload[cursor++] = 0x03;
        payload[cursor++] = 0x03;
        cursor += 32;
        payload[cursor++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(cursor, 2), 2);
        cursor += 2;
        payload[cursor++] = 0x13;
        payload[cursor++] = 0x01;
        payload[cursor++] = 1;
        payload[cursor++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(cursor, 2), (ushort)extensionLength);
        cursor += 2;
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(cursor, 2), 0);
        cursor += 2;
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(cursor, 2), (ushort)extensionDataLength);
        cursor += 2;
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(cursor, 2), (ushort)(3 + hostBytes.Length));
        cursor += 2;
        payload[cursor++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(cursor, 2), (ushort)hostBytes.Length);
        cursor += 2;
        hostBytes.CopyTo(payload, cursor);
        return payload;
    }
}
