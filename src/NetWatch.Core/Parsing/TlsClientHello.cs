using System.Buffers.Binary;
using System.Text;

namespace NetWatch.Core.Parsing;

internal static class TlsClientHello
{
    public static bool TryGetServerName(ReadOnlySpan<byte> payload, out string serverName)
    {
        serverName = string.Empty;
        if (payload.Length < 9 || payload[0] != 0x16 || payload[5] != 0x01)
        {
            return false;
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(payload[3..5]);
        if (recordLength + 5 > payload.Length)
        {
            return false;
        }

        var cursor = 9;
        if (!Skip(payload, ref cursor, 2 + 32) || !SkipVector8(payload, ref cursor) ||
            !SkipVector16(payload, ref cursor) || !SkipVector8(payload, ref cursor))
        {
            return false;
        }

        if (cursor + 2 > payload.Length)
        {
            return false;
        }

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(cursor, 2));
        cursor += 2;
        var extensionsEnd = Math.Min(payload.Length, cursor + extensionsLength);

        while (cursor + 4 <= extensionsEnd)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(cursor, 2));
            var length = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(cursor + 2, 2));
            cursor += 4;
            if (cursor + length > extensionsEnd)
            {
                return false;
            }

            if (type == 0 && length >= 5)
            {
                var nameType = payload[cursor + 2];
                var nameLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(cursor + 3, 2));
                if (nameType == 0 && nameLength > 0 && cursor + 5 + nameLength <= extensionsEnd)
                {
                    serverName = Encoding.ASCII.GetString(payload.Slice(cursor + 5, nameLength));
                    return true;
                }
            }

            cursor += length;
        }

        return false;
    }

    private static bool Skip(ReadOnlySpan<byte> payload, ref int cursor, int length)
    {
        if (cursor + length > payload.Length)
        {
            return false;
        }

        cursor += length;
        return true;
    }

    private static bool SkipVector8(ReadOnlySpan<byte> payload, ref int cursor)
    {
        if (cursor >= payload.Length)
        {
            return false;
        }

        return Skip(payload, ref cursor, 1 + payload[cursor]);
    }

    private static bool SkipVector16(ReadOnlySpan<byte> payload, ref int cursor)
    {
        if (cursor + 2 > payload.Length)
        {
            return false;
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(cursor, 2));
        return Skip(payload, ref cursor, 2 + length);
    }
}
