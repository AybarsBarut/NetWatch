using System.Buffers.Binary;
using System.Text;

namespace NetWatch.Core.Parsing;

internal static class DnsMessage
{
    public static bool TrySummarize(ReadOnlySpan<byte> payload, out string summary)
    {
        summary = string.Empty;
        if (payload.Length < 12)
        {
            return false;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(payload[2..4]);
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(payload[4..6]);
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(payload[6..8]);
        if (questionCount == 0)
        {
            summary = (flags & 0x8000) == 0
                ? "Query (soru yok)"
                : $"Response ({answerCount} yanıt)";
            return true;
        }

        var offset = 12;
        if (!TryReadName(payload, ref offset, out var name) || offset + 4 > payload.Length)
        {
            return false;
        }

        var type = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
        var typeName = type switch
        {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            65 => "HTTPS",
            _ => $"TYPE{type}"
        };

        summary = (flags & 0x8000) == 0
            ? $"Query {typeName} {name}"
            : $"Response {typeName} {name} ({answerCount} yanıt)";
        return true;
    }

    private static bool TryReadName(ReadOnlySpan<byte> payload, ref int offset, out string name)
    {
        var labels = new List<string>();
        var cursor = offset;
        var jumped = false;
        var jumps = 0;

        while (cursor < payload.Length && jumps++ < 32)
        {
            var length = payload[cursor++];
            if (length == 0)
            {
                if (!jumped)
                {
                    offset = cursor;
                }

                name = string.Join('.', labels);
                return labels.Count > 0;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (cursor >= payload.Length)
                {
                    break;
                }

                var pointer = ((length & 0x3F) << 8) | payload[cursor++];
                if (!jumped)
                {
                    offset = cursor;
                    jumped = true;
                }

                if (pointer >= payload.Length)
                {
                    break;
                }

                cursor = pointer;
                continue;
            }

            if (length > 63 || cursor + length > payload.Length)
            {
                break;
            }

            labels.Add(Encoding.ASCII.GetString(payload.Slice(cursor, length)));
            cursor += length;
            if (!jumped)
            {
                offset = cursor;
            }
        }

        name = string.Empty;
        return false;
    }
}
