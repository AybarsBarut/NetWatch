using System.Text;

namespace NetWatch.Core.Parsing;

internal static class HttpMessageParser
{
    private const int MaximumHeaderBytes = 32 * 1024;
    private static readonly HashSet<string> SensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization",
        "Cookie",
        "Proxy-Authorization",
        "Set-Cookie",
        "X-Api-Key",
        "X-Auth-Token"
    };

    public static bool TryParse(
        ReadOnlySpan<byte> payload,
        bool includeBody,
        int maximumBodyBytes,
        out HttpMessage? message)
    {
        message = null;
        if (payload.IsEmpty)
        {
            return false;
        }

        var headerEnd = FindHeaderEnd(payload);
        if (headerEnd < 0 || headerEnd > MaximumHeaderBytes)
        {
            return false;
        }

        var headerText = Encoding.Latin1.GetString(payload[..headerEnd]);
        var lines = headerText.Split("\r\n", StringSplitOptions.None);
        if (lines.Length == 0)
        {
            return false;
        }

        var firstLine = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        var isResponse = firstLine.Length >= 2 && firstLine[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase);
        var isRequest = firstLine.Length == 3 && IsHttpMethod(firstLine[0]) &&
            firstLine[2].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase);
        if (!isRequest && !isResponse)
        {
            return false;
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var containsSensitiveHeaders = false;
        foreach (var line in lines.Skip(1))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            var name = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (SensitiveHeaders.Contains(name))
            {
                containsSensitiveHeaders = true;
                value = "[REDACTED]";
            }

            headers[name] = value;
        }

        var bodyOffset = headerEnd + 4;
        string? bodyPreview = null;
        var bodyTruncated = false;
        if (includeBody && bodyOffset < payload.Length && IsTextualBody(headers))
        {
            var available = payload[bodyOffset..];
            var previewLength = Math.Min(available.Length, maximumBodyBytes);
            bodyPreview = DecodeBody(available[..previewLength], headers);
            bodyTruncated = available.Length > previewLength;
        }

        if (isRequest)
        {
            message = new HttpMessage(
                "request",
                firstLine[2],
                firstLine[0],
                firstLine[1],
                null,
                null,
                headers.GetValueOrDefault("Host"),
                headers,
                bodyPreview,
                bodyTruncated,
                containsSensitiveHeaders);
            return true;
        }

        if (!int.TryParse(firstLine[1], out var statusCode))
        {
            return false;
        }

        message = new HttpMessage(
            "response",
            firstLine[0],
            null,
            null,
            statusCode,
            firstLine.Length == 3 ? firstLine[2] : null,
            headers.GetValueOrDefault("Host"),
            headers,
            bodyPreview,
            bodyTruncated,
            containsSensitiveHeaders);
        return true;
    }

    private static int FindHeaderEnd(ReadOnlySpan<byte> payload)
    {
        var searchLength = Math.Min(payload.Length, MaximumHeaderBytes + 4);
        for (var index = 0; index <= searchLength - 4; index++)
        {
            if (payload[index] == '\r' && payload[index + 1] == '\n' &&
                payload[index + 2] == '\r' && payload[index + 3] == '\n')
            {
                return index;
            }
        }

        return -1;
    }

    private static bool IsHttpMethod(string value) => value is
        "GET" or "HEAD" or "POST" or "PUT" or "DELETE" or "CONNECT" or
        "OPTIONS" or "TRACE" or "PATCH" or "PRI";

    private static bool IsTextualBody(IReadOnlyDictionary<string, string> headers)
    {
        if (!headers.TryGetValue("Content-Type", out var contentType))
        {
            return true;
        }

        return contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ||
            contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
            contentType.Contains("xml", StringComparison.OrdinalIgnoreCase) ||
            contentType.Contains("javascript", StringComparison.OrdinalIgnoreCase) ||
            contentType.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase);
    }

    private static string DecodeBody(ReadOnlySpan<byte> body, IReadOnlyDictionary<string, string> headers)
    {
        var encoding = Encoding.UTF8;
        if (headers.TryGetValue("Content-Type", out var contentType) &&
            contentType.Contains("charset=iso-8859-1", StringComparison.OrdinalIgnoreCase))
        {
            encoding = Encoding.Latin1;
        }

        return encoding.GetString(body).Replace("\0", "�", StringComparison.Ordinal);
    }
}
