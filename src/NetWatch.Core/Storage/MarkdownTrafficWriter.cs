using System.Text;
using NetWatch.Core.Parsing;

namespace NetWatch.Core.Storage;

public sealed class MarkdownTrafficWriter : IAsyncDisposable
{
    private readonly StreamWriter writer;

    public MarkdownTrafficWriter(string path, CaptureSessionMetadata metadata)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(parent))
        {
            Directory.CreateDirectory(parent);
        }

        writer = new StreamWriter(
            new FileStream(fullPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite),
            new UTF8Encoding(false));

        writer.WriteLine("# NetWatch trafik günlüğü");
        writer.WriteLine();
        writer.WriteLine($"- Başlangıç: `{metadata.StartedAt:O}`");
        writer.WriteLine($"- Sağlayıcı: `{EscapeInline(metadata.Provider)}`");
        writer.WriteLine($"- Arayüz: `{EscapeInline(metadata.InterfaceDescription)}` (`{EscapeInline(metadata.InterfaceId)}`)");
        writer.WriteLine($"- Yakalama filtresi: `{EscapeInline(metadata.CaptureFilter ?? "yok")}`");
        writer.WriteLine($"- İzlenen IP: `{EscapeInline(metadata.WatchedIp ?? "yok")}`");
        writer.WriteLine($"- Protokol filtresi: `{EscapeInline(metadata.ProtocolFilter ?? "yok")}`");
        writer.WriteLine($"- HTTP gövde önizlemesi: `{(metadata.IncludesHttpBody ? "açık" : "kapalı")}`");
        writer.WriteLine();
        writer.WriteLine("> " + metadata.PrivacyNotice);
        writer.WriteLine();
        writer.Flush();
    }

    public async ValueTask WriteAsync(PacketInfo packet, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await writer.WriteLineAsync($"## Paket {packet.Number}: {packet.Protocol}").ConfigureAwait(false);
        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.WriteLineAsync($"- Zaman: `{packet.Timestamp:O}`").ConfigureAwait(false);
        await writer.WriteLineAsync($"- Kaynak: `{EscapeInline(packet.Source)}`").ConfigureAwait(false);
        await writer.WriteLineAsync($"- Hedef: `{EscapeInline(packet.Destination)}`").ConfigureAwait(false);
        await writer.WriteLineAsync($"- Uzunluk: `{packet.Length}` bayt").ConfigureAwait(false);
        await writer.WriteLineAsync($"- Özet: {EscapeMarkdown(packet.Summary)}").ConfigureAwait(false);

        if (packet.Http is not null)
        {
            await WriteHttpAsync(packet.Http).ConfigureAwait(false);
        }

        if (packet.Anomalies is { Count: > 0 })
        {
            await writer.WriteLineAsync().ConfigureAwait(false);
            await writer.WriteLineAsync("### Anomaliler").ConfigureAwait(false);
            await writer.WriteLineAsync().ConfigureAwait(false);
            foreach (var anomaly in packet.Anomalies)
            {
                await writer.WriteLineAsync(
                    $"- **{EscapeMarkdown(anomaly.Severity.ToUpperInvariant())} / " +
                    $"{EscapeMarkdown(anomaly.Code)}:** {EscapeMarkdown(anomaly.Message)}").ConfigureAwait(false);
            }
        }

        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await writer.DisposeAsync().ConfigureAwait(false);
    }

    private async Task WriteHttpAsync(HttpMessage http)
    {
        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.WriteLineAsync("### HTTP ayrıntıları").ConfigureAwait(false);
        await writer.WriteLineAsync().ConfigureAwait(false);
        if (http.Kind == "request")
        {
            await writer.WriteLineAsync($"- İstek: `{EscapeInline(http.Method ?? string.Empty)} " +
                $"{EscapeInline(http.Target ?? string.Empty)} {EscapeInline(http.Version)}`").ConfigureAwait(false);
        }
        else
        {
            await writer.WriteLineAsync($"- Yanıt: `{EscapeInline(http.Version)} {http.StatusCode} " +
                $"{EscapeInline(http.ReasonPhrase ?? string.Empty)}`").ConfigureAwait(false);
        }

        if (!string.IsNullOrWhiteSpace(http.Host))
        {
            await writer.WriteLineAsync($"- Host: `{EscapeInline(http.Host)}`").ConfigureAwait(false);
        }

        if (http.Headers.Count > 0)
        {
            await writer.WriteLineAsync("- Başlıklar:").ConfigureAwait(false);
            foreach (var header in http.Headers)
            {
                await writer.WriteLineAsync(
                    $"  - `{EscapeInline(header.Key)}`: `{EscapeInline(header.Value)}`").ConfigureAwait(false);
            }
        }

        if (http.BodyPreview is not null)
        {
            await writer.WriteLineAsync($"- Gövde önizlemesi{(http.BodyTruncated ? " (kısaltıldı)" : string.Empty)}:")
                .ConfigureAwait(false);
            foreach (var line in http.BodyPreview.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
            {
                await writer.WriteLineAsync($"    {line}").ConfigureAwait(false);
            }
        }
    }

    private static string EscapeInline(string value) => value.Replace("`", "'", StringComparison.Ordinal)
        .Replace("\r", " ", StringComparison.Ordinal)
        .Replace("\n", " ", StringComparison.Ordinal);

    private static string EscapeMarkdown(string value) => EscapeInline(value)
        .Replace("*", "\\*", StringComparison.Ordinal)
        .Replace("_", "\\_", StringComparison.Ordinal);
}
