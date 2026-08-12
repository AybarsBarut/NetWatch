using NetWatch.Core.Parsing;
using NetWatch.Core.Storage;
using Spectre.Console;
using System.Text.Json;

namespace NetWatch.ConsoleApp;

internal static class PacketRenderer
{
    private const int VisiblePackets = 30;

    public static async Task RenderPlainAsync(
        IAsyncEnumerable<PacketInfo> packets,
        CancellationToken cancellationToken)
    {
        await foreach (var packet in packets.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            Console.WriteLine(
                $"{packet.Number,7} {packet.Timestamp:HH:mm:ss.ffffff} " +
                $"{packet.Source,-30} {packet.Destination,-30} " +
                $"{packet.Protocol,-8} {packet.Length,7} {packet.Summary}" +
                FormatAnomalies(packet));
        }
    }

    public static async Task RenderJsonLinesAsync(
        IAsyncEnumerable<PacketInfo> packets,
        CancellationToken cancellationToken)
    {
        await foreach (var packet in packets.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            var packetEvent = PacketEvent.FromPacket(packet);
            Console.WriteLine(JsonSerializer.Serialize(packetEvent, NetWatchJsonContext.Default.PacketEvent));
        }
    }

    public static async Task RenderLiveAsync(
        IAsyncEnumerable<PacketInfo> packets,
        CancellationToken cancellationToken)
    {
        var visible = new Queue<PacketInfo>(VisiblePackets);
        await AnsiConsole.Live(BuildTable(visible))
            .AutoClear(false)
            .Overflow(VerticalOverflow.Ellipsis)
            .StartAsync(async context =>
            {
                var lastRefresh = DateTime.UtcNow;
                await foreach (var packet in packets.WithCancellation(cancellationToken).ConfigureAwait(false))
                {
                    if (visible.Count == VisiblePackets)
                    {
                        visible.Dequeue();
                    }

                    visible.Enqueue(packet);
                    if ((DateTime.UtcNow - lastRefresh).TotalMilliseconds >= 100)
                    {
                        context.UpdateTarget(BuildTable(visible));
                        context.Refresh();
                        lastRefresh = DateTime.UtcNow;
                    }
                }

                context.UpdateTarget(BuildTable(visible));
                context.Refresh();
            }).ConfigureAwait(false);
    }

    private static Table BuildTable(IEnumerable<PacketInfo> packets)
    {
        var table = new Table()
            .Border(TableBorder.SimpleHeavy)
            .Expand()
            .AddColumn(new TableColumn("No").RightAligned())
            .AddColumn("Zaman")
            .AddColumn("Kaynak IP:Port")
            .AddColumn("Hedef IP:Port")
            .AddColumn("Protokol")
            .AddColumn(new TableColumn("Uzunluk").RightAligned())
            .AddColumn("Bilgi");

        foreach (var packet in packets)
        {
            table.AddRow(
                packet.Number.ToString(),
                packet.Timestamp.ToString("HH:mm:ss.ffffff"),
                Markup.Escape(packet.Source),
                Markup.Escape(packet.Destination),
                ColorProtocol(packet.Protocol),
                packet.Length.ToString(),
                Markup.Escape(packet.Summary) + ColorAnomalyCount(packet));
        }

        return table;
    }

    private static string ColorProtocol(string protocol) => protocol switch
    {
        "TCP" => "[deepskyblue1]TCP[/]",
        "UDP" => "[mediumpurple2]UDP[/]",
        "DNS" => "[springgreen2]DNS[/]",
        "HTTP" => "[cyan1]HTTP[/]",
        "TLS" => "[gold1]TLS[/]",
        "ARP" => "[orange3]ARP[/]",
        "MALFORMED" => "[red]MALFORMED[/]",
        _ => Markup.Escape(protocol)
    };

    private static string FormatAnomalies(PacketInfo packet) => packet.Anomalies is { Count: > 0 }
        ? $" ANOMALY={string.Join(',', packet.Anomalies.Select(item => item.Code))}"
        : string.Empty;

    private static string ColorAnomalyCount(PacketInfo packet) => packet.Anomalies is { Count: > 0 }
        ? $" [red]⚠ {packet.Anomalies.Count}[/]"
        : string.Empty;
}
