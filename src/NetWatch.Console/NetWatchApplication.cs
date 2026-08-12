using NetWatch.Core.Capture;
using NetWatch.Core.Analysis;
using NetWatch.Core.Parsing;
using NetWatch.Core.Storage;
using Spectre.Console;
using System.Net;

namespace NetWatch.ConsoleApp;

internal static class NetWatchApplication
{
    public static async Task<int> RunAsync(AppOptions appOptions, CancellationToken cancellationToken)
    {
        try
        {
            if (appOptions.Plain && appOptions.JsonLines)
            {
                throw new ArgumentException("--plain ve --jsonl birlikte kullanılamaz.");
            }

            await using var provider = CreateProvider(appOptions.Mode);
            var interfaces = provider.GetInterfaces();

            if (appOptions.ListInterfaces)
            {
                PrintInterfaces(interfaces, provider.Mode);
                return 0;
            }

            if (interfaces.Count == 0)
            {
                AnsiConsole.MarkupLine("[red]Kullanılabilir ağ arayüzü bulunamadı.[/]");
                return 2;
            }

            var selected = SelectInterface(interfaces, appOptions.Interface);
            string? watchedIp = null;
            if (!string.IsNullOrWhiteSpace(appOptions.WatchIp))
            {
                if (!IPAddress.TryParse(appOptions.WatchIp, out var parsedWatchedIp))
                {
                    throw new ArgumentException("--watch-ip geçerli bir IPv4 veya IPv6 adresi olmalıdır.");
                }

                watchedIp = parsedWatchedIp.ToString();
            }
            var filter = BpfFilter.CombineWithHost(appOptions.Filter, watchedIp);
            var captureOptions = new CaptureOptions(selected.Id, filter, appOptions.Promiscuous);
            var trafficFilter = new TrafficFilter(appOptions.Protocols);

            using var stopSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                stopSource.Cancel();
            };
            Console.CancelKeyPress += cancelHandler;

            try
            {
                WriteStatus(
                    appOptions.JsonLines,
                    $"Arayüz: {selected.Description}  Mod: {provider.Mode}  Filtre: {filter ?? "yok"}");
                WriteStatus(appOptions.JsonLines, "Durdurmak için Ctrl+C.");

                if (appOptions.IncludeHttpBody)
                {
                    WriteStatus(
                        appOptions.JsonLines,
                        $"UYARI: HTTP gövde önizlemesi açık ({appOptions.MaximumHttpBodyBytes} bayta kadar); hassas veri içerebilir.");
                }

                await using var writer = appOptions.SaveFile is null
                    ? null
                    : new PcapWriter(appOptions.SaveFile.FullName);

                var metadata = new CaptureSessionMetadata(
                    "1.0",
                    DateTimeOffset.UtcNow,
                    provider.Mode,
                    selected.Id,
                    selected.Description,
                    filter,
                    watchedIp,
                    appOptions.Protocols,
                    appOptions.IncludeHttpBody,
                    "Bu dosyalar ağ uç noktaları ve şifresiz uygulama verileri içerebilir. Yalnızca yetkili tanılama kapsamında paylaşın.");
                var agentTrafficPath = appOptions.AgentSessionDirectory is null
                    ? null
                    : Path.GetFullPath(Path.Combine(appOptions.AgentSessionDirectory.FullName, "traffic.md"));
                var separateMarkdownPath = appOptions.MarkdownLog?.FullName;
                var markdownDuplicatesAgentLog = separateMarkdownPath is not null && agentTrafficPath is not null &&
                    string.Equals(
                        Path.GetFullPath(separateMarkdownPath),
                        agentTrafficPath,
                        StringComparison.OrdinalIgnoreCase);
                await using var markdownWriter = separateMarkdownPath is null || markdownDuplicatesAgentLog
                    ? null
                    : new MarkdownTrafficWriter(separateMarkdownPath, metadata);
                await using var agentWriter = appOptions.AgentSessionDirectory is null
                    ? null
                    : new AgentSessionWriter(appOptions.AgentSessionDirectory.FullName, metadata);

                var parser = new PacketParser(appOptions.IncludeHttpBody, appOptions.MaximumHttpBodyBytes);
                var anomalyDetector = new TrafficAnomalyDetector(watchedIp);
                var stream = ReadPacketsAsync(
                    provider,
                    captureOptions,
                    parser,
                    trafficFilter,
                    anomalyDetector,
                    writer,
                    markdownWriter,
                    agentWriter,
                    appOptions.MaxPackets,
                    stopSource.Token);
                if (appOptions.JsonLines)
                {
                    await PacketRenderer.RenderJsonLinesAsync(stream, stopSource.Token).ConfigureAwait(false);
                }
                else if (appOptions.Plain || Console.IsOutputRedirected)
                {
                    await PacketRenderer.RenderPlainAsync(stream, stopSource.Token).ConfigureAwait(false);
                }
                else
                {
                    await PacketRenderer.RenderLiveAsync(stream, stopSource.Token).ConfigureAwait(false);
                }

                if (appOptions.SaveFile is not null)
                {
                    WriteStatus(appOptions.JsonLines, $"Pcap kaydedildi: {appOptions.SaveFile.FullName}");
                }

                if (appOptions.MarkdownLog is not null)
                {
                    WriteStatus(appOptions.JsonLines, $"Markdown günlüğü: {appOptions.MarkdownLog.FullName}");
                }

                if (appOptions.AgentSessionDirectory is not null)
                {
                    WriteStatus(appOptions.JsonLines, $"Agent oturumu: {appOptions.AgentSessionDirectory.FullName}");
                }
            }
            finally
            {
                Console.CancelKeyPress -= cancelHandler;
            }

            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (CaptureProviderException ex)
        {
            WriteError(appOptions.JsonLines, $"Yakalama hatası: {ex.Message}");
            return 3;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            WriteError(appOptions.JsonLines, $"Hata: {ex.Message}");
            return 4;
        }
    }

    private static ICaptureProvider CreateProvider(string mode) => mode.ToLowerInvariant() switch
    {
        "npcap" => new NpcapCaptureProvider(),
        "etw" => new EtwCaptureProvider(),
        _ => throw new ArgumentException("--mode yalnızca 'npcap' veya 'etw' olabilir.", nameof(mode))
    };

    private static CaptureInterface SelectInterface(
        IReadOnlyList<CaptureInterface> interfaces,
        string? requested)
    {
        if (!string.IsNullOrWhiteSpace(requested))
        {
            var selected = interfaces.FirstOrDefault(item =>
                string.Equals(item.Name, requested, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(item.Id, requested, StringComparison.OrdinalIgnoreCase));
            return selected ?? throw new ArgumentException($"Ağ arayüzü bulunamadı: {requested}");
        }

        if (Console.IsInputRedirected)
        {
            return interfaces[0];
        }

        return AnsiConsole.Prompt(
            new SelectionPrompt<CaptureInterface>()
                .Title("[cyan]Yakalanacak ağ arayüzünü seçin[/]")
                .PageSize(12)
                .UseConverter(FormatInterface)
                .AddChoices(interfaces));
    }

    private static void PrintInterfaces(IReadOnlyList<CaptureInterface> interfaces, string mode)
    {
        var table = new Table().Border(TableBorder.Rounded)
            .AddColumn("No")
            .AddColumn("Açıklama")
            .AddColumn("Kimlik")
            .AddColumn("Adresler");

        foreach (var item in interfaces)
        {
            table.AddRow(
                Markup.Escape(item.Name),
                Markup.Escape(item.Description),
                Markup.Escape(item.Id),
                Markup.Escape(item.Addresses.Count == 0 ? "-" : string.Join(", ", item.Addresses)));
        }

        AnsiConsole.MarkupLine($"[grey]Sağlayıcı:[/] [cyan]{mode}[/]");
        AnsiConsole.Write(table);
    }

    private static string FormatInterface(CaptureInterface item) =>
        $"{item.Name}. {item.Description}" +
        (item.Addresses.Count == 0 ? string.Empty : $" ({string.Join(", ", item.Addresses)})");

    private static async IAsyncEnumerable<PacketInfo> ReadPacketsAsync(
        ICaptureProvider provider,
        CaptureOptions options,
        IPacketParser parser,
        TrafficFilter trafficFilter,
        TrafficAnomalyDetector anomalyDetector,
        PcapWriter? writer,
        MarkdownTrafficWriter? markdownWriter,
        AgentSessionWriter? agentWriter,
        int maxPackets,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        long number = 0;
        long emitted = 0;
        await foreach (var frame in provider.CaptureAsync(options, cancellationToken).ConfigureAwait(false))
        {
            number++;
            if (writer is not null)
            {
                await writer.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
            }

            var packet = parser.Parse(number, frame);
            if (!trafficFilter.Matches(packet))
            {
                continue;
            }

            packet = anomalyDetector.Analyze(packet);
            if (markdownWriter is not null)
            {
                await markdownWriter.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
            }

            if (agentWriter is not null)
            {
                await agentWriter.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
            }

            yield return packet;
            emitted++;
            if (maxPackets > 0 && emitted >= maxPackets)
            {
                yield break;
            }
        }
    }

    private static void WriteStatus(bool useStandardError, string message)
    {
        if (useStandardError)
        {
            Console.Error.WriteLine(message);
            return;
        }

        AnsiConsole.MarkupLine($"[grey]{Markup.Escape(message)}[/]");
    }

    private static void WriteError(bool useStandardError, string message)
    {
        if (useStandardError)
        {
            Console.Error.WriteLine(message);
            return;
        }

        AnsiConsole.MarkupLine($"[red]{Markup.Escape(message)}[/]");
    }
}
