using NetWatch.Core.Capture;
using NetWatch.Core.Parsing;
using NetWatch.Core.Storage;
using Spectre.Console;

namespace NetWatch.ConsoleApp;

internal static class NetWatchApplication
{
    public static async Task<int> RunAsync(AppOptions appOptions, CancellationToken cancellationToken)
    {
        try
        {
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
            var filter = BpfFilter.Normalize(appOptions.Filter);
            var captureOptions = new CaptureOptions(selected.Id, filter, appOptions.Promiscuous);

            using var stopSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                stopSource.Cancel();
            };
            Console.CancelKeyPress += cancelHandler;

            try
            {
                AnsiConsole.MarkupLine(
                    $"[grey]Arayüz:[/] [cyan]{Markup.Escape(selected.Description)}[/]  " +
                    $"[grey]Mod:[/] [cyan]{provider.Mode}[/]  " +
                    $"[grey]Filtre:[/] [cyan]{Markup.Escape(filter ?? "yok")}[/]");
                AnsiConsole.MarkupLine("[grey]Durdurmak için Ctrl+C.[/]\n");

                await using var writer = appOptions.SaveFile is null
                    ? null
                    : new PcapWriter(appOptions.SaveFile.FullName);

                var parser = new PacketParser();
                var stream = ReadPacketsAsync(provider, captureOptions, parser, writer, appOptions.MaxPackets, stopSource.Token);
                if (appOptions.Plain || Console.IsOutputRedirected)
                {
                    await PacketRenderer.RenderPlainAsync(stream, stopSource.Token).ConfigureAwait(false);
                }
                else
                {
                    await PacketRenderer.RenderLiveAsync(stream, stopSource.Token).ConfigureAwait(false);
                }

                if (appOptions.SaveFile is not null)
                {
                    AnsiConsole.MarkupLine($"\n[green]Pcap kaydedildi:[/] {Markup.Escape(appOptions.SaveFile.FullName)}");
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
            AnsiConsole.MarkupLine($"[red]Yakalama hatası:[/] {Markup.Escape(ex.Message)}");
            return 3;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            AnsiConsole.MarkupLine($"[red]Hata:[/] {Markup.Escape(ex.Message)}");
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
        PcapWriter? writer,
        int maxPackets,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        long number = 0;
        await foreach (var frame in provider.CaptureAsync(options, cancellationToken).ConfigureAwait(false))
        {
            number++;
            if (writer is not null)
            {
                await writer.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
            }

            yield return parser.Parse(number, frame);
            if (maxPackets > 0 && number >= maxPackets)
            {
                yield break;
            }
        }
    }
}
