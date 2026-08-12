using System.CommandLine;
using NetWatch.ConsoleApp;

var rootCommand = new RootCommand("Windows için canlı ağ ve paket izleme aracı");

var listOption = new Option<bool>("--list-interfaces")
{
    Description = "Kullanılabilir ağ arayüzlerini listeler"
};
var interfaceOption = new Option<string?>("--interface", "-i")
{
    Description = "Arayüz numarası, adı veya kimliği"
};
var filterOption = new Option<string?>("--filter", "-f")
{
    Description = "libpcap BPF filtresi (ör. tcp port 443)"
};
var watchIpOption = new Option<string?>("--watch-ip")
{
    Description = "Yalnızca belirtilen IPv4/IPv6 adresine ait trafiği yakalar ve anomali analizini bu cihaza odaklar"
};
var protocolOption = new Option<string?>("--protocol")
{
    Description = "Görüntülenecek protokoller, virgülle ayrılır (ör. HTTP,DNS,TLS)"
};
var saveOption = new Option<FileInfo?>("--save", "-w")
{
    Description = "Yakalanan paketleri klasik pcap dosyasına kaydeder"
};
var markdownLogOption = new Option<FileInfo?>("--markdown-log")
{
    Description = "Filtrelenmiş trafiği canlı olarak Markdown günlüğüne yazar"
};
var agentSessionOption = new Option<DirectoryInfo?>("--agent-session")
{
    Description = "AI agentları için session.json, events.jsonl, traffic.md ve summary.json üretir"
};
var modeOption = new Option<string>("--mode")
{
    Description = "Yakalama sağlayıcısı: npcap veya etw",
    DefaultValueFactory = _ => "npcap"
};
var promiscuousOption = new Option<bool>("--promiscuous")
{
    Description = "Karışık modu açıkça etkinleştirir (yalnızca yetkili ağlarda kullanın)"
};
var plainOption = new Option<bool>("--plain")
{
    Description = "Canlı TUI yerine satır tabanlı çıktı kullanır"
};
var jsonLinesOption = new Option<bool>("--jsonl")
{
    Description = "Standart çıktıya makine-dostu, satır başına tek JSON olay yazar"
};
var httpBodyOption = new Option<bool>("--include-http-body")
{
    Description = "Metinsel HTTP gövdelerinin sınırlı önizlemesini çıktıya ekler (hassas veri içerebilir)"
};
var httpBodyBytesOption = new Option<int>("--http-body-bytes")
{
    Description = "HTTP gövde önizlemesinin azami bayt sayısı",
    DefaultValueFactory = _ => 4096
};
httpBodyBytesOption.Validators.Add(result =>
{
    var value = result.GetValueOrDefault<int>();
    if (value is < 0 or > 65_536)
    {
        result.AddError("--http-body-bytes 0 ile 65536 arasında olmalıdır.");
    }
});
var maxPacketsOption = new Option<int>("--max-packets")
{
    Description = "Belirtilen paket sayısından sonra çıkar; 0 sınırsızdır",
    DefaultValueFactory = _ => 0
};
maxPacketsOption.Validators.Add(result =>
{
    if (result.GetValueOrDefault<int>() < 0)
    {
        result.AddError("--max-packets negatif olamaz.");
    }
});

rootCommand.Options.Add(listOption);
rootCommand.Options.Add(interfaceOption);
rootCommand.Options.Add(filterOption);
rootCommand.Options.Add(watchIpOption);
rootCommand.Options.Add(protocolOption);
rootCommand.Options.Add(saveOption);
rootCommand.Options.Add(markdownLogOption);
rootCommand.Options.Add(agentSessionOption);
rootCommand.Options.Add(modeOption);
rootCommand.Options.Add(promiscuousOption);
rootCommand.Options.Add(plainOption);
rootCommand.Options.Add(jsonLinesOption);
rootCommand.Options.Add(httpBodyOption);
rootCommand.Options.Add(httpBodyBytesOption);
rootCommand.Options.Add(maxPacketsOption);

rootCommand.SetAction(async (parseResult, cancellationToken) =>
{
    var options = new AppOptions(
        parseResult.GetValue(listOption),
        parseResult.GetValue(interfaceOption),
        parseResult.GetValue(filterOption),
        parseResult.GetValue(watchIpOption),
        parseResult.GetValue(protocolOption),
        parseResult.GetValue(saveOption),
        parseResult.GetValue(markdownLogOption),
        parseResult.GetValue(agentSessionOption),
        parseResult.GetValue(modeOption) ?? "npcap",
        parseResult.GetValue(promiscuousOption),
        parseResult.GetValue(plainOption),
        parseResult.GetValue(jsonLinesOption),
        parseResult.GetValue(httpBodyOption),
        parseResult.GetValue(httpBodyBytesOption),
        parseResult.GetValue(maxPacketsOption));

    return await NetWatchApplication.RunAsync(options, cancellationToken).ConfigureAwait(false);
});

return await rootCommand.Parse(args).InvokeAsync().ConfigureAwait(false);
