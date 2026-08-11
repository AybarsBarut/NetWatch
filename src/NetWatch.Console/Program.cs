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
var saveOption = new Option<FileInfo?>("--save", "-w")
{
    Description = "Yakalanan paketleri klasik pcap dosyasına kaydeder"
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
rootCommand.Options.Add(saveOption);
rootCommand.Options.Add(modeOption);
rootCommand.Options.Add(promiscuousOption);
rootCommand.Options.Add(plainOption);
rootCommand.Options.Add(maxPacketsOption);

rootCommand.SetAction(async (parseResult, cancellationToken) =>
{
    var options = new AppOptions(
        parseResult.GetValue(listOption),
        parseResult.GetValue(interfaceOption),
        parseResult.GetValue(filterOption),
        parseResult.GetValue(saveOption),
        parseResult.GetValue(modeOption) ?? "npcap",
        parseResult.GetValue(promiscuousOption),
        parseResult.GetValue(plainOption),
        parseResult.GetValue(maxPacketsOption));

    return await NetWatchApplication.RunAsync(options, cancellationToken).ConfigureAwait(false);
});

return await rootCommand.Parse(args).InvokeAsync().ConfigureAwait(false);
