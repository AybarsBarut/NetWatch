using System.Net.NetworkInformation;

namespace NetWatch.Core.Capture;

public sealed class EtwCaptureProvider : ICaptureProvider
{
    public string Mode => "etw";

    public IReadOnlyList<CaptureInterface> GetInterfaces() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(network => network.OperationalStatus == OperationalStatus.Up)
        .Select((network, index) => new CaptureInterface(
            network.Id,
            $"{index + 1}",
            network.Description,
            network.GetIPProperties().UnicastAddresses
                .Select(address => address.Address.ToString())
                .ToArray()))
        .ToArray();

    public async IAsyncEnumerable<CapturedFrame> CaptureAsync(
        CaptureOptions options,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask;
        cancellationToken.ThrowIfCancellationRequested();
        throw new CaptureProviderException(
            "ETW modu bu önizlemede yalnızca arayüz keşfi sağlar. Ham paket yakalama için --mode npcap kullanın.");
#pragma warning disable CS0162
        yield break;
#pragma warning restore CS0162
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
