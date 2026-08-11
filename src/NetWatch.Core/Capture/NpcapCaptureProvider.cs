using System.Threading.Channels;
using SharpPcap;

namespace NetWatch.Core.Capture;

public sealed class NpcapCaptureProvider : ICaptureProvider
{
    private ICaptureDevice? activeDevice;
    private bool disposed;

    public string Mode => "npcap";

    public IReadOnlyList<CaptureInterface> GetInterfaces()
    {
        ThrowIfDisposed();

        try
        {
            return CaptureDeviceList.Instance
                .Select((device, index) => new CaptureInterface(
                    device.Name,
                    $"{index + 1}",
                    string.IsNullOrWhiteSpace(device.Description) ? device.Name : device.Description,
                    Array.Empty<string>()))
                .ToArray();
        }
        catch (Exception ex) when (ex is not CaptureProviderException)
        {
            throw new CaptureProviderException(
                "Npcap aygıtları okunamadı. Npcap'in kurulu ve hizmetin çalışır durumda olduğunu doğrulayın.", ex);
        }
    }

    public async IAsyncEnumerable<CapturedFrame> CaptureAsync(
        CaptureOptions options,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        var device = CaptureDeviceList.Instance.FirstOrDefault(candidate =>
            string.Equals(candidate.Name, options.InterfaceId, StringComparison.OrdinalIgnoreCase));

        if (device is null)
        {
            throw new CaptureProviderException($"Ağ arayüzü bulunamadı: {options.InterfaceId}");
        }

        var channel = Channel.CreateBounded<CapturedFrame>(new BoundedChannelOptions(options.ChannelCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false
        });

        PacketArrivalEventHandler handler = (_, capture) =>
        {
            var packet = capture.GetPacket();
            channel.Writer.TryWrite(new CapturedFrame(
                new DateTimeOffset(packet.Timeval.Date, TimeSpan.Zero),
                packet.LinkLayerType,
                packet.Data,
                packet.PacketLength));
        };

        activeDevice = device;
        device.OnPacketArrival += handler;

        try
        {
            var configuration = new DeviceConfiguration
            {
                Mode = options.Promiscuous ? DeviceModes.Promiscuous : DeviceModes.None,
                ReadTimeout = options.ReadTimeoutMilliseconds
            };

            device.Open(configuration);
            if (!string.IsNullOrWhiteSpace(options.Filter))
            {
                device.Filter = options.Filter;
            }

            device.StartCapture();

            await foreach (var frame in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                yield return frame;
            }
        }
        finally
        {
            channel.Writer.TryComplete();
            device.OnPacketArrival -= handler;

            if (device.Started)
            {
                device.StopCapture();
            }

            device.Close();
            activeDevice = null;
        }
    }

    public ValueTask DisposeAsync()
    {
        if (disposed)
        {
            return ValueTask.CompletedTask;
        }

        disposed = true;
        if (activeDevice is not null)
        {
            try
            {
                if (activeDevice.Started)
                {
                    activeDevice.StopCapture();
                }

                activeDevice.Close();
            }
            catch
            {
                // Best-effort cleanup while the process is shutting down.
            }
        }

        return ValueTask.CompletedTask;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
    }
}
