namespace NetWatch.Core.Capture;

public interface ICaptureProvider : IAsyncDisposable
{
    string Mode { get; }

    IReadOnlyList<CaptureInterface> GetInterfaces();

    IAsyncEnumerable<CapturedFrame> CaptureAsync(
        CaptureOptions options,
        CancellationToken cancellationToken = default);
}
