namespace NetWatch.Core.Capture;

public sealed class CaptureProviderException(string message, Exception? innerException = null)
    : Exception(message, innerException);
