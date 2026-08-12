using NetWatch.Core.Parsing;

namespace NetWatch.Core.Analysis;

public sealed class TrafficAnomalyDetector
{
    private static readonly TimeSpan ScanWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan SpikeWindow = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromSeconds(30);

    private readonly string? watchedAddress;
    private readonly int portScanThreshold;
    private readonly int trafficSpikeThreshold;
    private readonly Queue<(DateTimeOffset Timestamp, ushort Port)> destinationPorts = new();
    private readonly Queue<DateTimeOffset> packetTimes = new();
    private DateTimeOffset lastPortScanAlert = DateTimeOffset.MinValue;
    private DateTimeOffset lastSpikeAlert = DateTimeOffset.MinValue;

    public TrafficAnomalyDetector(
        string? watchedAddress,
        int portScanThreshold = 12,
        int trafficSpikeThreshold = 500)
    {
        this.watchedAddress = watchedAddress;
        this.portScanThreshold = portScanThreshold > 1
            ? portScanThreshold
            : throw new ArgumentOutOfRangeException(nameof(portScanThreshold));
        this.trafficSpikeThreshold = trafficSpikeThreshold > 1
            ? trafficSpikeThreshold
            : throw new ArgumentOutOfRangeException(nameof(trafficSpikeThreshold));
    }

    public PacketInfo Analyze(PacketInfo packet)
    {
        if (!MatchesWatchedDevice(packet))
        {
            return packet;
        }

        var findings = new List<AnomalyFinding>();
        TrackTrafficSpike(packet, findings);
        TrackPortScan(packet, findings);

        if (packet.Protocol == "MALFORMED")
        {
            findings.Add(new AnomalyFinding(
                "malformed_packet",
                "warning",
                "Paket ayrıştırılamadı; bozuk trafik veya desteklenmeyen kapsülleme olabilir."));
        }

        if (packet.Protocol == "TCP" && packet.Summary.Contains("RST", StringComparison.Ordinal))
        {
            findings.Add(new AnomalyFinding(
                "tcp_reset",
                "warning",
                "TCP bağlantısı RST ile aniden sonlandırıldı."));
        }

        if (packet.Http is { ContainsSensitiveHeaders: true })
        {
            findings.Add(new AnomalyFinding(
                "plaintext_sensitive_header",
                "critical",
                "Kimlik bilgisi taşıyabilen bir HTTP başlığı şifrelenmemiş bağlantıda görüldü; değer loglarda maskelendi."));
        }

        if (packet.Http?.StatusCode is >= 400 and < 500)
        {
            findings.Add(new AnomalyFinding(
                "http_client_error",
                "warning",
                $"HTTP istemci hatası döndü: {packet.Http.StatusCode}."));
        }
        else if (packet.Http?.StatusCode is >= 500)
        {
            findings.Add(new AnomalyFinding(
                "http_server_error",
                "critical",
                $"HTTP sunucu hatası döndü: {packet.Http.StatusCode}."));
        }

        return findings.Count == 0 ? packet : packet with { Anomalies = findings };
    }

    private bool MatchesWatchedDevice(PacketInfo packet) =>
        watchedAddress is null ||
        string.Equals(packet.SourceAddress, watchedAddress, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(packet.DestinationAddress, watchedAddress, StringComparison.OrdinalIgnoreCase);

    private void TrackTrafficSpike(PacketInfo packet, ICollection<AnomalyFinding> findings)
    {
        packetTimes.Enqueue(packet.Timestamp);
        while (packetTimes.TryPeek(out var timestamp) && packet.Timestamp - timestamp > SpikeWindow)
        {
            packetTimes.Dequeue();
        }

        if (packetTimes.Count >= trafficSpikeThreshold && packet.Timestamp - lastSpikeAlert >= AlertCooldown)
        {
            findings.Add(new AnomalyFinding(
                "traffic_spike",
                "warning",
                $"Son {SpikeWindow.TotalSeconds:0} saniyede en az {packetTimes.Count} paket görüldü."));
            lastSpikeAlert = packet.Timestamp;
        }
    }

    private void TrackPortScan(PacketInfo packet, ICollection<AnomalyFinding> findings)
    {
        if (watchedAddress is null || packet.DestinationPort is null ||
            !string.Equals(packet.SourceAddress, watchedAddress, StringComparison.OrdinalIgnoreCase) ||
            packet.Protocol != "TCP" || !packet.Summary.Contains("SYN", StringComparison.Ordinal))
        {
            return;
        }

        destinationPorts.Enqueue((packet.Timestamp, packet.DestinationPort.Value));
        while (destinationPorts.TryPeek(out var item) && packet.Timestamp - item.Timestamp > ScanWindow)
        {
            destinationPorts.Dequeue();
        }

        var uniquePorts = destinationPorts.Select(item => item.Port).Distinct().Count();
        if (uniquePorts >= portScanThreshold && packet.Timestamp - lastPortScanAlert >= AlertCooldown)
        {
            findings.Add(new AnomalyFinding(
                "possible_port_scan",
                "critical",
                $"İzlenen cihaz {ScanWindow.TotalSeconds:0} saniye içinde en az {uniquePorts} farklı hedef porta SYN gönderdi."));
            lastPortScanAlert = packet.Timestamp;
        }
    }
}
