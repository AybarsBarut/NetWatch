# NetWatch Mimarisi

NetWatch, yakalama sürücüsünü kullanıcı arayüzünden ayıran üç katmanlı bir .NET 8 uygulamasıdır.

## Veri akışı

```text
Npcap/libpcap → ICaptureProvider → bounded Channel → PacketDotNet/HTTP parser → display filter → TUI/plain/JSONL
                                      ├────────────→ pcap writer                 ├→ Markdown log
                                      └ BPF/IP filter                            └→ agent session
```

`NpcapCaptureProvider`, SharpPcap olaylarını kapasitesi sınırlı bir `Channel<CapturedFrame>` içine yazar. Kanal dolarsa en eski bekleyen çerçeve bırakılır; bu tercih yüksek trafikte yakalama callback'inin terminal çizimi yüzünden bloke olmasını önler. Arayüz yalnızca son 30 paketi gösterir ve en fazla 10 kez/saniye yenilenir. `--save` yolu ise tüketilen her çerçeveyi standart little-endian pcap biçiminde yazar.

## Projeler

- `NetWatch.Core`: Sağlayıcı sözleşmeleri, Npcap uygulaması, paket ayrıştırıcıları ve pcap depolama.
- `NetWatch.Console`: System.CommandLine seçenekleri, arayüz seçimi ve Spectre.Console görünümü.
- `NetWatch.Tests`: DNS, TLS SNI, TCP bayrakları, filtre normalizasyonu ve pcap round-trip testleri.

## Yakalama sağlayıcıları

`ICaptureProvider`, gelecekteki platform ve sürücü seçeneklerinin CLI'dan bağımsız kalmasını sağlar. `npcap` tam ham paket yakalama yoludur. `etw` sağlayıcısı şu an yalnızca Windows ağ arayüzü keşfini sunan bir önizlemedir; ham ETW olay tüketimi tamamlanana kadar çalıştırma aşamasında açık bir hata döndürür.

Karışık mod varsayılan olarak kapalıdır. Kullanıcı yalnızca yetkili olduğu ağlarda `--promiscuous` ile açıkça etkinleştirebilir.

## Protokol çözümleme

PacketDotNet Ethernet, ARP, IPv4/IPv6, TCP, UDP ve ICMP katmanlarını çözer. Küçük ve sınır kontrollü ayrıştırıcılar ayrıca şunları üretir:

- DNS soru/yanıt, kayıt türü ve alan adı özeti.
- TLS ClientHello içindeki şifrelenmemiş SNI alanı.
- Tek TCP segmentindeki şifresiz HTTP/1.x istek/yanıt metadata'sı ve isteğe bağlı gövde önizlemesi.
- TCP SYN/ACK/PSH/FIN/RST/URG kombinasyonları.

Uygulama TLS içeriğini çözmez ve anahtar materyali toplamaz.

## Analiz ve agent veri yüzeyi

`TrafficFilter`, ayrıştırılmış protokolleri CLI görünümünden ve yapılandırılmış loglardan süzer. `TrafficAnomalyDetector`, isteğe bağlı izlenen IP için küçük zaman pencereleri tutar ve deterministik bulguları `PacketInfo` üzerine ekler. Bu katman paket göndermediği, bağlantı kurmadığı ve dış servise veri aktarmadığı için analiz salt okunurdur.

`AgentSessionWriter`, ham çerçeveyi dışarı vermeden `events.jsonl` üretir. Olay şeması sürümlüdür (`schemaVersion: "1.0"`); HTTP alanları ve anomali dizisi yapılandırılmıştır. Aynı akış `traffic.md` dosyasına yazılır. Kapanışta `summary.json` atomik olmayan son durum özeti olarak oluşturulur; agentlar canlı çalışma sırasında esas olarak append edilen `events.jsonl` dosyasını izlemelidir.

## Güven sınırları

- BPF ifadeleri shell'e gönderilmez; doğrudan libpcap derleyicisine atanır.
- `--watch-ip`, `--peer-ip`, `--source-ip` ve `--destination-ip` yalnızca `IPAddress.TryParse` ile doğrulanan adreslerden BPF `host`, `src host` ve `dst host` ifadeleri üretir.
- `--watch-ip A --peer-ip B`, yalnızca A ile B arasındaki çift yönlü trafiği yakalamak için `host A and host B` üretir; yönlü `--source-ip`/`--destination-ip` moduyla birlikte kullanılamaz.
- `--port` 1-65535 aralığında doğrulanır ve oluşturulan BPF kapsamına `port N` olarak eklenir.
- Hassas HTTP kimlik başlıkları tüm yapılandırılmış ve Markdown çıktılarda koşulsuz maskelenir; gövde önizlemesi açık onay gerektirir.
- Kurulum, yayın ikilisini SHA256 dosyasıyla doğrular.
- Npcap kurucusu yalnızca resmi HTTPS adresinden alınır ve Authenticode imzası kontrol edilir.
- Ücretsiz Npcap sürümü sessiz kurulmadığından kullanıcı lisansı görerek etkileşimli kurulum yapar.
