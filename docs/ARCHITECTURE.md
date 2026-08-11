# NetWatch Mimarisi

NetWatch, yakalama sürücüsünü kullanıcı arayüzünden ayıran üç katmanlı bir .NET 8 uygulamasıdır.

## Veri akışı

```text
Npcap/libpcap → ICaptureProvider → bounded Channel → PacketDotNet parser → TUI
                                      └────────────→ pcap writer
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
- TCP SYN/ACK/PSH/FIN/RST/URG kombinasyonları.

Uygulama TLS içeriğini çözmez ve anahtar materyali toplamaz.

## Güven sınırları

- BPF ifadeleri shell'e gönderilmez; doğrudan libpcap derleyicisine atanır.
- Kurulum, yayın ikilisini SHA256 dosyasıyla doğrular.
- Npcap kurucusu yalnızca resmi HTTPS adresinden alınır ve Authenticode imzası kontrol edilir.
- Ücretsiz Npcap sürümü sessiz kurulmadığından kullanıcı lisansı görerek etkileşimli kurulum yapar.
