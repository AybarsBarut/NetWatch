# NetWatch

NetWatch, Windows terminalinde canlı paket ve trafik görünümü sağlayan açık kaynak bir ağ tanılama aracıdır. Npcap üzerinden paketleri yakalar; Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS ve TLS ClientHello/SNI bilgilerini tek bir tabloda özetler. Yakalamayı Wireshark ile açılabilen standart `.pcap` dosyasına da kaydedebilir.

> [!WARNING]
> NetWatch yalnızca sahibi olduğunuz cihazlarda ve açıkça yetkilendirildiğiniz ağlarda tanılama amacıyla kullanılmalıdır. Başkalarına ait trafiği izinsiz yakalamak bulunduğunuz ülkede yasa dışı olabilir. Karışık mod varsayılan olarak kapalıdır ve `--promiscuous` ile bilinçli olarak açılmalıdır.

## Neden NetWatch?

| Özellik | NetWatch | Wireshark |
|---|---:|---:|
| Terminalde canlı paket listesi | Evet | TShark ile |
| Tek komutla kurulum | Evet | Hayır |
| Tek, self-contained uygulama dosyası | Evet | Hayır |
| BPF yakalama filtresi | Evet | Evet |
| Wireshark uyumlu pcap kaydı | Evet | Evet |
| Derin protokol analizi ve GUI | Sınırlı | Evet |

NetWatch, hızlı terminal tanılaması için tasarlanmıştır; Wireshark'ın bütün dissector ve inceleme özelliklerinin yerini almayı amaçlamaz.

## Hızlı başlangıç

PowerShell'i açın ve çalıştırın:

```powershell
irm https://raw.githubusercontent.com/AybarsBarut/WireSniffer/main/install.ps1 | iex
```

Kurucu Npcap yoksa açık onayınızdan sonra resmi ve imzalı Npcap kurucusunu çalıştırır; yalnızca sürücü kurulumu sırasında Windows yönetici izni isteyebilir. Son yayın ikilisinin SHA256 değerini doğrular ve NetWatch'ı kullanıcı PATH'inize ekler.

Ücretsiz Npcap sürümü lisansı gereği sessiz kurulamaz. Kurulum sihirbazı bu nedenle ekranda gösterilir. Kurumsal sessiz dağıtım için Npcap OEM lisansı gerekir.

## Kullanım

```powershell
# Arayüzleri listele
netwatch --list-interfaces

# Arayüzü etkileşimli seçip yakalamayı başlat
netwatch

# Belirli arayüzde HTTPS trafiğini göster
netwatch --interface 1 --filter "tcp port 443"

# Bir ana bilgisayara ait trafiği pcap olarak kaydet
netwatch --filter "host 8.8.8.8" --save capture.pcap

# Satır tabanlı çıktı (log/pipeline kullanımı)
netwatch --plain --filter "udp port 53"

# Yetkili bir ağda karışık modu açıkça etkinleştir
netwatch --promiscuous
```

Yakalamayı `Ctrl+C` ile durdurabilirsiniz. BPF ifadeleri libpcap tarafından derlenir; örnekler: `tcp`, `udp port 53`, `host 192.0.2.10`, `net 10.0.0.0/8`.

## Terminal görünümü

```text
 No   Zaman            Kaynak IP:Port          Hedef IP:Port          Protokol  Uzunluk  Bilgi
 41   14:32:08.113245  192.0.2.25:53341        1.1.1.1:53             DNS            74  Query A example.com
 42   14:32:08.127911  192.0.2.25:53342        203.0.113.10:443       TCP            66  [SYN] Seq=...
 43   14:32:08.141220  192.0.2.25:53342        203.0.113.10:443       TLS           517  Client Hello (SNI: example.com)
```

## Npcap neden gerekli?

Windows, genel amaçlı kullanıcı uygulamalarına bütün bağlantı katmanı paketlerini doğrudan sunmaz. Npcap imzalı bir Windows sürücüsü ve libpcap uyumlu API sağlayarak BPF filtreleme, loopback yakalama ve pcap uyumluluğunu mümkün kılar. NetWatch karışık modu varsayılan olarak kullanmaz.

`--mode etw` yolu gelecekte sürücüsüz metadata yakalama için ayrılmıştır. Mevcut önizlemede arayüz keşfi çalışır; canlı ham paket görünümü için `--mode npcap` gerekir.

## Kaynaktan derleme

Gereksinimler: .NET 8 SDK ve canlı yakalama için Npcap.

```powershell
dotnet restore NetWatch.sln
dotnet test NetWatch.sln -c Release
dotnet run --project src/NetWatch.Console -- --list-interfaces
dotnet publish src/NetWatch.Console -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

Mimari ayrıntılar için [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) dosyasına bakın.

## Yayınlama

Sürümler yerel olarak derlenir ve doğrulanır. `netwatch.exe` ile `netwatch.exe.sha256` dosyaları, sürüm etiketi oluşturulduktan sonra GitHub Release'e manuel olarak yüklenir. Bu depoda GitHub Actions kullanılmaz.

## Katkı sağlama

1. Küçük ve tek amaçlı bir dal açın.
2. Davranış değişiklikleri için test ekleyin.
3. `dotnet test NetWatch.sln -c Release` komutunun geçtiğini doğrulayın.
4. Değişikliğin güvenlik ve gizlilik etkisini pull request açıklamasında belirtin.

Paket yakalama kodunda varsayılan izinleri genişleten, kullanıcı onayını atlayan veya yakalanan veriyi ağ üzerinden gönderen değişiklikler kabul edilmez.

## Lisanslar

NetWatch MIT lisanslıdır. SharpPcap MIT, PacketDotNet MPL-2.0 ve Spectre.Console MIT lisanslıdır. Npcap ayrı bir üründür ve kendi kullanım/dağıtım lisansına tabidir; bu depo Npcap ikilisini barındırmaz.
