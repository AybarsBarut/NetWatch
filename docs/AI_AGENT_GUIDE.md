# NetWatch AI agent erişim sözleşmesi

Bu belge, bir geliştiricinin sahibi olduğu veya açıkça yetkilendirildiği ağdaki prototipi AI destekli tanılama ile incelemek için NetWatch'ın dosya ve standart çıktı yüzeyini tanımlar. NetWatch pasif olarak okur; paket üretmez, istek tekrarlamaz ve veriyi dış servise göndermez.

## Önerilen çalışma akışı

```powershell
netwatch `
  --interface 1 `
  --watch-ip 192.168.1.42 `
  --peer-ip 192.168.1.50 `
  --filter "tcp or udp" `
  --agent-session .\netwatch-sessions\prototype-01 `
  --plain
```

Agent şu sırayla çalışabilir:

1. `session.json` dosyasından kapsamı ve izlenen IP'yi doğrular.
2. Canlı tanılamada `events.jsonl` dosyasına eklenen yeni satırları takip eder.
3. `protocol`, `http.method`, `http.target`, `http.statusCode` ve `anomalies[].code` alanlarıyla filtreleme yapar.
4. İnsanla ortak inceleme için aynı olayların `traffic.md` karşılığını kullanır.
5. Kullanıcı yakalamayı kapattığında `summary.json` sayaçlarını okur.

## Trafik kapsamı

İki cihaz yalnızca birbirleriyle iletişim kurduğunda olay üretmek için çift yönlü peer filtresi kullanılabilir:

```powershell
netwatch --watch-ip 192.168.1.42 --peer-ip 192.168.1.50 --agent-session .\netwatch-sessions\pair-01 --plain
```

Tek yönlü bir akış için kaynak ve hedef ayrı ayrı belirtilir:

```powershell
netwatch --source-ip 192.168.1.42 --destination-ip 192.168.1.50 --port 443 --jsonl
```

`--peer-ip`, `--watch-ip` gerektirir. Peer modu çift yönlüdür; `--source-ip` ve `--destination-ip` ise yönlüdür ve bu iki mod birlikte kullanılamaz. `--port` ve özel `--filter` her iki moda da eklenebilir. Seçilen kapsam `session.json` içinde ayrı alanlarla ve oluşturulan BPF ifadesiyle kaydedilir.

## JSONL olay şeması

Her satır bağımsız ve geçerli bir JSON nesnesidir:

```json
{"schemaVersion":"1.0","type":"packet","number":44,"timestamp":"2026-08-12T10:30:15.1234567+03:00","source":"192.168.1.42:53001","destination":"192.168.1.50:80","sourceAddress":"192.168.1.42","destinationAddress":"192.168.1.50","sourcePort":53001,"destinationPort":80,"protocol":"HTTP","length":231,"summary":"POST http://prototype.local/api/state","http":{"kind":"request","version":"HTTP/1.1","method":"POST","target":"/api/state","host":"prototype.local","headers":{"Content-Type":"application/json"},"bodyTruncated":false,"containsSensitiveHeaders":false},"anomalies":[]}
```

Alanlar eklenebilir; agent bilinmeyen alanları yok saymalı ve ana sürüm değiştiğinde (`schemaVersion`) şemayı yeniden doğrulamalıdır. `RawData` bilinçli olarak olaylara dahil edilmez.

## Boru hattı modu

Dosya oturumu yerine olaylar doğrudan standart çıktıda tüketilebilir:

```powershell
netwatch --watch-ip 192.168.1.42 --protocol HTTP,DNS --jsonl
```

`--jsonl` kullanıldığında yalnızca olaylar stdout'a, durum ve uyarılar stderr'e yazılır. Böylece agent veya yerel betik her stdout satırını bağımsız JSON olarak ayrıştırabilir.

## Debug sorguları

Tipik agent filtreleri:

- Başarısız prototip çağrıları: `protocol == "HTTP" && http.statusCode >= 400`
- Belirli uç nokta: `http.target` değeri `/api/...` ile başlıyor.
- Bağlantı kopmaları: `anomalies[].code == "tcp_reset"`
- Sunucu tarafı hata: `anomalies[].code == "http_server_error"`
- Şifresiz kimlik riski: `anomalies[].code == "plaintext_sensitive_header"`
- DNS davranışı: `protocol == "DNS"` ve `summary` içindeki sorgu/yanıt.

HTTP ayrıştırma TCP yeniden birleştirmesi yapmaz; başlık farklı segmentlere bölünmüşse olay `TCP` olarak kalabilir. Tam akış yeniden birleştirme veya TLS çözümleme gerekiyorsa kullanıcı ayrıca pcap kaydı alıp yetkili, özel bir analiz ortamında incelemelidir.

## Gizlilik sınırları

- Yalnızca kullanıcıya ait veya açıkça yetkilendirilmiş cihaz/ağ izlenmelidir.
- `--include-http-body` varsayılan olarak kapalıdır; açıkken parola, token veya kişisel veri gövdede yer alabilir.
- Bilinen kimlik başlıkları gövde seçeneğinden bağımsız olarak `[REDACTED]` biçiminde maskelenir.
- Oturum dosyaları yerel diskte kalır ve NetWatch tarafından hiçbir uzak servise gönderilmez.
