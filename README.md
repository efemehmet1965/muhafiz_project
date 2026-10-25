# Muhafız

Muhafız, modern bilgi hırsızı (stealer), fidye yazılımı (ransomware) ve benzeri zararlı yazılımlara karşı çok katmanlı, davranışsal bir savunma sağlayan açık kaynaklı bir Windows güvenlik ajanıdır. İmza tabanlı tespitin ötesine geçerek dosya sistemi davranışı, tuzak dosyalar, ağ tuzakları, pano değişiklikleri ve DNS sorguları üzerinden anomali tespiti yapar.

Proje, Sivas Cumhuriyet Üniversitesi Şarkışla Uygulamalı Bilimler Yüksekokulu bünyesinde geliştirilmiştir.

## Künye

**Akademik Danışman**
- Doç. Dr. Mesut Polatgil

**Geliştirme Ekibi**
- Mehmet Can Efe (Proje Lideri)
- İbrahim Arslan (Geliştirici)

## Mimari

Çözüm üç projeden oluşur:

| Proje | Görev |
| --- | --- |
| `Muhafiz.Agent` | İzleme, analiz ve müdahale mantığını barındıran arka plan servisi (.NET 8, Generic Host) |
| `Muhafiz.Agent.WPF.UI` | Ajanı yönetmek, olayları görüntülemek ve tehdit istihbaratını güncellemek için WPF tabanlı yönetim paneli |
| `Muhafiz.Agent.Tests` | Birim testleri (xUnit) |

Ajan ile arayüz arasında bir IPC kanalı yoktur; iki bileşen `%PROGRAMDATA%\Muhafiz` altındaki yapılandırma ve olay dosyaları üzerinden gevşek bağlı çalışır. Ajanın yalnızca arayüz üzerinden başlatılabilmesi için tek kullanımlık bir başlatma jetonu (`ui_start.token`, 2 dakika geçerli) kullanılır.

Tüm operasyonel veriler tek bir merkezî konumda tutulur:

```
%PROGRAMDATA%\Muhafiz\
├── settings.json        # Ajan yapılandırması
├── ioc\                 # Tehdit istihbaratı (hashes.json, urls.json)
├── events\              # Olay kayıtları (günlük klasörler)
├── Q\                   # Karantina
├── canary\              # Tuzak dosya durumu
├── yara\                # YARA CLI ve kuralları
└── update\              # Güncelleme paketleri
```

## Savunma Katmanları

### Dosya sistemi ve YARA tarama

İzlenen klasörlere (`İndirilenler`, `Masaüstü`) bırakılan dosyalar SHA-256 özeti ve YARA kuralları ile analiz edilir. Eşleşme durumunda dosya karantinaya alınır ve olay kaydı oluşturulur. Aynı dosyaya ait çoklu dosya sistemi olayları, gereksiz yeniden taramayı önlemek için debounce edilir.

### Tuzak dosyalar (canary)

Tarayıcı profilleri, belgeler ve indirilenler gibi stealer'ların hedef aldığı konumlara sahte dosyalar bırakılır. Bu dosyalara erişim veya yazma girişimi saldırı göstergesi olarak değerlendirilir. Dosyayı kilitleyen süreç, Windows Restart Manager API'si üzerinden tespit edilir; isteğe bağlı olarak arşivleyici süreçler sonlandırılır.

### Ağ tuzakları (honeypot)

Yapılandırılmış TCP portları dinlenir. Bir süreç bu portlara bağlandığında, bağlantıyı kuran süreç `GetExtendedTcpTable` API'si ile belirlenir ve olay kaydedilir.

### Pano koruması

Pano düzenli aralıklarla yoklanır ve tanımlı düzenli ifadelerle (örn. kripto para adresleri) eşleşen içerik raporlanır. Bu, pano değiştiren (clipper) zararlı yazılımların tespitine yardımcı olur.

### DNS anomali tespiti

DNS istemci önbelleği periyodik olarak taranır ve tehdit istihbaratındaki alan adlarıyla eşleşen sorgular raporlanır.

### Egress kontrolü

Tespit edilen bir olayın indirme kaynağı ve yapılandırılmış ek alan adları için `netsh advfirewall` üzerinden TTL'li çıkış kuralları oluşturulur. Kalıcı IOC IP blokları ajan başlangıcında uygulanır.

### Sandbox analizi

Karantinaya alınan örnekler, etkinleştirildiğinde Windows Sandbox, VirusTotal ve Hybrid Analysis arka uçlarına iletilir. Sonuçlar olay kaydına işlenir.

### LLM destekli değerlendirme

İsteğe bağlı olarak olaylar bir dil modeline (Gemini veya OpenAI) gönderilir ve yapılandırılmış bir risk değerlendirmesi (risk puanı, özet, gerekçe) alınır.

## Gereksinimler

- Windows 10/11 (x64)
- .NET 8 SDK
- Visual Studio 2022 veya üzeri
- YARA CLI (`yara64.exe`) ve kural dosyaları
- Firewall kuralları için yönetici hakları (isteğe bağlı)
- Windows Sandbox bileşeni (sandbox analizi için isteğe bağlı)

## Kurulum

1. Depoyu klonlayın:

   ```bash
   git clone https://github.com/efemehmet1965/muhafiz-project.git
   ```

2. `Muhafiz.Agent.sln` çözüm dosyasını Visual Studio 2022 ile açın.
3. Çözümü derleyin (`Build > Build Solution`).
4. Başlangıç projesi olarak `Muhafiz.Agent.WPF.UI` projesini seçin ve çalıştırın. Ajan, arayüz açıldığında arka planda başlar.

İlk çalıştırmada `%PROGRAMDATA%\Muhafiz` altındaki dizinler, varsayılan yapılandırma ve boş IOC dosyaları otomatik olarak oluşturulur. `yara64.exe` dosyası `Resources` klasöründen hedef konuma kopyalanır.

## Yapılandırma

Tüm ayarlar `%PROGRAMDATA%\Muhafiz\settings.json` dosyasında tutulur ve arayüzdeki ilgili panellerden düzenlenebilir. Dosya değişiklikleri çalışma zamanında yeniden yüklenir.

Öne çıkan bölümler:

| Bölüm | Açıklama |
| --- | --- |
| `WatchedPaths` | Taranacak klasörler |
| `Yara` | YARA CLI yolu, kural dizini ve etkinlik durumu |
| `Canary` | Tuzak dosya adları, bırakılacak konumlar, yenileme süresi |
| `Honeypot` | Dinlenecek TCP portları |
| `Egress` | Firewall uygulama, TTL, DNS önbellek süresi |
| `Sandbox` | Arka uçlar, zaman aşımı, izin verilen uzantılar |
| `LlmAnalysis` | Sağlayıcı, model, uç nokta ve API anahtarı |
| `ProcessKiller` | Süreç sonlandırma politikası ve istisnalar |
| `Events` | Olay kayıt kökü ve saklama süresi |

### Tehdit istihbaratı (IoC)

Zararlı yazılım özetleri `ioc\hashes.json`, engellenecek alan adları ve IP'ler `ioc\urls.json` dosyalarına yazılır. Her iki dosya da arayüzden yönetilebilir ve değişiklik anında yeniden yüklenir.

`hashes.json` biçimi:

```json
{
  "malicious_hashes": [
    "e4a5531289181c33b44b82654aa3a1c86576432f2b5a198c8a4872958373a76f"
  ]
}
```

`urls.json` biçimi:

```json
{
  "blocked_hosts": ["malicious-c2-domain.com"],
  "blocked_paths": [],
  "ioc_ips": ["203.0.113.10"]
}
```

## Testler

```bash
dotnet test
```

YARA entegrasyon testi, `yara64.exe` mevcut değilse atlanır.

## Proje Yapısı

```
Muhafiz.Agent/
├── Analysis/          # Sandbox orkestrasyonu, LLM analizi, arka uçlar
├── Ioc/               # IOC yükleme ve sıcak yeniden yükleme
├── Monitoring/        # Canary, pano, honeypot, DNS izleyicileri
├── Pipelines/         # YARA tarayıcı
├── Response/          # Karantina, süreç sonlandırma, egress, olay yazımı
├── Security/          # Kendini koruma (ACL, servis kurtarma)
├── Setup/             # Ortam hazırlığı
├── Update/            # Güncelleme kanalı
└── Utils/             # Yardımcılar (Zone.Identifier okuyucu)

Muhafiz.Agent.WPF.UI/
├── Converters/
├── Models/
├── ViewModels/
└── MainWindow.xaml

Muhafiz.Agent.Tests/
```

## Güvenlik Notları

- Ajan, arayüz tarafından üretilen tek kullanımlık jeton olmadan başlatılamaz.
- API anahtarları `settings.json` içinde düz metin olarak saklanır; dosya erişimini kısıtlayın.
- Firewall kurallarının uygulanması için ajanın yönetici olarak çalışması gerekir. Yönetici değilse kurallar uygulanmaz ve uyarı kaydedilir.
- Karantina ve olay dizinleri, kendini koruma etkinleştirildiğinde ACL ile sertleştirilir.

## Katkı

Hata bildirimleri, özellik istekleri ve kod katkıları için issue veya pull request açabilirsiniz. Katkı göndermeden önce mevcut testlerin geçtiğinden emin olun.

## Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.
