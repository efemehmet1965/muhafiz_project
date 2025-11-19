# Muhafiz Agent

`Muhafiz.Agent`, Windows sistemler için geliştirilmiş, EDR (Endpoint Detection and Response) benzeri yeteneklere sahip modüler bir güvenlik ajanıdır. Arka planda çalışan bir servis (`Muhafiz.Agent`) ve yönetimi için bir WPF arayüzünden (`Muhafiz.Agent.WPF.UI`) oluşur.

## Temel Özellikler

- **Gerçek Zamanlı Dosya Takibi:** Belirlenen dizinleri (örn: İndirilenler, Masaüstü) sürekli izler ve dosya sistemi olaylarına anında müdahale eder.
- **Çok Aşamalı Analiz Pipeline'ı:** Yeni veya değiştirilmiş dosyaları bir dizi kontrolden geçirir:
  1.  **IOC Kontrolü:** Dosya hash'ini bilinen zararlı imzalarla karşılaştırır.
  2.  **YARA Taraması:** Dosyayı önceden tanımlanmış YARA kurallarıyla tarar.
- **Otomatik Müdahale (Response):** Bir tehdit algılandığında otomatik olarak şu eylemleri gerçekleştirir:
    -   Zararlı süreci sonlandırma.
    -   Dosyayı karantinaya alma.
    -   Bilinen C2 sunucularına giden ağ bağlantılarını engelleme.
    -   Detaylı olay kaydı oluşturma.
- **Sandbox Analizi:** Şüpheli dosyaları daha derin bir analiz için entegre Windows Sandbox ortamına veya VirusTotal gibi harici servislere gönderebilir.
- **Ransomware Koruması:** Kritik dizinlere yerleştirilen "canary" (tuzak) dosyaları sayesinde fidye yazılımı aktivitelerini tespit eder.
- **DNS Anomali Tespiti:** Şüpheli DNS isteklerini izler.
- **Modüler ve Yapılandırılabilir:** Tüm modüller ve ayarları, WPF arayüzü üzerinden veya merkezi yapılandırma dosyası aracılığıyla kolayca yönetilebilir.

## Gereksinimler

-   **İşletim Sistemi:** Windows 10 veya üzeri.
-   **.NET:** .NET 8 SDK.

## Mimari

Proje iki ana bileşenden oluşur:

1.  **`Muhafiz.Agent` (.NET Worker Service):**
    -   Çekirdek izleme, analiz ve müdahale mantığını içerir.
    -   Olay güdümlü bir mimariyle çalışır.
    -   Tespit edilen olayları (`incidents`) bir `events` klasörüne JSON formatında yazar.

2.  **`Muhafiz.Agent.WPF.UI` (WPF Uygulaması):**
    -   Ajanın kontrol panelidir.
    -   `events` klasöründeki olay kayıtlarını okuyarak kullanıcıya sunar.
    -   Ajanın ayarlarını (`settings.json`), IOC listelerini ve diğer konfigürasyonları yönetir.

Bu iki bileşen, dosya sistemi üzerinden asenkron bir şekilde haberleşir. Bu tasarım, ajanın UI'dan bağımsız olarak arka planda sürekli çalışabilmesini sağlar.

## Kurulum ve Çalıştırma

1.  Projeyi Visual Studio ile açın.
2.  `.NET 8 SDK`'nın yüklü olduğundan emin olun.
3.  **YARA Entegrasyonu (Opsiyonel ama Önerilir):**
    -   [YARA'nın resmi sayfasından](https://github.com/VirusTotal/yara/releases) Windows için derlenmiş `yara64.exe` (veya `yara32.exe`) dosyasını indirin.
    -   Uygulamayı ilk kez çalıştırdığınızda `C:\ProgramData\Muhafiz\yara` dizini oluşturulacaktır.
    -   `yara64.exe`'yi bu dizine kopyalayın.
    -   Kullanmak istediğiniz YARA kurallarını (`.yar` veya `.yara`) `C:\ProgramData\Muhafiz\yara\rules` dizinine yerleştirin.
4.  `Muhafiz.Agent.WPF.UI` projesini "Başlangıç Projesi" (Startup Project) olarak ayarlayın.
5.  Uygulamayı yönetici haklarıyla çalıştırın (F5). Ajan, Windows Güvenlik Duvarı kuralları eklemek gibi yetki gerektiren işlemler yapabilir.
6.  UI açıldığında, ajanı başlatmak için **"Start Agent"** düğmesine tıklayın.
7.  Tespit edilen olaylar ve loglar, UI üzerindeki ilgili sekmelerde görünecektir.

## Yapılandırma

Ajanın tüm ayarları, `C:\ProgramData\Muhafiz\settings.json` dosyasında merkezi olarak saklanır. Bu dosya, uygulama ilk kez çalıştığında proje içindeki `appsettings.json` şablonu kullanılarak oluşturulur.

Ayarları WPF arayüzü üzerinden değiştirebilirsiniz. Temel yapılandırma seçenekleri şunlardır:
-   **Watched Paths:** Ajanın aktif olarak izleyeceği dizinler.
-   **Yara:** YARA taramasını etkinleştirme/devre dışı bırakma.
-   **Sandbox:** VirusTotal, HybridAnalysis gibi harici analiz servislerinin API anahtarları.
-   **Canary:** Ransomware koruması için tuzak dosyaların yerleştirileceği konumlar ve ayarları.

## Kullanım

-   **Olayları Görüntüleme:** "Logs" ve "Incidents" sekmeleri, ajanın aktivitesini ve tespit ettiği tehditleri gösterir.
-   **IOC Yönetimi:** "IOCs" sekmesinden sisteme bilinen zararlı dosya hash'lerini (SHA256) veya URL'leri ekleyebilirsiniz. Bu listeler ajanın tespit yeteneğini artırır.
-   **Ayarlar:** "Settings" sekmesinden tüm ajan modüllerini ve davranışlarını canlı olarak yapılandırabilirsiniz. Değişiklikler anında `settings.json` dosyasına kaydedilir ve ajan tarafından uygulanır.
