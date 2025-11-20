# Muhafız: Gelişmiş Tehdit Savunma Ajanı

![Muhafız Yönetim Paneli](https://raw.githubusercontent.com/efemehmet1965/muhafiz-project/main/assets/ui.png)

## 🛡️ Hakkında

**Muhafız**, modern bilgi hırsızı (stealer), fidye yazılımı (ransomware) ve diğer zararlı yazılımlara karşı proaktif, çok katmanlı bir savunma sağlamak amacıyla geliştirilmiş açık kaynaklı bir güvenlik ajanıdır. Sadece bilinen imzalarla değil, aynı zamanda davranışsal analiz ve anomali tespiti gibi gelişmiş yöntemlerle sisteminizi korur.

## 🎓 Projenin Künyesi ve Geliştirme Ekibi

Bu proje, **Sivas Cumhuriyet Üniversitesi Şarkışla Uygulamalı Bilimler Yüksekokulu**'nda hayata geçirilmiştir. Geliştirme sürecinde emeği geçen değerli ekip aşağıda belirtilmiştir:

**Akademik Danışman**
*   Doç. Dr. Mesut Polatgil

**Geliştirme Ekibi**
*   Mehmet Can Efe (*Proje Lideri*)
*   İbrahim Arslan (*Geliştirici*)


## ✨ Temel Özellikler (Savunma Katmanları)

Muhafız, tehditleri saldırı zincirinin farklı aşamalarında yakalamak için çeşitli modüller kullanır:

#### 1. **Dosya Sistemi ve YARA Tarama**
- **Anlık Analiz:** Belirlenen kritik klasörlere (örn. `İndirilenler`, `Masaüstü`) bırakılan her dosyayı anında tarar.
- **İmza ve Kural Tabanlı Tespit:** Dosyaların [SHA256](https://en.wikipedia.org/wiki/SHA-2) hash değerini bilinen zararlı listesiyle karşılaştırır ve güçlü [YARA](https://yara.readthedocs.io/en/stable/) kurallarıyla içerik analizi yapar. Tespit edilen zararlı dosyalar anında karantinaya alınır.

#### 2. **Tuzak Dosyalar (Canary Files)**
- **Davranışsal Tespit:** Stealer'ların hedef aldığı tarayıcı profilleri, kripto cüzdanları ve sistem klasörleri gibi değerli konumlara sahte "tuzak dosyalar" yerleştirir.
- **Proaktif Müdahale:** Bir işlem bu tuzak dosyalara erişmeye veya onları okumaya çalıştığında, Muhafız bunu bir saldırı göstergesi olarak kabul eder, olayı raporlar ve isteğe bağlı olarak işlemi sonlandırabilir.

#### 3. **Ağ Tuzakları (Honeypot)**
- **Ağ Keşif Tespiti:** Sistemdeki yaygın olmayan veya özel olarak belirlenmiş TCP portlarını dinleyerek ağ tarama faaliyetlerini tespit eder.
- **Saldırgan Tespiti:** Bir zararlı yazılım yanal hareket veya C2 sunucusu arayışı için bu tuzak portlara bağlandığında, Muhafız bağlantıyı kuran işlemin kimliğini belirler ve raporlar.

#### 4. **Pano Koruması (Clipboard Protection)**
- **"Clipper" Engelleme:** Kripto para adresleri gibi hassas verilerin panoya kopyalandığı anı izler. Eğer panodaki cüzdan adresi, bilinen bir zararlı tarafından aniden başka bir adresle değiştirilirse, Muhafız bu değişikliği algılayarak kullanıcıyı uyarır ve olayı kaydeder.

#### 5. **DNS Anomali Tespiti**
- **Zararlı İletişimi Engelleme:** Sistemin DNS önbelleğini periyodik olarak tarayarak, bilinen zararlı komuta-kontrol (C2) sunucularına veya kimlik avı sitelerine yapılmış sorguları tespit eder. Bu, zararlı yazılımın dış dünya ile iletişim kurmasını daha başlamadan ortaya çıkarır.

##  architectural-design  Mimari

Muhafız, iki ana bileşenden oluşur:
- **`Muhafız.Agent` (Çekirdek Servis):** Tüm izleme, analiz ve müdahale mantığını içeren, arka planda çalışan ana motordur.
- **`Muhafız.Agent.WPF.UI` (Yönetim Paneli):** Ajanı yönetmek, tespit edilen olayları gerçek zamanlı olarak görüntülemek ve tehdit istihbaratını (IoC) güncellemek için kullanılan kullanıcı arayüzüdür.

Tüm yapılandırma dosyaları, olay kayıtları (loglar), karantina ve YARA kuralları gibi operasyonel veriler, `%PROGRAMDATA%\Muhafiz` klasörü altında merkezî bir konumda saklanır.

![Muhafız IoC Yönetimi](https://raw.githubusercontent.com/efemehmet1965/muhafiz-project/main/assets/ioc.png)

## 🚀 Kurulum ve Kullanım

1. Projeyi klonlayın: `git clone https://github.com/efemehmet1965/muhafiz-project.git`
2.  `Muhafiz.Agent.sln` çözüm dosyasını Visual Studio 2022 veya üstü ile açın.
3.  Projeyi derlemek için `Build > Build Solution` menüsünü kullanın.
4.  Çalıştırmak için başlangıç projesi olarak `Muhafiz.Agent.WPF.UI`'ı seçin ve başlatın. Yönetim paneli açıldığında ajan otomatik olarak arka planda çalışmaya başlayacaktır.

## ⚙️ Yapılandırma ve Değişiklikler

Muhafız'ın davranışını ve tespit yeteneklerini kendi ihtiyaçlarınıza göre kolayca özelleştirebilirsiniz.

### Temel Ayarlar

Ajanın temel ayarları (izlenecek klasörler, dinlenecek honeypot portları vb.) `%PROGRAMDATA%\Muhafiz\appsettings.json` dosyasında bulunur. Bu dosyayı düzenleyerek ajanın davranışını değiştirebilirsiniz.

### Tehdit İstihbaratı (IoC) Ekleme

Muhafız'ın en güçlü yanlarından biri, tehdit istihbaratının yönetim paneli üzerinden dinamik olarak güncellenebilmesidir.

- **Zararlı Hash Ekleme (`hashes.json`):** Tespit etmek istediğiniz yeni zararlı yazılımların SHA256 hash'lerini UI üzerinden ekleyebilirsiniz.
  ```json
  [
    {
      "hash": "e4a5531289181c33b44b82654aa3a1c86576432f2b5a198c8a4872958373a76f",
      "description": "Örnek bir zararlı yazılım imzası"
    }
  ]
  ```

- **Zararlı Alan Adı Ekleme (`urls.json`):** Engellemek veya izlemek istediğiniz zararlı alan adlarını UI'daki ilgili sekmeye ekleyebilirsiniz.
  ```json
  [
    {
      "url": "malicious-c2-domain.com",
      "description": "Zararlı Komuta Kontrol Sunucusu"
    }
  ]
  ```

## 🤝 Katkıda Bulunma ve Kullanım

Bu proje MIT lisansı altında açık kaynaklıdır; kendi projelerinizde serbestçe kullanabilir ve geliştirebilirsiniz. Hata raporları, özellik istekleri veya kod katkıları gibi her türlü geri bildirim ve katkıdan çekinmeyin. Bir 'Issue' açmanız veya 'Pull Request' göndermeniz yeterlidir.


## 📄 Lisans

Bu proje, [MIT Lisansı](LICENSE) altında lisanslanmıştır.