# Katkıda Bulunma Rehberi

`Muhafiz.Agent` projesine katkıda bulunduğunuz için teşekkür ederiz! Bu rehber, projeye nasıl katkı sağlayabileceğinizi açıklar.

## Hataları Bildirme (Bug Reports)

Bir hata bulduğunuzu düşünüyorsanız, lütfen GitHub Issues üzerinden bir "issue" açın. Hata raporunuzda şu bilgileri eklemeye çalışın:

-   Hatanın açık ve kısa bir tanımı.
-   Hatayı yeniden oluşturmak için gereken adımlar.
-   Beklenen davranışın ne olduğu.
-   Gözlemlenen davranışın ne olduğu.
-   Mümkünse, ilgili log kayıtları veya ekran görüntüleri.
-   Kullandığınız işletim sistemi ve .NET sürümü.

## Özellik Önerileri (Feature Requests)

Yeni bir özellik veya mevcut bir özellikte bir geliştirme önermek isterseniz, yine GitHub Issues üzerinden bir "issue" açabilirsiniz. Lütfen önerinizi detaylı bir şekilde açıklayın:

-   Önerdiğiniz özelliğin ne işe yarayacağı.
-   Bu özelliğin neden projeye değer katacağını düşündüğünüz.
-   Mümkünse, özelliğin nasıl çalışabileceğine dair bir örnek veya senaryo.

## Kod Katkısı Süreci (Pull Requests)

Kod katkıları, "Pull Request" (PR) yoluyla kabul edilmektedir.

1.  **Fork & Clone:** Projeyi kendi GitHub hesabınıza "fork" edin ve ardından yerel makinenize "clone"layın.
2.  **Branch Oluşturma:** Yapacağınız değişiklikler için yeni bir "branch" oluşturun. Branch isminin, yapacağınız değişikliği özetlemesi tercih edilir (örn: `fix/login-bug`, `feature/add-new-scanner`).
    ```bash
    git checkout -b ozellik/yeni-tarayici
    ```
3.  **Değişiklikleri Yapma:** Kod üzerinde istediğiniz değişiklikleri ve geliştirmeleri yapın.
4.  **Commit:** Değişikliklerinizi anlamlı "commit" mesajlarıyla kaydedin.
    ```bash
    git commit -m "feat: Yeni XYZ tarayıcısı eklendi"
    ```
5.  **Push:** Oluşturduğunuz branch'i kendi forkladığınız repoya "push" edin.
    ```bash
    git push origin ozellik/yeni-tarayici
    ```
6.  **Pull Request Açma:** GitHub üzerinden orijinal `Muhafiz.Agent` reposuna bir "Pull Request" açın. PR açıklamasında yaptığınız değişiklikleri ve nedenlerini detaylı bir şekilde açıklayın. Eğer mevcut bir "issue" ile ilgiliyse, `Closes #123` gibi bir ifadeyle issue'yu etiketleyin.

Proje yöneticileri, PR'ınızı en kısa sürede inceleyecek ve geri bildirimde bulunacaktır.

## Kodlama Stili

Lütfen projenin mevcut kodlama stilini (isimlendirme kuralları, formatlama vb.) takip etmeye özen gösterin. Bu, kodun tutarlı ve okunabilir kalmasına yardımcı olur. Proje, standart .NET kodlama kurallarını benimsemektedir.
