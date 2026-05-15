Evet, mevcut dokümanı **Yeşil Seviye için sadeleştirilmiş yeni protokol** ile güncelleyebiliriz. Aşağıda **değiştirilmesi gereken bölümleri** ve **yeni hallerini** bulacaksın.

Özellikle **Bölüm 4 (İşlem Aşaması)** tamamen yeniden yazılacak çünkü ePriv kaldırılıyor. Ayrıca **Bölüm 5 (Erişim Katmanları)** içindeki Yeşil Seviye tanımı da güncellenecek.

> **Not:** GitHub'daki dosyayı doğrudan düzenleme yetkim yok. Aşağıdaki güncel metni kopyalayıp ilgili bölümlerin üzerine yapıştırabilirsin.

---

## 📝 Güncellenecek Bölümler

### 1. Bölüm 2.2 – ePriv/ePub tanımı **değişecek** (sadece Sarı seviye için olduğu belirtilecek)

**Yeni metin:**

```markdown
### 2.2 ePriv / ePub — Ephemeral Anahtar Çifti (Sadece Sarı Seviye)
(ePriv, ePub) ← Dilithium3.KeyGen()
nonce         ← SHAKE-256(random_seed, 32)
session_id    ← SHAKE-256(ePub || nonce || timestamp, 32)

- **Sadece Sarı seviye** (banka, sigorta, kredi) işlemlerinde kullanılır.
- Her işlem başlangıcında TEE içinde sıfırdan üretilir.
- İşlem tamamlandığında TEE tarafından güvenli şekilde silinir (purge).
- Yeşil seviyede **kullanılmaz** — yalnızca sertifika ve uPriv yeterlidir.
```

---

### 2. Bölüm 4 – İşlem Aşaması **tamamen yeniden yazılacak**

**Yeni metin (Yeşil ve Sarı ayrıştırılmış):**

```markdown
## 4. İşlem Aşaması

Protokol, erişim seviyesine göre iki farklı akış kullanır:

- **Yeşil Seviye** (Sosyal Medya, Forumlar, Genel Platformlar): ePriv'siz, yalnızca sertifika + uPriv imzası.
- **Sarı Seviye** (Bankalar, Sigorta, Kredi): ePriv ile işlem içeriği imzalama.

### 4.1 Yeşil Seviye — Sadece Varlık Doğrulama

Bu seviyede platform (Facebook, Twitter vb.) kullanıcıya **"gerçek misin?"** sorusunu sorar. İmzalanacak bir işlem içeriği yoktur.

#### 4.1.1 İzole Alan (TEE) BTK'ya İstek Gönderir

```c
btk_istegi = {
    // Kanıt 1: eDevlet bu uPub'ı onaylıyor
    eDevlet_sertifikasi,     // eDevlet imzalı (içinde uPub var)
    
    // Kanıt 2: Bu uPub'ın sahibi bu talebi yapıyor
    talep_imzasi,            // uPriv ile imzalanmış: hash(uPub + platform_id + timestamp)
    
    // Platform bilgisi
    hedef_platform: "facebook.com",
    platform_soru: "kullanici_gercek_mi",   // Sadece yetkili sorular
    
    // Teknik alanlar
    timestamp,
    nonce
}
```

- `talep_imzasi` içinde **sertifika yok**, sadece `uPub` referansı vardır (döngü önlenir).
- `platform_soru` yalnızca BTK'nın yetkili listesindeki soru tipleri olabilir. Örneğin "tc_kimlik_ver" yetkisizdir ve BTK tarafından reddedilir.

#### 4.1.2 BTK Doğrulama ve Token Üretimi

BTK, kullanıcının TC kimliğini görmez. eDevlet'e runtime sorgusu yapmaz.

```c
// 1. Sertifikadan uPub'ı çıkar
uPub = extract_from_certificate(eDevlet_sertifikasi)

// 2. Sertifika imzasını doğrula (eDevlet onayı)
Dilithium3.Verify(eDev_pub, SHA3-256(uPub), eDevlet_sertifikasi)

// 3. Talep imzasını doğrula (kullanıcı bu talebi yapıyor)
dogrulama_hash = SHA3-256(uPub + hedef_platform + timestamp)
Dilithium3.Verify(uPub, dogrulama_hash, talep_imzasi)

// 4. CRL kontrolü
assert uPub not in CRL

// 5. Platform sorusunu kontrol et
assert platform_soru in yetkili_soru_listesi  // "kullanici_gercek_mi" evet, "tc_kimlik_ver" hayır

// 6. BTK onay token'ı üretir
token = {
    onay_durumu: true,
    hedef_platform: "facebook.com",
    seviye: "yesil",
    timestamp
}
btk_token = Dilithium3.Sign(BTK_priv, SHA3-256(token))
```

#### 4.1.3 Platform Doğrulaması

```c
// Platform BTK token'ını alır
Dilithium3.Verify(BTK_pub, SHA3-256(token), btk_token)

// Token'ın kendi platformu için olduğunu kontrol eder
assert token.hedef_platform == platform_id

// Token'da kullanıcı tanımlayıcısı (uPub, ePub) yoktur
// Platform yalnızca "evet" sinyalini alır, kendi callback_token'ı ile oturumu ilişkilendirir
```

**Yeşil Seviyede ePriv yoktur** — gereksiz anahtar üretimi ve imza zinciri önlenmiştir.

### 4.2 Sarı Seviye — İşlem İmzalama (ePriv ile)

Sarı seviye, bankacılık işlemleri gibi **içeriği imzalanmış** talepler için kullanılır. Yeşil seviyeden farklı olarak:

- Her işlem için yeni bir `(ePriv, ePub)` üretilir.
- İşlem içeriği (`"Hesap X'e 100 TL gönder"`) ePriv ile imzalanır.
- uPriv, yalnızca ePriv'in bu kullanıcıya ait olduğunu kanıtlamak için kullanılır.
- CA (Sertifika Yetkilisi) devreye girer ve geçici sertifika üretir.

> Sarı seviye detayları için ek belgeye bakınız. Bu bölümün devamı önceki protokoldeki gibidir.

*(Not: 4.2 altındaki eski ephemeral akışı buraya taşıyabilirsin, ama onu da sadeleştirmek gerekirse ayrı bir belgeye koymak daha iyi olur.)*
```

---

### 3. Bölüm 5 (Erişim Katmanları) – Yeşil Seviye token'ı **değişecek**

**Yeni Yeşil Seviye tanımı:**

```markdown
### Yeşil Seviye — Sosyal Medya ve Genel Platformlar

```c
token = {onay_durumu: true, hedef_platform, seviye: "yesil", timestamp}
btk_token = Sign(BTK_priv, hash(token))
```

- TC kimliği: hiçbir noktada açığa çıkmaz.
- **ePriv/ephemeral anahtar kullanılmaz** — yalnızca kalıcı sertifika + uPriv imzası yeterlidir.
- Sertifika Yetkilisi (CA) dahil değildir.
- Platform yalnızca `onay_durumu: true` sinyalini alır.
- Platform, kullanıcıyı tanımak için kendi `callback_token` mekanizmasını kullanır; token içinde uPub veya ePub taşınmaz.
- BTK'nın döndüğü token, "bağlantısız" (unlinkable) olduğu için farklı oturumlar birbiriyle ilişkilendirilemez.
```

---

### 4. Bölüm 8 (Güvenlik Özellikleri) – Forward Secrecy notu **değişecek**

```markdown
### Forward Secrecy

**Sadece Sarı seviyede** geçerlidir. Her işlem bağımsız bir ephemeral anahtar çifti (ePriv/ePub) kullanır. Geçmiş oturumlar, ePriv silindiğinden geriye dönük olarak çözülemez.

Yeşil seviyede forward secrecy gerekmez çünkü işlem içeriği imzalanmaz; yalnızca varlık doğrulaması yapılır.
```

---

## 🔄 Özet: Değişikliklerin Listesi

| Bölüm | Değişiklik |
|-------|-------------|
| 2.2 | ePriv tanımına "Sadece Sarı seviye" notu eklendi |
| 4 (başlık) | İşlem Aşaması → Yeşil ve Sarı ayrıştırıldı |
| 4.1 (yeni) | Yeşil seviye akışı: ePriv yok, sadece sertifika + uPriv imzası |
| 4.1.2 | BTK doğrulama adımları güncellendi (sertifika içinden uPub çıkarma) |
| 4.1.3 | Platform token doğrulaması: ePub/uPub yok, sadece onay sinyali |
| 5 (Yeşil) | Token tanımı sadeleştirildi, callback_token notu eklendi |
| 8 (Forward Secrecy) | "Sadece Sarı seviye" olarak güncellendi |

---

## ⚠️ Yapılması Gerekenler

1. Yukarıdaki metinleri kopyala.
2. GitHub'daki `GUVENLI_KIMLIK_DOGRULAMA_PROTOKOLU_TEKNIK.md` dosyasını aç.
3. İlgili bölümlerin üzerine yapıştır.
4. Versiyon numarasını güncelle: `Versiyon: 0.4-draft`
5. Commit mesajı: `refactor: yesil seviyede ePriv kaldirildi, protokol sadelestirildi`

Bu değişikliklerle Yeşil seviye artık:
- Daha hızlı (keygen yok)
- Daha basit (3 adım)
- Daha az karmaşık (ePriv yok)
- Sarı seviyeden tamamen ayrışmış

İstersen **Sarı seviye için ayrı bir belge** açılmasını da önerebiliriz, böylece bu ana belge iyice sadeleşir.