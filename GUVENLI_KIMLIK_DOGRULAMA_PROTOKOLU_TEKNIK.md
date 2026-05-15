# Güvenli Kimlik Doğrulama Protokolü — Teknik Spesifikasyon

**Hazırlayan:** Güven ACAR — İzmir, 2026  
**Kaynak:** https://github.com/guvenacar/GKDP-Guvenli-Kimlik-Dogrulama-Protokolu  
**Versiyon:** 0.4-draft

---

## 1. Kriptografik Primitifler

Bu protokol yalnızca NIST onaylı, kuantum dirençli algoritmalar kullanır.

| Kullanım Amacı | Algoritma | Standart |
|---|---|---|
| İmzalama | CRYSTALS-Dilithium (Dilithium3) | FIPS 204 |
| Anahtar kapsülleme | CRYSTALS-Kyber (Kyber-768) | FIPS 203 |
| Hash | SHA-3 / SHAKE-256 | FIPS 202 |
| Geçici anahtar türetme | HKDF-SHA3-256 | RFC 5869 |

---

## 2. Bileşenler ve Anahtar Yapısı

### 2.1 uPriv / uPub — Kullanıcı Uzun Dönem Anahtar Çifti

```
(uPriv, uPub) ← Dilithium3.KeyGen()
```

- **uPriv:** Kullanıcının kalıcı gizli anahtarı. Donanımsal güvenlik bölgesinde (TEE) üretilir ve saklanır. Cihazdan asla çıkmaz. Export edilemez.
- **uPub:** Kullanıcının kalıcı açık anahtarı. Kayıt aşamasında eDevlet'e iletilir ve kullanıcı kimliğiyle ilişkilendirilir.

### 2.2 ePriv / ePub — Ephemeral Anahtar Çifti (Sadece Sarı Seviye)

```
(ePriv, ePub) ← Dilithium3.KeyGen()
nonce         ← SHAKE-256(random_seed, 32)
session_id    ← SHAKE-256(ePub || nonce || timestamp, 32)
```

- **Sadece Sarı seviye** (banka, sigorta, kredi) işlemlerinde kullanılır.
- Her işlem başlangıcında TEE içinde sıfırdan üretilir.
- İşlem tamamlandığında TEE tarafından güvenli şekilde silinir (purge).
- Yeşil seviyede **kullanılmaz** — yalnızca sertifika ve uPriv yeterlidir.
- uPriv ile doğrudan ilişkisi yoktur — bağlantı yalnızca imza zinciri üzerinden kurulur.

### 2.3 Platform Anahtar Çifti

```
(P_priv, P_pub) ← Kyber768.KeyGen()
```

- Her platform kendi anahtar çiftini üretir ve P_pub'ı kamuya açık şekilde yayımlar.
- Oturum şifrelemesinde kullanıcı P_pub ile kapsülleme yapar; platform P_priv ile açar.
- Platform kimliği (platform_id), BTK tarafından kayıt altına alınır ve her platforma özel bir sertifika verilir. Token doğrulaması sırasında platform, kendi kimliğini bu sertifika ile kanıtlar.

### 2.4 BTK Anahtar Çifti

```
(BTK_priv, BTK_pub) ← Dilithium3.KeyGen()
```

- BTK_pub kamuya açık şekilde yayımlanır.
- Tüm taraflar BTK imzasını bağımsız olarak doğrulayabilir.

### 2.5 eDevlet Anahtar Çifti

```
(eDev_priv, eDev_pub) ← Dilithium3.KeyGen()
```

- Kayıt aşamasında kullanıcı sertifikalarını imzalamak için kullanılır.
- eDev_pub, BTK tarafından bilinir.

---

## 3. Kayıt Aşaması (Tek Seferlik)

Kullanıcı sisteme ilk kez dahil olurken gerçekleşir. eDevlet yalnızca bu aşamada devrededir — runtime işlemlerinde yer almaz.

```
1. TEE içinde uPriv/uPub üretilir.

2. Kullanıcı eDevlet'e başvurur:
   kayit_talebi = {uPub, TC_kimlik, zaman_damgasi}
   imzali_talep = Dilithium3.Sign(uPriv, SHA3-256(kayit_talebi))

3. eDevlet TC kimliğini doğrular ve eşleştirmeyi kendi veritabanında saklar:
   eDevlet_kaydi = {TC_kimlik ↔ uPub}  // eDevlet'te saklanır, dışarı çıkmaz

4. eDevlet yalnızca uPub'ı imzalayarak sertifika yayımlar:
   sertifika = Dilithium3.Sign(eDev_priv, SHA3-256(uPub))
   // TC_kimlik sertifikaya girmez — eDevlet'te kalır
   // Sertifika kullanıcı cihazında saklanır
```

**Bu aşamadan sonra:**
- eDevlet: TC_kimlik ↔ uPub ilişkisini bilir.
- BTK: yalnızca uPub'ı eDevlet'in onayladığını bilir. TC_kimlik'i bilmez.
- Üçüncü taraflar: hiçbir şey bilmez.
- **eDevlet runtime işlemlerine dahil olmaz.**

---

## 4. İşlem Aşaması

Protokolün iki farklı akışı vardır:

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
dog_hash = SHA3-256(uPub + hedef_platform + timestamp)
Dilithium3.Verify(uPub, dog_hash, talep_imzasi)

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

#### 4.2.1 Ephemeral Anahtar Üretimi ve Zincir İmzalama

```
// TEE içinde gerçekleşir
(ePriv, ePub) ← Dilithium3.KeyGen()
nonce         ← SHAKE-256(random_seed, 32)
session_id    ← SHAKE-256(ePub || nonce || timestamp, 32)

// ePriv, işlem içeriğini imzalar — ePub da islem içinde
islem  = {ePub, session_id, hedef_platform, timestamp}
e_imza = Dilithium3.Sign(ePriv, SHA3-256(islem))

// uPriv, e_imza'yı imzalar → ePriv'in bu kullanıcıya ait olduğu kanıtlanır
u_imza = Dilithium3.Sign(uPriv, SHA3-256(e_imza))

// BTK'ya gönderilir — ePriv hiç çıkmaz
btk_girdisi = {islem, e_imza, u_imza, sertifika}
```

**Tasarım kararı:** İşlemi imzalayan ePriv'dir, uPriv değil. Bu sayede ePriv çalınsa bile geçmiş ve gelecekteki oturumlar tehlikeye girmez (forward secrecy). uPriv yalnızca e_imza'yı imzalar — ePub zaten e_imza'nın içinde kriptografik olarak kilitlidir.

#### 4.2.2 BTK Doğrulama ve Token Üretimi

BTK, kullanıcının TC kimliğini görmez. eDevlet'e runtime'da sorgu göndermez. Yalnızca şunları yapar:

```
// 1. Sertifikayı doğrular → uPub, eDevlet tarafından onaylanmış mı?
//    TC_kimlik sertifikada yoktur — BTK yalnızca uPub'ın geçerliliğini doğrular
Dilithium3.Verify(eDev_pub, SHA3-256(uPub), sertifika)

// 2. u_imza → "e_imza, uPriv sahibinden geldi"
Dilithium3.Verify(uPub, SHA3-256(e_imza), u_imza)

// 3. e_imza → "işlemi imzalayan ePriv, ePub'a karşılık geliyor"
Dilithium3.Verify(ePub, SHA3-256(islem), e_imza)

// 4. CRL kontrolü — uPub iptal edilmiş mi?
//    BTK, CRL'yi önbelleğe alır ve periyodik olarak günceller (örn. her 5 dakika)
//    Token üretimi önbellek üzerinden kontrol yapılarak gerçekleştirilir
assert uPub not in CRL

// 5. BTK onay token'ı üretir ve imzalar
token     = {ePub, session_id, hedef_platform, gecerli: true, timestamp}
btk_token = Dilithium3.Sign(BTK_priv, SHA3-256(token))
```

**Bu adımda BTK elinde yalnızca uPub vardır. TC kimliği BTK'dan hiç geçmez. eDevlet devrede değildir.**

#### 4.2.3 Platform Doğrulaması

```
// Platform BTK token'ını alır ve doğrular
Dilithium3.Verify(BTK_pub, SHA3-256(token), btk_token)

// Platform token içindeki hedef_platform alanını kendi kimliğiyle karşılaştırır
assert token.hedef_platform == platform_id
// Eşleşmezse işlem reddedilir — token başka bir platformda kullanılamaz

// Platform şunu bilir:
// - Bu session geçerlidir
// - BTK onaylamıştır
// - Bu token yalnızca bu platform için üretilmiştir
// - TC kimliği: bilinmez, bilinemez
```

**hedef_platform garantisi:** Token çalınsa bile yalnızca üretildiği platformda geçerlidir. Farklı bir platforma sunulan token, hedef_platform eşleşmediği için otomatik olarak reddedilir.

#### 4.2.4 Oturum Şifrelemesi

Oturum anahtarı, platformun P_pub'ı kullanılarak kurulur. ePriv platform tarafına hiç gitmez.

```
// Kullanıcı tarafında (TEE içinde):
// Platform P_pub'ı ile kapsülleme yapar
(shared_secret, ciphertext) ← Kyber768.Encapsulate(P_pub)
session_key ← HKDF-SHA3-256(shared_secret, session_id, 32)
// ciphertext platforma gönderilir

// Platform tarafında:
// P_priv ile ciphertext açılır → aynı shared_secret elde edilir
shared_secret ← Kyber768.Decapsulate(P_priv, ciphertext)
session_key   ← HKDF-SHA3-256(shared_secret, session_id, 32)

// İşlem tamamlandığında TEE içinde temizlenir
TEE.purge(ePriv)
TEE.purge(session_key)
```

---

## 5. Erişim Katmanları

Protokol üç erişim seviyesi tanımlar. Platform türü, BTK token üretimi sırasında belirlenir ve kriptografik olarak bağlanır.

### Yeşil Seviye — Sosyal Medya ve Genel Platformlar

```
token = {onay_durumu: true, hedef_platform, seviye: "yesil", timestamp}
btk_token = Sign(BTK_priv, hash(token))
```

- TC kimliği: hiçbir noktada açığa çıkmaz.
- **ePriv/ephemeral anahtar kullanılmaz** — yalnızca kalıcı sertifika + uPriv imzası yeterlidir.
- Sertifika Yetkilisi (CA) dahil değildir.
- Platform yalnızca `onay_durumu: true` sinyalini alır.
- Platform, kullanıcıyı tanımak için kendi `callback_token` mekanizmasını kullanır; token içinde uPub veya ePub taşınmaz.
- BTK'nın döndüğü token, "bağlantısız" (unlinkable) olduğu için farklı oturumlar birbiriyle ilişkilendirilemez.

### Sarı Seviye — Bankalar, Sigorta, Kredi Kuruluşları

```
token = {ePub, session_id, hedef_platform, seviye: "sari", gecerli: true, timestamp}
```

- CA, token'a ek olarak geçici sertifika üretir; işlem sonunda siler.
- TC kimliği: hiçbir noktada açığa çıkmaz.
- Platform `gecerli: true` sinyalinin yanı sıra CA sertifikasını doğrular.

### Kırmızı Seviye — Devlet Daireleri, e-Devlet

Kırmızı seviyede BTK aracı değildir. Akış doğrudan kullanıcı ↔ eDevlet ↔ devlet dairesi üzerinden yürür.

```
// Kullanıcı, eDevlet'e doğrudan başvurur
kirmizi_talep = {uPub, session_id, hedef_daire, timestamp}
k_imza        = Dilithium3.Sign(uPriv, SHA3-256(kirmizi_talep))

// eDevlet TC kimliğini doğrular ve devlet dairesine imzalı yetki belgesi yayımlar
yetki_belgesi = Dilithium3.Sign(eDev_priv, SHA3-256(uPub || hedef_daire || session_id))

// TC kimliği yalnızca eDevlet ↔ devlet dairesi arasında kalır
// Kullanıcı cihazına TC kimliği dönmez
```

- TC kimliği yalnızca bu kanalda ve yalnızca yetkili devlet kurumlarına açılır.
- BTK bu kanalda hiç devrede değildir.

---

## 6. Anahtar İptali (Revocation)

uPriv çalınması veya cihaz kaybı durumunda sistemin bütünlüğünü korumak için iptal mekanizması gereklidir.

```
// Kullanıcı iptal talebinde bulunur (ikincil doğrulama ile — örn. kimlik belgesi)
iptal_talebi = {uPub, TC_kimlik, sebep, timestamp}

// eDevlet iptal listesini günceller (CRL)
CRL.add(uPub, timestamp)

// BTK her token üretiminde CRL'i kontrol eder (bölüm 4.2, adım 4)
assert uPub not in CRL
```

- eDevlet, iptal listesini (CRL) yönetir.
- BTK, CRL'yi önbelleğe alır ve periyodik olarak günceller — token üretimi önbellek üzerinden gerçekleşir, her işlemde ağ sorgusu yapılmaz.
- İptal edilen uPub ile üretilmiş önceki token'lar geçersiz sayılır.
- Kullanıcı yeni bir uPriv/uPub çifti üreterek yeniden kayıt yaptırabilir.

---

## 7. TEE Gereksinimi

uPriv ve ePriv yalnızca TEE (Trusted Execution Environment) içinde üretilir ve işlenir. İşletim sistemi dahil hiçbir yazılım katmanı bu anahtarlara erişemez.

**Desteklenen TEE implementasyonları:**
- ARM TrustZone (mobil cihazlar) — en yaygın ve önerilen
- Intel TDX / SGX (masaüstü ve sunucu)
- AMD SEV (sunucu)

**TEE yoksa:** Protokol çalışmaz. Yazılımsal izolasyon, uPriv güvenliği için yeterli kabul edilmez. Protokol "TEE zorunludur" olarak tanımlar.

> **Not:** PC ortamında Intel SGX birçok sistemde devre dışıdır veya kısıtlıdır. AMD SEV ise ağırlıklı olarak sunucu ortamlarına yöneliktir. Bu nedenle GKDP, öncelikli hedef platform olarak ARM TrustZone tabanlı mobil cihazları esas alır. PC desteği, TEE standardizasyonunun olgunlaşmasıyla birlikte genişleyecektir.

---

## 8. Güvenlik Özellikleri

### Forward Secrecy
**Sadece Sarı seviyede** geçerlidir. Her işlem bağımsız bir ephemeral anahtar çifti (ePriv/ePub) kullanır. Geçmiş oturumlar, ePriv silindiğinden geriye dönük olarak çözülemez.

Yeşil seviyede forward secrecy gerekmez çünkü işlem içeriği imzalanmaz; yalnızca varlık doğrulaması yapılır.

### Kimlik Bağlantısızlığı (Unlinkability)
Her session_id bağımsız türetilir. Farklı platformlardaki işlemler kriptografik olarak birbirine bağlanamaz — ne BTK tarafından, ne de platformlar tarafından. Not: uPub sabit olduğundan sistem düzeyinde korelasyon teorik olarak mümkündür; bu risk CRL önbellekleme stratejisi ile minimize edilir.

### Kuantum Direnci
Tüm imzalama ve anahtar kapsülleme işlemleri kafes tabanlı (lattice-based) algoritmalar kullanır. RSA ve ECDH tabanlı sistemlere karşı Shor algoritmasıyla gerçekleştirilebilecek kuantum saldırıları bu protokole uygulanamaz.

### Token Bağlama (Token Binding)
Her token yalnızca belirli bir platform için üretilir. `hedef_platform` alanı sayesinde token çalınsa bile başka bir platformda kullanılamaz.

### eDevlet Runtime Bağımsızlığı
eDevlet yalnızca kayıt ve iptal aşamalarında devrededir. Runtime işlemlerinde eDevlet'in erişilebilirliği sistemin çalışmasını etkilemez.

---

## 9. Tehdit Modeli

| Tehdit | Etki | Protokol Yanıtı |
|---|---|---|
| Platform ihlali | Saldırgan platform veritabanını ele geçirir | TC kimliği platformda yoktur — sızdırılacak veri yoktur |
| BTK ihlali | BTK altyapısı tehlikeye girer | BTK'da TC kimliği yoktur — uPub listeleri açığa çıkabilir |
| Token çalınması | Başka platformda kullanılmaya çalışılır | hedef_platform eşleşmediği için reddedilir |
| uPriv çalınması | Saldırgan kullanıcı adına işlem yapabilir | CRL ile iptal, yeni kayıt |
| Oturum dinleme | Ağ trafiği izlenir | Kyber-768 ile şifrelenmiş, ephemeral anahtar ile korunmuş |
| Tekrar saldırısı (replay) | Eski token tekrar kullanılır | session_id + timestamp + nonce kombinasyonu tekrarı engeller |
| Kuantum saldırısı | Gelecekte kuantum bilgisayar ile şifre çözme | Dilithium3 + Kyber-768 kuantum dirençlidir |
| eDevlet kesintisi | Runtime işlemler durur | eDevlet runtime'da devrede değildir — etki yok |

---

## 10. Referanslar

- FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (Kyber)
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (Dilithium)
- FIPS 202 — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- Chaum, D. (1982) — Blind Signatures for Untraceable Payments

---

*Politika yapıcılara yönelik genel belge için README.md dosyasına bakınız.*  
*https://github.com/guvenacar/GKDP-Guvenli-Kimlik-Dogrulama-Protokolu/blob/main/README.md*
