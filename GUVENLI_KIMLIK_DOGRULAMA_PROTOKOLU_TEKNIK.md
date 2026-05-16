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
| Hash | SHA-3 / SHAKE-256 | FIPS 202 |
| Geçici anahtar türetme | HKDF-SHA3-256 | RFC 5869 |

> **Not:** Oturum şifrelemesi (CRYSTALS-Kyber / Kyber-768, FIPS 203) bu belgenin kapsamı dışındadır ve ayrı bir teknik belgede ele alınacaktır.

---

## 2. Bileşenler ve Anahtar Yapısı

### 2.1 uPriv / uPub — Kullanıcı Uzun Dönem Anahtar Çifti

```
(uPriv, uPub) ← Dilithium3.KeyGen()
```

- **uPriv:** Kullanıcının kalıcı gizli anahtarı. Donanımsal güvenlik bölgesinde (TEE) üretilir ve saklanır. Cihazdan asla çıkmaz. Export edilemez.
- **uPub:** Kullanıcının kalıcı açık anahtarı. Kayıt aşamasında eDevlet'e iletilir ve kullanıcı kimliğiyle ilişkilendirilir.

### 2.2 ePriv / ePub — Ephemeral Anahtar Çifti

```
(ePriv, ePub) ← Dilithium3.KeyGen()
```

- Yalnızca Sarı seviye işlemlerde kullanılır (bkz. Bölüm 5.2).
- Her işlem başlangıcında TEE içinde sıfırdan üretilir.
- İşlem tamamlandığında TEE tarafından güvenli şekilde silinir (purge).

### 2.3 BTK Anahtar Çifti

```
(BTK_priv, BTK_pub) ← Dilithium3.KeyGen()
```

- BTK_pub kamuya açık şekilde yayımlanır.
- Tüm taraflar BTK imzasını bağımsız olarak doğrulayabilir.

### 2.4 eDevlet Anahtar Çifti

```
(eDev_priv, eDev_pub) ← Dilithium3.KeyGen()
```

- Kayıt aşamasında kullanıcı sertifikalarını imzalamak için kullanılır.
- eDev_pub, BTK tarafından bilinir.

---

## 3. Kayıt Aşaması (Tek Seferlik)

Kullanıcı sisteme ilk kez dahil olurken gerçekleşir. eDevlet yalnızca bu aşamada ve iptal aşamasında devrededir — runtime işlemlerinde yer almaz.

```
1. TEE içinde uPriv/uPub üretilir.

2. Kullanıcı eDevlet'e başvurur:
   kayit_talebi = {uPub, TC_kimlik, timestamp}
   imzali_talep = Dilithium3.Sign(uPriv, SHA3-256(kayit_talebi))

3. eDevlet TC kimliğini doğrular ve eşleştirmeyi kendi veritabanında saklar:
   eDevlet_kaydi = {TC_kimlik ↔ uPub}  // eDevlet'te saklanır, dışarı çıkmaz

4. eDevlet yalnızca uPub'ı imzalayarak sertifika yayımlar:
   sertifika = Dilithium3.Sign(eDev_priv, SHA3-256(uPub))
   // TC_kimlik sertifikaya girmez — eDevlet'te kalır
   // Sertifika kullanıcının izole alanında saklanır
```

**Bu aşamadan sonra:**
- eDevlet: TC_kimlik ↔ uPub ilişkisini bilir.
- BTK: yalnızca uPub'ı eDevlet'in onayladığını bilir. TC_kimlik'i bilmez.
- Üçüncü taraflar: hiçbir şey bilmez.
- **eDevlet runtime işlemlerine dahil olmaz.**

---

## 4. Temel Prensip: İmza Ne Zaman Gereklidir?

Bu protokol imzalama gereksinimini şu kurala bağlar:

> **İmzalanacak bir işlem içeriği yoksa imza mekanizması gereksizdir.**

| Seviye | İşlem İçeriği | ePriv | Açıklama |
|---|---|---|---|
| Yeşil | Yok — sadece "gerçek mi?" sorusu | ❌ | uPriv ile talep imzası yeterli |
| Sarı | Var — belirli bir işlem onayı | ✅ | Forward secrecy gerekli |
| Kırmızı | Yok — doğrudan eDevlet kanalı | ❌ | BTK devre dışı |

---

## 5. İşlem Aşaması

### 5.1 Yeşil Seviye — Sosyal Medya ve Genel Platformlar

**Soru:** "Bu kullanıcı gerçek bir vatandaş mı?"  
**ePriv kullanılmaz.** Talep uPriv ile imzalanır, sertifika kanıt olarak sunulur.

#### Adım 1 — Platform isteği

Platform (örn. Facebook), kullanıcının izole alanına kimlik doğrulama isteği gönderir:

```
platform_istegi = {
    hedef_platform,    // "facebook.com"
    firma_istegi,      // "kullanici_gercek_mi"
    timestamp,
    nonce*
}
```

#### Adım 2 — İzole alan BTK'ya iletir

```
talep_imzasi = Dilithium3.Sign(uPriv, SHA3-256(uPub || hedef_platform || timestamp || nonce*))

btk_istegi = {
    eDevlet_sertifikasi,    // eDevlet'in imzaladığı, içinde uPub olan belge
    talep_imzasi,           // uPriv ile imzalanmış talep
    hedef_platform,
    firma_istegi,
    timestamp,
    nonce*
}
```

#### Adım 3 — BTK doğrular

```
// 1. Sertifikadan uPub'ı çıkar
uPub ← extract(eDevlet_sertifikasi)

// 2. Sertifika geçerli mi? (eDevlet imzası)
Dilithium3.Verify(eDev_pub, SHA3-256(uPub), eDevlet_sertifikasi)

// 3. Talebi gerçekten uPub sahibi mi imzaladı?
Dilithium3.Verify(uPub, SHA3-256(uPub || hedef_platform || timestamp || nonce*), talep_imzasi)

// 4. CRL kontrolü — uPub iptal edilmiş mi?
assert uPub not in CRL

// 5. Firma isteği yetkili mi?
//    Örn: firma TC kimliği talep ediyorsa → reddedilir
assert firma_istegi in izin_verilen_istekler
```

#### Adım 4 — BTK token üretir ve izole alana gönderir

```
token = {
    hedef_platform,
    seviye: "yesil",
    gecerli: true,
    timestamp
}
btk_token = Dilithium3.Sign(BTK_priv, SHA3-256(token))
```

#### Adım 5 — İzole alan platformu bilgilendirir

Token geçerliyse platform girişe izin verir. TC kimliği hiçbir aşamada platforma iletilmez. Platform, kullanıcıyı kendi oturumuyla ilişkilendirmek için kendi ürettiği bir callback_token kullanır — BTK token içinde kullanıcıya ait hiçbir tanımlayıcı taşınmaz.

---

### 5.2 Sarı Seviye — Bankalar, Sigorta, Kredi Kuruluşları

Sarı seviyede kullanıcı belirli bir işlem içeriğini onaylar. ePriv/ePub bu aşamada devreye girer; forward secrecy sağlanır. CA geçici sertifika üretir ve işlem sonunda siler.

> Sarı seviye detaylı akışı bir sonraki belgede ele alınacaktır.

---

### 5.3 Kırmızı Seviye — Devlet Daireleri, e-Devlet

Kırmızı seviyede BTK aracı değildir. Akış doğrudan kullanıcı ↔ eDevlet ↔ devlet dairesi üzerinden yürür.

```
kirmizi_talep = {uPub, session_id, hedef_daire, timestamp}
k_imza        = Dilithium3.Sign(uPriv, SHA3-256(kirmizi_talep))

// eDevlet TC kimliğini doğrular ve devlet dairesine imzalı yetki belgesi yayımlar
yetki_belgesi = Dilithium3.Sign(eDev_priv, SHA3-256(uPub || hedef_daire || session_id))
```

- TC kimliği yalnızca eDevlet ↔ devlet dairesi arasında kalır.
- BTK bu kanalda hiç devrede değildir.

---

## 6. Anahtar İptali (Revocation)

uPriv çalınması veya cihaz kaybı durumunda:

```
// Kullanıcı ikincil doğrulama ile (örn. kimlik belgesi) eDevlet'e başvurur
CRL.add(uPub, timestamp)
```

- eDevlet iptal listesini (CRL) yönetir.
- BTK, CRL'yi önbelleğe alır ve periyodik olarak günceller. Token üretimi sırasında ağ sorgusu yapılmaz, önbellek üzerinden kontrol edilir.
- Kullanıcı yeni uPriv/uPub çifti üreterek yeniden kayıt yaptırabilir.

---

## 7. TEE Gereksinimi

uPriv ve ePriv yalnızca TEE (Trusted Execution Environment) içinde üretilir ve işlenir.

**Desteklenen implementasyonlar:**
- ARM TrustZone (mobil cihazlar) — öncelikli hedef platform
- Intel TDX / SGX (masaüstü ve sunucu)
- AMD SEV (sunucu)

**TEE yoksa:** Protokol çalışmaz. Yazılımsal izolasyon yeterli kabul edilmez.

> **Not:** Intel SGX birçok PC'de devre dışıdır; AMD SEV ağırlıklı olarak sunucu ortamlarına yöneliktir. GKDP öncelikli hedef olarak ARM TrustZone tabanlı mobil cihazları esas alır. PC desteği TEE standardizasyonunun olgunlaşmasıyla genişleyecektir.

---

## 8. Güvenlik Özellikleri

### Forward Secrecy
Sarı seviyede her işlem bağımsız bir ephemeral anahtar çifti kullanır. ePriv silindiğinden geçmiş oturumlar geriye dönük olarak çözülemez. Yeşil seviyede işlem içeriği olmadığından forward secrecy gerekmez.

### Kimlik Bağlantısızlığı (Unlinkability)
TC kimliği hiçbir zaman platforma iletilmez. Her token bağımsız nonce ve timestamp içerir. uPub sabit olduğundan sistem düzeyinde korelasyon teorik olarak mümkündür; bu risk CRL önbellekleme stratejisi ile minimize edilir.

### Kuantum Direnci
Tüm imzalama işlemleri kafes tabanlı (lattice-based) Dilithium3 algoritması kullanır. RSA ve ECDH tabanlı sistemlere karşı Shor algoritmasıyla gerçekleştirilebilecek kuantum saldırıları bu protokole uygulanamaz.

### Token Bağlama (Token Binding)
Her token `hedef_platform` alanı ile belirli bir platforma bağlıdır. Token çalınsa bile başka bir platformda kullanılamaz.

### Yetkisiz Talep Reddi
BTK, firma_istegi alanını denetler. Platform TC kimliği veya protokol kapsamı dışında bir bilgi talep ederse BTK isteği reddeder ve token üretmez.

### eDevlet Runtime Bağımsızlığı
eDevlet yalnızca kayıt ve iptal aşamalarında devrededir. Runtime işlemlerinde eDevlet kesintisi sistemi etkilemez.

---

## 9. Tehdit Modeli

| Tehdit | Etki | Protokol Yanıtı |
|---|---|---|
| Platform ihlali | Saldırgan platform veritabanını ele geçirir | TC kimliği platformda yoktur — sızdırılacak veri yoktur |
| BTK ihlali | BTK altyapısı tehlikeye girer | BTK'da TC kimliği yoktur — uPub listeleri açığa çıkabilir |
| Token çalınması | Başka platformda kullanılmaya çalışılır | hedef_platform eşleşmediği için reddedilir |
| uPriv çalınması | Saldırgan kullanıcı adına işlem yapabilir | CRL ile iptal, yeni kayıt |
| Yetkisiz firma talebi | Platform TC kimliği talep eder | BTK firma_istegi kontrolü ile reddeder |
| Tekrar saldırısı (replay) | Eski token tekrar kullanılır | timestamp + nonce kombinasyonu tekrarı engeller |
| Kuantum saldırısı | Gelecekte kuantum bilgisayar ile şifre çözme | Dilithium3 kuantum dirençlidir |
| eDevlet kesintisi | Runtime işlemler durur | eDevlet runtime'da devrede değildir — etki yok |

---

## 10. Referanslar

- FIPS 204 — Module-Lattice-Based Digital Signature Standard (Dilithium)
- FIPS 202 — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- Chaum, D. (1982) — Blind Signatures for Untraceable Payments

---

*Politika yapıcılara yönelik genel belge için README.md dosyasına bakınız.*  
*https://github.com/guvenacar/GKDP-Guvenli-Kimlik-Dogrulama-Protokolu/blob/main/README.md*

---

**Dipnotlar**

*\*nonce: TEE'nin donanımsal rastgele sayı üreticisinden (TRNG) elde edilen, tek kullanımlık 32 baytlık değer. Her istekte sıfırdan üretilir, bir daha kullanılmaz.*
