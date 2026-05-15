# Güvenli Kimlik Doğrulama Protokolü — Teknik Spesifikasyon

**Hazırlayan:** Güven ACAR — İzmir, 2026  
**Kaynak:** https://github.com/guvenacar/GKDP-Guvenli-Kimlik-Dogrulama-Protokolu  
**Versiyon:** 0.1-draft

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

### 2.2 ePriv / ePub — Ephemeral Anahtar Çifti

```
(ePriv, ePub) ← Dilithium3.KeyGen()
nonce         ← SHAKE-256(random_seed, 32)
session_id    ← SHAKE-256(ePub || nonce || timestamp, 32)
```

- Her işlem başlangıcında TEE içinde sıfırdan üretilir.
- İşlem tamamlandığında TEE tarafından güvenli şekilde silinir (purge).
- uPriv ile doğrudan ilişkisi yoktur — bağlantı yalnızca imza zinciri üzerinden kurulur.

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

- Kimlik doğrulama yanıtlarını imzalamak için kullanılır.
- eDevlet_pub, BTK tarafından bilinir.

---

## 3. Kayıt Aşaması (Tek Seferlik)

Kullanıcı sisteme ilk kez dahil olurken gerçekleşir.

```
1. TEE içinde uPriv/uPub üretilir.

2. Kullanıcı eDevlet'e başvurur:
   kayit_talebi = {uPub, TC_kimlik, zaman_damgasi}
   imzali_talep = Dilithium3.Sign(uPriv, SHA3-256(kayit_talebi))

3. eDevlet TC kimliğini doğrular:
   eDevlet_kaydı = {TC_kimlik ↔ uPub}  // eDevlet'te saklanır

4. eDevlet kullanıcıya sertifika yayımlar:
   sertifika = Dilithium3.Sign(eDevlet_priv, SHA3-256(uPub || TC_kimlik))
```

**Bu aşamadan sonra:**
- eDevlet: TC_kimlik ↔ uPub ilişkisini bilir.
- BTK: bu ilişkiyi bilmez.
- Üçüncü taraflar: bu ilişkiyi bilmez.

---

## 4. İşlem Aşaması

### 4.1 Ephemeral Anahtar Üretimi ve İmzalama

```
// TEE içinde gerçekleşir
(ePriv, ePub) ← Dilithium3.KeyGen()
nonce         ← SHAKE-256(random_seed, 32)
session_id    ← SHAKE-256(ePub || nonce || timestamp, 32)

// Kullanıcı ephemeral anahtarı uPriv ile imzalar
talep_paketi  = {ePub, session_id, hedef_platform, timestamp}
u_imza        = Dilithium3.Sign(uPriv, SHA3-256(talep_paketi))

// BTK'ya gönderilir
btk_girdisi   = {talep_paketi, u_imza}
```

### 4.2 BTK Doğrulama ve Kör İmzalama

BTK, kullanıcının TC kimliğini görmez. Yalnızca şunları yapar:

```
// 1. Kullanıcı imzasını uPub ile doğrular
gecerli = Dilithium3.Verify(uPub, SHA3-256(talep_paketi), u_imza)

// 2. eDevlet'e soru sorar: "Bu uPub'a ait kullanıcı geçerli mi?"
edev_sorgu   = {uPub, session_id}
edev_imzali  = Dilithium3.Sign(eDevlet_priv, SHA3-256(edev_sorgu))

// 3. eDevlet yanıtlar: "evet/hayır" — TC kimliğini BTK'ya iletmez
edev_yanit   = {gecerli: true, session_id}
edev_yanit_imza = Dilithium3.Sign(eDevlet_priv, SHA3-256(edev_yanit))

// 4. BTK yanıtı doğrular
Dilithium3.Verify(eDevlet_pub, SHA3-256(edev_yanit), edev_yanit_imza)

// 5. BTK onay token'ı üretir ve imzalar
token        = {ePub, session_id, hedef_platform, gecerli: true, timestamp}
btk_token    = Dilithium3.Sign(BTK_priv, SHA3-256(token))
```

**Bu adımda BTK elinde yalnızca uPub vardır. TC kimliği BTK'dan hiç geçmez.**

### 4.3 Platform Doğrulaması

```
// Platform BTK token'ını alır
Dilithium3.Verify(BTK_pub, SHA3-256(token), btk_token)

// Platform şunu bilir:
// - Bu session geçerlidir
// - BTK onaylamıştır
// - TC kimliği: bilinmez, bilinemez
```

### 4.4 Oturum İletişimi

Platform ile kullanıcı arasındaki oturum, ephemeral anahtar çifti üzerinden Kyber-768 ile kurulur:

```
// Anahtar kapsülleme
(shared_secret, ciphertext) ← Kyber768.Encapsulate(ePub)
session_key ← HKDF-SHA3-256(shared_secret, session_id, 32)

// İşlem tamamlandığında
TEE.purge(ePriv)
TEE.purge(session_key)
```

---

## 5. Erişim Katmanları

Protokol üç erişim seviyesi tanımlar. Platform türü, BTK token üretimi sırasında belirlenir ve kriptografik olarak bağlanır.

### Yeşil Seviye — Sosyal Medya ve Genel Platformlar
- BTK token içerir: `{gecerli: true}`
- TC kimliği: hiçbir noktada açığa çıkmaz
- Sertifika Yetkilisi (CA) dahil değildir

### Sarı Seviye — Bankalar, Sigorta, Kredi Kuruluşları
- BTK token içerir: `{gecerli: true, risk_skoru: opsiyonel}`
- CA geçici sertifika üretir, işlem sonunda siler
- TC kimliği: hiçbir noktada açığa çıkmaz

### Kırmızı Seviye — Devlet Daireleri, e-Devlet
- eDevlet doğrudan yanıt verir
- TC kimliği yalnızca bu kanalda ve yalnızca yetkili devlet kurumlarına açılır
- BTK bu kanalda aracı değildir

---

## 6. Güvenlik Özellikleri

### Forward Secrecy
Her işlem bağımsız bir ephemeral anahtar çifti kullanır. Geçmiş oturumlar, ePriv silindiğinden geriye dönük olarak çözülemez.

### Kimlik Bağlantısızlığı (Unlinkability)
Her session_id bağımsız türetilir. Farklı platformlardaki işlemler birbirine bağlanamaz — ne BTK tarafından, ne de platformlar tarafından.

### Kuantum Direnci
Tüm imzalama ve anahtar kapsülleme işlemleri kafes tabanlı (lattice-based) algoritmalar kullanır. RSA ve ECDH tabanlı sistemlere karşı Shor algoritmasıyla gerçekleştirilebilecek kuantum saldırıları bu protokole uygulanamaz.

### TEE İzolasyonu
uPriv ve ePriv yalnızca TEE içinde işlenir. İşletim sistemi dahil hiçbir yazılım katmanı bu anahtarlara erişemez.

---

## 7. Tehdit Modeli

| Tehdit | Etki | Protokol Yanıtı |
|---|---|---|
| Platform ihlali | Saldırgan platform veritabanını ele geçirir | TC kimliği platformda yoktur — sızdırılacak veri yoktur |
| BTK ihlali | BTK altyapısı tehlikeye girer | BTK'da TC kimliği yoktur — uPub listeleri açığa çıkabilir |
| Oturum dinleme | Ağ trafiği izlenir | Kyber-768 ile şifrelenmiş, ephemeral anahtar ile korunmuş |
| Tekrar saldırısı (replay) | Eski token tekrar kullanılır | session_id + timestamp + nonce kombinasyonu tekrarı engeller |
| Kuantum saldırısı | Gelecekte kuantum bilgisayar ile şifre çözme | Dilithium3 + Kyber-768 kuantum dirençlidir |

---

## 8. Referanslar

- FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (Kyber)
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (Dilithium)
- FIPS 202 — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- Chaum, D. (1982) — Blind Signatures for Untraceable Payments

---

*Politika yapıcılara yönelik genel belge için README.md dosyasına bakınız.*  
*https://github.com/guvenacar/README.md*
