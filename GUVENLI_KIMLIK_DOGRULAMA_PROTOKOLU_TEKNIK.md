# Güvenli Kimlik Doğrulama Protokolü — Teknik Spesifikasyon

**Hazırlayan:** Güven ACAR — İzmir, 2026  
**Kaynak:** https://github.com/guvenacar/GKDP-Guvenli-Kimlik-Dogrulama-Protokolu  
**Versiyon:** 0.9-draft

---

> **Köken:** GKDP, [EIDA (Ephemeral Identity Distribution Architecture)](https://github.com/guvenacar/EIDA) protokolünün Türkiye kamu gereksinimlerine göre uyarlanmış bir türevidir. EIDA'nın temel mimari ilkesi olan *"güvenliği merkezi yapıdan alıp kullanıcı cihazlarına dağıtma"* yaklaşımı GKDP'de aynen korunmuştur. Bu sayede BTK altyapısı saldırıya uğrasa dahi saldırganların eline yalnızca anlamsız hash çıktıları ve oturumluk geçici tanımlayıcılar geçer — kullanıcı kimlik bilgileri (TC kimlik, uPriv) BTK dahil hiçbir merkezi sistemde bulunmaz. Saldırı yüzeyi tek bir kritik sistemden milyonlarca bireysel cihaza dağıtılmıştır.

## 1. Kriptografik Primitifler

Bu protokol yalnızca NIST onaylı, kuantum dirençli algoritmalar kullanır.

| Kullanım Amacı | Algoritma | Standart |
|---|---|---|
| İmzalama | CRYSTALS-Dilithium (Dilithium3) | FIPS 204 |
| Anahtar Kapsülleme (KEM) | CRYSTALS-Kyber (Kyber-768) | FIPS 203 |
| Simetrik Şifreleme | AES-256-GCM | FIPS 197, SP 800-38D |
| Hash | SHA-3 / SHAKE-256 | FIPS 202 |
| Anahtar türetme | HKDF-SHA3-256 | RFC 5869 |

> **Kyber-768 + AES-256-GCM Akışı:** Kyber-768 bir Anahtar Kapsülleme Mekanizmasıdır (KEM) — doğrudan veri şifrelemez. Protokolde önce Kyber ile paylaşılan sır (shared secret) elde edilir, HKDF ile AES anahtarı türetilir, ardından veri AES-256-GCM ile şifrelenir. Bu, hibrit KEM + DEM (Data Encapsulation Mechanism) yaklaşımıdır.

---

## 2. Bileşenler ve Anahtar Yapısı

### 2.1 uPriv / uPub — Kullanıcı Uzun Dönem Anahtar Çifti

```
(uPriv, uPub) ← Dilithium3.KeyGen()
```

- **uPriv:** Kullanıcının kalıcı gizli anahtarı. Donanımsal güvenlik bölgesinde (TEE) üretilir ve saklanır. Cihazdan asla çıkmaz. Export edilemez.
- **uPub:** Kullanıcının kalıcı açık anahtarı. Kayıt aşamasında eDevlet'e iletilir ve kullanıcı kimliğiyle ilişkilendirilir.

### 2.2 ePriv / ePub — Ephemeral Oturum Anahtar Çifti

```
(ePriv, ePub) ← Dilithium3.KeyGen()
```

- **ePub:** Oturumluk geçici açık anahtar. Her giriş oturumunda TEE tarafından sıfırdan üretilir. Kullanıcının "kimliksiz" oturum tanımlayıcısıdır.
- **ePriv:** Oturumluk geçici gizli anahtar. TEE içinde kalır, yalnızca imzalama için kullanılır, asla dışarı çıkmaz.
- **Yaşam döngüsü:** Oturum başlangıcında TEE tarafından üretilir, oturum sonunda güvenli şekilde silinir (purge).
- **Kullanım:** Yeşil seviyede (5.1) oturum tanımlayıcı ve imza zinciri için kullanılır. Sarı seviye (5.2) ayrı bir ephemeral mekanizma kullanır.
- **Amaç:** Aynı kullanıcının farklı oturumlarını birbirine bağlamayı (korelasyon) engellemek. BTK her oturumda farklı ePub görür.

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

### 2.5 Kullanıcı Token Çiftleri — Oturumluk Kimliksiz Tanımlayıcılar

Kayıt aşamasında eDevlet, her kullanıcı için N adet (varsayılan: 1000) rastgele hash çifti üretir:

```
Her çift (n = 1..N) için:
  h1_n, h2_n ← CSPRNG(256 bit)           // birbirinden bağımsız rastgele
  cert_n = Dilithium3.Sign(eDev_priv, h1_n || h2_n)  // eDevlet onaylı çift

  BTK_token_n    = HybridEncrypt(BTK_pub, {h1_n, h2_n, cert_n})
  Kullanici_token_n = {h1_n, h2_n, cert_n}
```

- **Kullanici_token_n:** TEE içinde düz metin saklanır (TEE koruması altında). Her oturumda bir tanesi tüketilir.
- **BTK_token_n:** BTK'nın açık anahtarı ile şifrelidir — yalnızca BTK açabilir. TEE bu veriyi açamaz; oturumda BTK'ya iletir.
- **cert_n:** eDevlet'in `h1_n || h2_n` üzerindeki imzası. BTK, çiftin eDevlet onaylı olduğunu bu imzadan doğrular.
- **h1_n:** BTK'nın gördüğü tanımlayıcı. Her oturumda farklıdır — korelasyon imkansızdır.
- **h2_n:** Firmaya token içinde iletilen tanımlayıcı. Firma için anlamsızdır; TEE, BTK'nın doğru çifti işlediğini h2 üzerinden doğrular.
- **eDevlet indeks tablosu:** Kayıt aşamasında her kullanıcı için bir `user_seed = HMAC-SHA3(K_eDev, uPub)` saklanır. Token çiftleri bu seed'den deterministik türetilir — her token için ayrı indeks kaydı gerekmez. Adli süreçte eDevlet, verilen h1 değerini tüm kullanıcı seed'lerine karşı tarar (~85M HMAC, ~2 saniye). Runtime'da sorgulanmaz.
- **Tükenme:** Tokenlar bittiğinde kullanıcı çevrimiçi olarak eDevlet'ten yeni paket alır. 1000 token ≈ 1-3 yıllık kullanım.

### 2.6 Firma Anahtar Çifti (Platform)

```
(F_priv, F_pub) ← Kyber768.KeyGen()
```

- Her platform (X.com, Facebook, banka vb.) kendi Kyber-768 anahtar çiftini üretir.
- **F_pub:** Platformun açık anahtarı. BTK tarafından kayıt altına alınır ve token şifrelemede kullanılır.
- **F_priv:** Platformun gizli anahtarı. Firmanın kendi sunucularında saklanır. BTK'dan gelen şifreli token'ı yalnızca F_priv ile açabilir.
- **Amaç:** BTK'nın ürettiği token'ın yalnızca hedef platform tarafından okunabilmesini sağlamak.

---

### 3.0. Fiziksel Güven Başlangıcı (Trust-on-First-Use)

uPriv/uPub ilk kez üretildiğinde, bu anahtar çiftinin **gerçek kullanıcıya ait olduğu** eDevlet tarafından doğrulanmalıdır.

Bu nedenle kayıt işlemi, **fiziksel bir güven ortamında** başlatılır:

- **Önerilen yöntem:** Kullanıcı, bir PTT şubesine veya nüfus müdürlüğüne gider. Görevli, kimlik kartını okutur ve kullanıcının cihazında TEE tarafından üretilen uPub'ı (ekranda gösterilen) sisteme onaylar. eDevlet, bu onayla birlikte `TC_kimlik ↔ uPub` eşlemesini kaydeder.
- **Alternatif (uzaktan):** eDevlet'in güvenli mobil uygulaması, yüz tanıma ve biyometrik doğrulama ile kullanıcının kimliğini onaylar. Uygulama, TEE içinde üretilen uPub'ı doğrudan eDevlet'e iletir. Bu yöntem, cihazın TEE'sinin (TrustZone) güvenli olduğu varsayımına dayanır.

**Bu adım olmadan, bir saldırgan rastgele uPub üretip başkasının TC'siyle kaydedemez.**

---

## 3. Kayıt Aşaması (Tek Seferlik)

Kullanıcı sisteme ilk kez dahil olurken gerçekleşir. eDevlet yalnızca bu aşamada ve iptal aşamasında devrededir — runtime işlemlerinde yer almaz.

```
1. TEE içinde uPriv/uPub üretilir.
   uPubHash = SHA3-256(uPub)  // TEE içinde hesaplanır

2. Kullanıcı eDevlet'e başvurur:
   kayit_talebi = {uPub, uPubHash, TC_kimlik, timestamp}
   imzali_talep = Dilithium3.Sign(uPriv, SHA3-256(kayit_talebi))

3. eDevlet TC kimliğini doğrular ve eşleştirmeyi kendi veritabanında saklar:
   eDevlet_kaydi = {TC_kimlik ↔ uPub ↔ uPubHash}  // eDevlet'te saklanır, dışarı çıkmaz

4. eDevlet yalnızca uPub'ı imzalayarak sertifika yayımlar:
   sertifika = Dilithium3.Sign(eDev_priv, SHA3-256(uPub))
   // TC_kimlik sertifikaya girmez — eDevlet'te kalır
   // Sertifika kullanıcının TEE'sinde saklanır
```

5. eDevlet N adet token çifti üretir ve TEE'ye yükler:
   for n = 1..N:
     h1_n, h2_n ← CSPRNG(256 bit)
     cert_n = Dilithium3.Sign(eDev_priv, h1_n || h2_n)
     BTK_token_n = HybridEncrypt(BTK_pub, {h1_n, h2_n, cert_n})
     Kullanici_token_n = {h1_n, h2_n, cert_n}
   // eDevlet, token çiftlerini HMAC ile deterministik türetir:
   //   user_seed = HMAC-SHA3(K_eDev, uPub)
   //   h1_n = HMAC-SHA3(user_seed, "h1" || n)
   //   h2_n = HMAC-SHA3(user_seed, "h2" || n)
   // Bu sayede her token çifti için ayrı indeks kaydı gerekmez.
   // Adli süreçte: eDevlet h1'i alır, tüm kullanıcıların user_seed'lerini
   // tarar (~85M HMAC, modern donanımda ~2 saniye). Eşleşen kullanıcı bulunur.
   TEE'ye N adet {BTK_token_n, Kullanici_token_n} yüklenir.
```

**Bu aşamadan sonra:**
- eDevlet: TC_kimlik ↔ uPub ↔ {tüm h1_n, h2_n} ilişkisini bilir.
- BTK: hiçbir şey bilmez (token çiftleri henüz BTK'ya iletilmemiştir).
- Üçüncü taraflar: hiçbir şey bilmez.
- **eDevlet runtime işlemlerine dahil olmaz.**

---

## 4. Temel Prensip: İmza Ne Zaman Gereklidir?

Bu protokol imzalama gereksinimini şu kurala bağlar:

> **İmzalanacak bir işlem içeriği yoksa imza mekanizması gereksizdir.**

| Seviye | İşlem İçeriği | Kimlik Mekanizması | Açıklama |
|---|---|---|---|
| Yeşil | Yok — sadece "gerçek mi?" sorusu | ePub + h1/h2 token çifti | Her oturumda yeni ePub + tek kullanımlık çift; BTK korelasyon yapamaz |
| Sarı | Var — belirli bir işlem onayı | ePub + ephemeral imza | Forward secrecy gerekli (ileri versiyon) |
| Kırmızı | Yok — doğrudan eDevlet kanalı | uPub + uPriv imzası | BTK devre dışı; eDevlet doğrudan doğrular |

---

## 5. İşlem Aşaması

### 5.1 Yeşil Seviye — Sosyal Medya ve Genel Platformlar

**Soru:** "Bu kullanıcı gerçek bir vatandaş mı?"  
**İşlem içeriği yoktur.** Kullanıcı kimliği iki katmanlı imza zinciri ile kanıtlanır.

> **TEE Konumu:** TEE yalnızca kullanıcı cihazında bulunur. Firma sunucularında TEE zorunluluğu yoktur.

#### 5.1.1. Nonce Kullanımı ve Replay Attack Önleme

Nonce, TEE'nin donanımsal rastgele sayı üreticisinden (TRNG) elde edilen 16 baytlık tek kullanımlık değerdir:

```
nonce ← SHAKE-256(TRNG_random, 16)
```

Nonce şu saldırıları önler:
- **Tekrar saldırısı (Replay attack):** Aynı `(ePub, timestamp, nonce)` kombinasyonu tekrar kullanılamaz.
- **Zamanlama çakışması:** İki farklı oturum aynı timestamp'e sahip olsa bile nonce farklı olur.

BTK, son N (varsayılan: 10.000) `(ePub, nonce)` çiftini geçici önbellekte tutar. Aynı nonce tekrar gelirse isteği reddeder.

> **Ölçek Notu:** Her oturumda yeni bir `ePub` üretildiği için aynı `(ePub, nonce)` çiftinin tekrar kullanılması mümkün değildir. Bu nedenle nonce cache mekanizması yeterlidir; ayrı bir **signed challenge** modeline gerek yoktur.

#### 5.1.2. İşlem Akışı

##### Adım 1 — Platform kimlik doğrulama isteği gönderir

Platform (örn. X.com), kullanıcının TEE'sine kimlik doğrulama isteği iletir:

```
platform_istegi = {
    firma_id,          // "x.com"
    firma_istegi,      // "kullanici_gercek_mi"
    timestamp,
    nonce_p
}
```

##### Adım 2 — TEE kullanılmamış bir token seçer, ePub üretir, BTK'ya iletir

```
// TEE içinde:
(ePriv, ePub) ← Dilithium3.KeyGen()    // oturumluk anahtar çifti
nonce ← SHAKE-256(TRNG_random, 16)

// Kullanılmamış bir token çifti seçilir
Kullanici_token_n = {h1, h2, cert}     // TEE içinden okunur
// BTK_token_n TEE tarafından açılamaz (BTK_pub ile şifreli)

// Talep oluşturulur
talep = {
    BTK_token_n,       // = HybridEncrypt(BTK_pub, {h1, h2, cert})
    h1,                // BTK'nın eşleştirme yapabilmesi için düz metin
    ePub,
    firma_id,
    firma_istegi,
    timestamp,
    nonce
}

// Talep BTK'nın açık anahtarı ile şifrelenir
(ss, ct_kyber) ← Kyber768.Encapsulate(BTK_pub)
aes_key ← HKDF-SHA3-256(ss, nonce, 32)
sifreli_talep = {AES-256-GCM(aes_key, talep), ct_kyber}
```

##### Adım 3 — BTK talebi açar ve doğrular

```
// BTK tarafında:
ss ← Kyber768.Decapsulate(BTK_priv, ct_kyber)
aes_key ← HKDF-SHA3-256(ss, nonce, 32)
talep = AES-256-GCM-Decrypt(aes_key, sifreli_talep.ct)

// 1. BTK_token_n'i aç
{h1', h2, cert} ← HybridDecrypt(BTK_priv, talep.BTK_token_n)

// 2. h1 eşleşiyor mu? → TEE gerçekten bu token'a sahip
assert talep.h1 == h1'

// 3. eDevlet imzasını doğrula → bu çift eDevlet onaylı
Dilithium3.Verify(eDev_pub, h1 || h2, cert)

// 4. Token çifti daha önce kullanılmış mı?
assert (h1, h2) not in kullanilmis_tokenlar

// 5. Nonce tekrar kontrolü
assert (ePub, nonce) not in nonce_cache

// 6. Firma isteği yetkili mi?
assert firma_istegi in izin_verilen_istekler

// 7. Token çiftini tüket ve nonce'u önbelleğe al
kullanilmis_tokenlar.add(h1, h2)
nonce_cache.add(ePub, nonce)
```

##### Adım 4 — BTK token üretir

```
// Token ham gövdesi (imzalanacak tüm alanlar)
token_ham = {
    firma_id,
    seviye: "yesil",
    gecerli: true,
    h2,                // oturumluk kimliksiz tanımlayıcı
    ePub,
    timestamp,
    nonce
}

// BTK, token_ham'in hash'ini imzalar
btk_imza = Dilithium3.Sign(BTK_priv, SHA3-256(token_ham))

// Token hash'i (adli süreç için saklanır)
// canonical_json: deterministik JSON serileştirme (anahtarlar alfabetik, boşluksuz)
token_hash = SHA3-256(canonical_json(token_ham) || btk_imza)

// BTK, h2 için ayrı imza üretir (TEE'nin yanıtın BTK'dan geldiğini doğrulaması için)
btk_h2_imza = Dilithium3.Sign(BTK_priv, h2 || token_hash)

// BTK kendi kaydını tutar
btk_kayit = {token_hash, h1, h2, ePub, firma_id, timestamp}

// Token paketlenir ve firmanın açık anahtarı ile şifrelenir
token_paket = {token_hash, token_ham, btk_imza}

// Firma için KEM + AES-GCM şifreleme
(ss_f, ct_f) ← Kyber768.Encapsulate(F_pub)
aes_key_f ← HKDF-SHA3-256(ss_f, nonce, 32)
sifreli_token = {AES-256-GCM(aes_key_f, token_paket), ct_f}
```

##### Adım 5 — BTK yanıtı TEE'ye gönderir, TEE doğrular ve firmaya iletir

```
// BTK → TEE: sifreli_token + {h2, btk_h2_imza}
BTK, sifreli_token ile birlikte h2 ve btk_h2_imza'yı TEE'ye gönderir.

// TEE tarafında:
// 1. BTK imzasını doğrula → yanıt gerçekten BTK'dan mı geldi?
Dilithium3.Verify(BTK_pub, h2 || token_hash, btk_h2_imza)

// 2. h2 eşleşiyor mu? → BTK doğru çifti işledi mi?
assert h2 == kullanilan_token.h2

// TEE sifreli_token'i açamaz (F_pub ile şifreli), değiştirmez

// TEE → Firma
TEE, sifreli_token'i doğrudan firmaya iletir.
// Kullanılan token çifti TEE tarafından tüketildi olarak işaretlenir.
```

##### Adım 6 — Firma token'ı açar ve doğrular

```
// Firma tarafında:
ss_f ← Kyber768.Decapsulate(F_priv, ct_f)
aes_key_f ← HKDF-SHA3-256(ss_f, nonce, 32)
token_paket = AES-256-GCM-Decrypt(aes_key_f, sifreli_token.ct)

// 1. BTK imzasını doğrula (token_ham'in tamamı imzalanmıştır)
Dilithium3.Verify(BTK_pub, SHA3-256(token_ham), btk_imza)

// 2. Token hash'i tutarlı mı?
assert token_hash == SHA3-256(canonical_json(token_ham) || btk_imza)

// 3. firma_id eşleşiyor mu?
assert token_ham.firma_id == "x.com"

// 4. Geçerliyse kullanıcıya giriş izni ver
```

Token geçerliyse platform girişe izin verir. TC kimliği hiçbir aşamada platforma iletilmez. Platform, kullanıcıyı kendi oturumuyla ilişkilendirmek için kendi ürettiği bir callback_token kullanır. Token içinde kullanıcıya ait tek tanımlayıcı `ePub`'tur — bu da bir sonraki oturumda değişir.

#### 5.1.3. Token Yaşam Döngüsü

- Firma `sifreli_token`'ı kendi veritabanında saklar (adli süreç için).
- ePub oturum sonunda TEE tarafından silinir — geçmiş oturumlarla ilişkilendirilemez.
- Her oturumda farklı bir token çifti (h1, h2) kullanılır — BTK aynı kullanıcının oturumlarını ilişkilendiremez (bkz. Bölüm 2.5).
- Kullanılan token çifti hem BTK hem TEE tarafından tüketildi olarak işaretlenir; tekrar kullanılamaz.
- Token çiftleri tükendiğinde kullanıcı eDevlet'ten çevrimiçi olarak yeni paket alır.

#### 5.1.4. Adli Süreç (Mahkeme Kararı ile Kimlik Tespiti)

```
Adım 1: Mahkeme, X.com'dan ilgili oturuma ait kayıtları resmi yazı ile talep eder.
        Firma, kendi veritabanında sakladığı sifreli_token'ı F_priv ile açar,
        içindeki token_paket'i (token_hash, token_ham, btk_imza)
        mahkemeye düz metin olarak sunar.
        token_ham içinde h2 bulunur.

Adım 2: Mahkeme, token_paket'teki token_hash ve btk_imza'yı BTK'ya götürür.
        BTK, token_hash ile kendi kayıtlarında arama yapar:
          btk_kayit = lookup(token_hash)
          // btk_kayit = {token_hash, h1, h2, ePub, firma_id, timestamp}
        h1 ve h2'yi mahkemeye resmi yazı ile bildirir.

Adım 3: Mahkeme, h1 (veya h2) ile DOĞRUDAN eDevlet'e başvurur.
        BTK bu adımda aracı değildir — manipülasyon riski ortadan kalkar.
        eDevlet, HMAC taraması ile h1'in hangi kullanıcıya ait olduğunu bulur,
        ardından uPub → TC_kimlik eşlemesini çıkarır.
        (Deterministik türetme sayesinde her token için ayrı indeks gerekmez, bkz. Bölüm 2.5.)

Adım 4: eDevlet, TC kimliğini yalnızca mahkemeye bildirir.
```

**Güvenlik garantisi:** Mahkeme hem BTK'dan hem eDevlet'ten bağımsız kayıt alır. İki kayıt uyuşmuyorsa manipülasyon tespit edilir.

#### 5.1.5. Çift Taraflı Kayıt Güvencesi (eDevlet Runtime Bağımsız)

BTK, her token için `btk_kayit` tutar. **Günde bir kez veya her 1000 token'da bir (hangi önce gelirse)** tüm kayıtların **Merkle ağaç kök hash'ini** eDevlet'e gönderir:

```
gunluk_merkle_kok = MerkleRoot(tum_token_hash'ler)
BTK → eDevlet: {tarih, gunluk_merkle_kok}
```

**Mahkeme sürecinde çapraz doğrulama:**

1. BTK, ilgili güne ait token kaydını ve Merkle kanıt yolunu (proof path) mahkemeye sunar.
2. eDevlet, aynı güne ait Merkle kök hash'ini mahkemeye sunar.
3. Mahkeme, Merkle kanıt yolunu kullanarak token kaydının kök hash ile uyuşup uyuşmadığını doğrular.
4. Uyuşmazsa BTK kayıtları değiştirilmiş demektir — manipülasyon kanıtlanır.

**eDevlet runtime'da devrede değildir** — yalnızca günlük batch Merkle kök hash'ini alır. Bu işlem eDevlet kesintisinden etkilenmez, gecikmeli olarak da yapılabilir.

---

### 5.2 Sarı Seviye — Bankalar, Sigorta, Kredi Kuruluşları

Sarı seviyede kullanıcı belirli bir işlem içeriğini onaylar. Ephemeral anahtar çifti bu aşamada devreye girer; forward secrecy sağlanır. CA geçici sertifika üretir ve işlem sonunda siler.

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

uPriv, ePriv ve ePub yalnızca TEE (Trusted Execution Environment) içinde üretilir ve işlenir.

**TEE yalnızca kullanıcı cihazında bulunur.** Firma sunucuları ve BTK altyapısı için TEE zorunluluğu yoktur. Protokol, sunucu tarafında standart donanım güvenliği varsayar.

**Desteklenen implementasyonlar:**
- ARM TrustZone (mobil cihazlar) — öncelikli hedef platform
- Intel TDX / SGX (masaüstü ve sunucu)
- AMD SEV (sunucu)

**TEE yoksa:** Protokol çalışmaz. Yazılımsal izolasyon yeterli kabul edilmez.

> **Not:** Intel SGX birçok PC'de devre dışıdır; AMD SEV ağırlıklı olarak sunucu ortamlarına yöneliktir. GKDP öncelikli hedef olarak ARM TrustZone tabanlı mobil cihazları esas alır. PC desteği TEE standardizasyonunun olgunlaşmasıyla genişleyecektir.
>
> **İleriye Dönük:** PC'lerde TEE standardizasyonu olgunlaştıkça, [MELP Programlama Dili](https://melp.dev) ile geliştirilmesi planlanan **EOK (Encrypted Optimizasyon Katmanı)** çözümü alternatif bir güvenlik katmanı sunabilir. EOK, güvenliği runtime'da CPU düzeyine indirmeyi ve donanım TEE'sine yazılımsal bir tamamlayıcı sağlamayı vadetmektedir. Bu yaklaşım hâlen araştırma aşamasındadır (MELP STAGE3.5).

### 7.1 Masaüstü PC ve TEE'siz Cihazlar için USB Donanım Anahtarı

Masaüstü PC'lerde donanımsal TEE yaygın değildir. Kullanıcının PC'sini PTT'ye götürmesi de pratik değildir. Bu sorunu çözmek için **USB donanım güvenlik anahtarı** modeli önerilir:

```
1. Kullanıcı PTT şubesine gider, USB donanım anahtarı alır
   (e-Devlet şifre kartı dağıtım modeline benzer)

2. USB anahtar içinde TEE işlevi bulunur:
   - uPriv anahtar içinde üretilir, cihazdan çıkmaz
   - Dilithium3 imzalama ve Kyber-768 KEM işlemleri anahtar içinde yapılır
   - TRNG donanımsal rastgelelik sağlar

3. PC'ye takıldığında GKDP izolasyon bölgesi olarak çalışır
   Oturum bitince USB çıkarılır, geride iz kalmaz

4. Aynı USB anahtar farklı PC'lerde kullanılabilir (companion model benzeri)
   Kullanıcı kendi cihazı olmayan bir PC'den de giriş yapabilir
```

USB donanım anahtarı, mobil cihazı olmayan veya PC'den giriş yapmak isteyen kullanıcılar için birincil çözümdür. Türkiye'de e-imza ve akıllı kart altyapısı bu modele benzer şekilde çalışmaktadır.

> **USB Anahtar Kayıt Süreci:** USB anahtarın ilk kaydı PTT şubesinde yapılır. Görevli, USB anahtarı PTT'deki okuyucuya takar, kullanıcının kimliğini doğrular ve anahtar içinde üretilen uPub'ı sisteme kaydeder. Kullanıcı daha sonra bu USB anahtarı kendi PC'sinde veya başka bir PC'de kullanabilir. Bu süreç, mobil cihazın PTT'ye götürülmesiyle aynı güvenlik seviyesini sağlar.

### 7.2 Geçici Erişim — Kapsam Dışı

Kullanıcının ne mobil cihazının ne USB anahtarının yanında olmadığı senaryolar GKDP kapsamı dışındadır. TEE olmayan bir ortamda kriptografik güvenlik garantisi verilemez; geçici kod, OTP veya benzer mekanizmalar BTK'nın `uPriv` türevi bir sırra erişmesini gerektireceğinden protokolün temel güvenlik varsayımlarıyla çelişir.

Bu durumdaki kullanıcılar için önerilen yol: USB donanım anahtarını yanında bulundurmak veya erişimi ertelemek. GKDP, "tamamen hazırlıksız anlık erişim" senaryosunu bilinçli olarak kapsam dışında bırakmaktadır. Bu kısıt, bankacılık uygulamalarının "kayıtlı cihaz" zorunluluğuyla aynı güvenlik felsefesini yansıtmaktadır.

### 7.3 Kapsam Sınırı (v0.9)

GKDP şu aşamada aşağıdaki güvenilir donanım platformlarını kapsar:

| Platform | Durum |
|----------|-------|
| ARM TrustZone (mobil) | ✅ Öncelikli, tam destek |
| USB donanım anahtarı | ✅ Önerilen PC çözümü |
| Apple Secure Enclave | ✅ M1/M2 Mac cihazlar |
| Intel TDX / AMD SEV | ⚠️ Sunucu tarafı için uygun; tüketici PC'de yaygın değil |
| TPM 2.0 (tek başına) | ⚠️ Anahtar saklama için, tam TEE değil |
| Yazılımsal izolasyon | ❌ Kabul edilmez |
| TEE'siz ortam | ❌ Protokol çalışmaz — bilinçli güvenlik kararı |

> GKDP, donanımsal TEE olmadan çalışmaz. Bu bir eksiklik değil, protokolün temel güvenlik varsayımıdır. Kullanıcıların her zaman bir TEE'ye sahip cihazı (mobil telefon veya USB anahtar) yanlarında bulundurması beklenir. Bu kısıt, bankacılık uygulamalarının "güvenli cihaz" zorunluluğuyla benzer niteliktedir.

---

## 8. Güvenlik Özellikleri

### BTK Tarafından Korelasyon Koruması

BTK'nın aynı kullanıcının farklı oturumlarını ilişkilendirmesi, **çift token mekanizması** ile **matematiksel olarak engellenmiştir.** Kayıt aşamasında eDevlet her kullanıcı için N adet rastgele `(h1, h2)` çifti üretir (bkz. Bölüm 2.5). Her oturumda farklı bir çift kullanılır; BTK yalnızca `h1`'i görür. `h1` değerleri birbirinden bağımsız rastgele sayılar olduğu için BTK aynı kullanıcıya ait farklı oturumları ayırt edemez.

Bu çözümün avantajları:
- **BTK uPub'ı hiç görmez** — eDevlet sertifikası BTK'ya iletilmez. Kullanıcının kalıcı kimliği BTK'dan tamamen gizlenir.
- **TEE token'ı doğrular** — BTK'dan dönen token'daki `h2` değerini kendi kaydıyla karşılaştırarak BTK'nın doğru çifti işlediğini teyit eder. BTK sahte token üretemez.
- **eDevlet runtime'da devrede değildir** — yalnızca kayıt anında token çiftlerini üretir, adli süreçte indeks sorgular.
- **Ek maliyet:** eDevlet'te kullanıcı başına bir `user_seed` kaydı (~85 milyon, ~2.7 GB). TEE'de N token (~2 MB). Adli süreç taraması ~2 saniye.

### Forward Secrecy
Sarı seviyede her işlem bağımsız bir ephemeral anahtar çifti kullanır. Geçmiş oturumlar geriye dönük olarak çözülemez. Yeşil seviyede ePub her oturumda yenilenir ve oturum sonunda silinir; işlem içeriği olmadığından forward secrecy gerekmez.

### Kimlik Bağlantısızlığı (Unlinkability)
TC kimliği hiçbir zaman platforma veya BTK'ya iletilmez. Her oturumda yeni ePub ve yeni `(h1, h2)` çifti kullanılır — BTK aynı kullanıcının farklı oturumlarını ne ePub ne de h1/h2 üzerinden ayırt edemez (bkz. Bölüm 2.5). Platformlar kullanıcı oturumlarını bağlayamaz.

### Kuantum Direnci
Tüm imzalama işlemleri kafes tabanlı Dilithium3, tüm anahtar kapsülleme işlemleri kafes tabanlı Kyber-768 kullanır. AES-256-GCM klasik tehditlere karşı güvenlidir ve Grover algoritması ile 2^128 güvenlik seviyesi sağlar. RSA/ECDH tabanlı sistemlere karşı Shor algoritmasıyla gerçekleştirilebilecek kuantum saldırıları bu protokole uygulanamaz.

### Token Bağlama (Token Binding)
Her token `firma_id` alanı ile belirli bir platforma bağlıdır ve yalnızca o platformun `F_priv` anahtarı ile açılabilir. Token çalınsa bile başka bir platformda kullanılamaz.

### Yetkisiz Talep Reddi
BTK, `firma_istegi` alanını denetler. Platform TC kimliği veya protokol kapsamı dışında bir bilgi talep ederse BTK isteği reddeder ve token üretmez.

### eDevlet Runtime Bağımsızlığı
eDevlet yalnızca kayıt, iptal ve günlük Merkle kök hash'i alma aşamalarında devrededir. Runtime işlemlerinde eDevlet kesintisi sistemi etkilemez. Merkle kök hash'i gecikmeli olarak da iletilebilir.

### Çift Taraflı Kayıt Güvencesi
BTK token kayıtlarını, eDevlet ise günlük Merkle kök hash'lerini bağımsız olarak tutar. Mahkeme her iki kaydı çapraz doğrular — tek tarafın manipülasyonu tespit edilebilir.

---

## 9. Tehdit Modeli

| Tehdit | Etki | Protokol Yanıtı |
|---|---|---|
| Platform ihlali | Saldırgan platform veritabanını ele geçirir | TC kimliği platformda yoktur — sadece ePub ve şifreli token vardır |
| BTK ihlali | BTK altyapısı tehlikeye girer | BTK'da TC kimliği ve uPub bulunmaz. Saldırgan yalnızca rastgele h1/h2 çiftleri ve ePub listelerini ele geçirebilir — bu veriler kullanıcı kimliğini açığa çıkarmaz ve korelasyon yapılamaz |
| BTK korelasyonu | BTK, kullanıcı oturumlarını ilişkilendirmeye çalışabilir | Her oturumda farklı rastgele h1 kullanılır, BTK uPub'ı hiç görmez — korelasyon matematiksel olarak imkansız (bkz. Bölüm 2.5, Bölüm 8) |
| Token çalınması | Başka platformda kullanılmaya çalışılır | firma_id eşleşmediği ve F_priv olmadığı için açılamaz |
| uPriv çalınması | Saldırgan kullanıcı adına işlem yapabilir | CRL ile iptal, yeni kayıt |
| Yetkisiz firma talebi | Platform TC kimliği talep eder | BTK firma_istegi kontrolü ile reddeder |
| Tekrar saldırısı (replay) | Eski token tekrar kullanılır | nonce + ePub + timestamp + BTK nonce cache'i tekrarı engeller |
| Oturum korelasyonu | Aynı kullanıcının farklı oturumları izlenir | ePub her oturumda yenilenir; platformlar oturumları bağlayamaz |
| Kuantum saldırısı | Gelecekte kuantum bilgisayar ile şifre çözme | Dilithium3 + Kyber-768 + AES-256-GCM kuantum dirençlidir |
| eDevlet kesintisi | Runtime işlemler durur | eDevlet runtime'da devrede değildir — etki yok |
| BTK kayıt manipülasyonu | BTK token kayıtlarını değiştirir | TEE token'daki h2'yi doğrular; firma kendi token kopyasını saklar — çapraz doğrulama mümkündür |
| Firma token silme | Firma adli süreçte token'ı gösteremez | BTK kendi token_hash kaydını tutar — firmadan bağımsız kanıt mevcuttur |
| Token çifti tüketme | Saldırgan kullanıcının token'larını tüketir | Token'lar TEE içinde saklanır; TEE olmadan tüketilemez. Tükenme durumunda eDevlet'ten yenisi alınır |

---

## 10. Referanslar

- FIPS 204 — Module-Lattice-Based Digital Signature Standard (CRYSTALS-Dilithium)
- FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (CRYSTALS-Kyber)
- FIPS 197 — Advanced Encryption Standard (AES)
- NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
- FIPS 202 — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- Chaum, D. (1982) — Blind Signatures for Untraceable Payments

---

*Politika yapıcılara yönelik genel belge için README.md dosyasına bakınız.*  
*https://github.com/guvenacar/GKDP-Guvenli-Kimlik-Dogrulama-Protokolu/blob/main/README.md*

---

**Dipnotlar**

*nonce: TEE'nin donanımsal rastgele sayı üreticisinden (TRNG) türetilen, tek kullanımlık 16 baytlık değer (bkz. Bölüm 5.1.1). Her oturumda sıfırdan üretilir.*
