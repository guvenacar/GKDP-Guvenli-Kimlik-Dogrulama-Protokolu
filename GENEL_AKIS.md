# GKDP Genel Akış — Boru Hattı (Pipeline)

**Hazırlayan:** Güven ACAR — İzmir, 2026  
**Versiyon:** 0.9-draft

---

Bu belge, GKDP protokolünün baştan sona işleyişini, teknik detaya girmeden, "kimde ne var, kim kime ne gönderiyor" mantığıyla anlatır.

---

## 1. Taraflar ve Ellerindekiler

### Kullanıcı Cihazı (TEE içinde)

| Anahtar / Veri | Açıklama |
|---|---|
| `uPriv` | Kullanıcının kalıcı gizli anahtarı. Cihazdan asla çıkmaz. |
| `uPub` | Kullanıcının kalıcı açık anahtarı. Kayıt sırasında eDevlet'e iletilir. |
| `ePriv` | Oturumluk geçici gizli anahtar. Her girişte yeniden üretilir, oturum sonunda silinir. |
| `ePub` | Oturumluk geçici açık anahtar. BTK'ya gönderilir. |
| N adet `Kullanici_token` | eDevlet'ten alınan kimliksiz giriş anahtarları. Her biri `{h1, h2, cert}` içerir. |
| N adet `BTK_token` | Aynı çiftin BTK_pub ile şifrelenmiş hali. TEE açamaz, BTK'ya iletir. |

### eDevlet

| Anahtar / Veri | Açıklama |
|---|---|
| `eDev_priv` | eDevlet'in gizli anahtarı. Token çiftlerini imzalamak için. |
| `eDev_pub` | eDevlet'in açık anahtarı. BTK bilir. |
| `TC_kimlik ↔ uPub` | Kullanıcı eşleştirmesi. |
| İndeks: `h1 → uPub → TC` | Her token çifti için adli süreç indeksi. Runtime'da sorgulanmaz. |

### BTK (Bilgi Teknolojileri Kurumu)

| Anahtar / Veri | Açıklama |
|---|---|
| `BTK_priv` | BTK'nın gizli anahtarı. Token imzalamak ve BTK_token açmak için. |
| `BTK_pub` | BTK'nın açık anahtarı. Kamuya açık. |
| Kayıtlı firma `F_pub` listesi | Hangi platformun hangi açık anahtara sahip olduğu. |
| `nonce_cache` | Son N adet `(ePub, nonce)` çifti. Tekrar saldırısını önler. |
| `kullanilmis_tokenlar` | Tüketilen `(h1, h2)` çiftleri. |
| `btk_kayit` | Her token için: `{token_hash, h1, h2, ePub, firma_id, timestamp}` |

### Firma (Platform — X.com, Banka vb.)

| Anahtar / Veri | Açıklama |
|---|---|
| `F_priv` | Firmanın gizli anahtarı. BTK'dan gelen şifreli token'ı açar. |
| `F_pub` | Firmanın açık anahtarı. BTK'da kayıtlı. |
| `BTK_pub` | BTK'nın açık anahtarı (kamuya açık, imza doğrulama için). |

---

## 2. Kayıt Aşaması (Bir Kerelik)

```
KULLANICI CİHAZI                    eDEVLET
     │                                  │
     │  1. uPriv/uPub üretilir (TEE)    │
     │  2. SHA3-256(uPub) hesaplanır    │
     │                                  │
     │── uPub, SHA3-256(uPub), TC ─────→│
     │                                  │
     │                          3. TC doğrulanır
     │                          4. Eşleştirme kaydedilir
     │                          5. N adet token çifti üretilir:
     │                             Her çift için:
     │                             • h1, h2 ← rastgele 256-bit
     │                             • cert = Sign(eDev_priv, h1||h2)
     │                             • BTK_token = Encrypt(BTK_pub, {h1,h2,cert})
     │                             • Kullanici_token = {h1, h2, cert}
     │                          6. İndeks: h1→uPub→TC (adli süreç için)
     │                                  │
     │←── N×(BTK_token, Kullanici_token)│
     │                                  │
     │  7. Tüm token'lar TEE'de saklanır│
```

**Sonuç:**
- eDevlet: `TC ↔ uPub ↔ {tüm h1, h2}` ilişkisini bilir
- BTK: hiçbir şey bilmez (token'lar henüz BTK'ya iletilmemiştir)
- Kullanıcı: N adet giriş anahtarına sahiptir

---

## 3. Giriş Aşaması (Her Oturumda)

### Adım 1 — Firma giriş isteği başlatır

```
KULLANICI CİHAZI                    FİRMA (X.com)
     │                                  │
     │←── platform_istegi ──────────────│
     │   {firma_id, timestamp, nonce_p} │
```

### Adım 2 — TEE kullanılmamış bir token seçer, BTK'ya gönderir

```
KULLANICI CİHAZI (TEE)                  BTK
     │                                    │
     │  ePriv/ePub üretilir               │
     │  nonce üretilir                    │
     │  Kullanılmamış token seçilir:      │
     │    {h1, h2, cert}                  │
     │                                    │
     │  talep = {BTK_token_n, h1, ePub,   │
     │           firma_id, nonce, ...}    │
     │  BTK_pub ile şifrelenir            │
     │                                    │
     │── sifreli_talep ─────────────────→│
```

### Adım 3 — BTK talebi doğrular

```
                                    BTK
                                     │
                                     │  BTK_token_n açılır → {h1, h2, cert}
                                     │  assert talep.h1 == h1   (TEE sahiplik kanıtı)
                                     │  eDevlet imzası doğrulanır (cert)
                                     │  Token çifti daha önce kullanılmış mı?
                                     │  Nonce tekrar kontrolü
                                     │  Firma yetki kontrolü
```

### Adım 4 — BTK token üretir

```
                                    BTK
                                     │
                                     │  token_ham = {firma_id, h2,
                                     │     ePub, timestamp, nonce, ...}
                                     │
                                     │  BTK_priv ile token_ham imzalanır → btk_imza
                                     │  BTK_priv ile h2 imzalanır → btk_h2_imza
                                     │  token_hash = SHA3-256(token_ham || btk_imza)
                                     │  token_paket = {token_hash, token_ham, btk_imza}
                                     │  F_pub ile şifrelenir → sifreli_token
                                     │
                                     │  BTK kayıt: {token_hash, h1, h2, ePub, ...}
```

### Adım 5 — BTK yanıtı TEE'ye gönderir, TEE doğrular ve firmaya iletir

```
KULLANICI CİHAZI         BTK                FİRMA
     │                    │                    │
     │← sifreli_token ───│                    │
     │   + h2 +           │                    │
     │   btk_h2_imza      │                    │
     │                    │                    │
     │ TEE kontroller:    │                    │
     │ 1. BTK_pub ile     │                    │
     │    btk_h2_imza     │                    │
     │    doğrulanır →    │                    │
     │    yanıt BTK'dan   │                    │
     │ 2. assert h2 ==    │                    │
     │    kendi_h2'si     │                    │
     │ ✅ BTK doğru token  │                    │
     │   çiftini işledi   │                    │
     │                    │                    │
     │── sifreli_token ──────────────────────→│
```

### Adım 6 — Firma token'ı açar ve doğrular

```
                                    FİRMA
                                     │
                                     │  F_priv ile sifreli_token açılır
                                     │  BTK imzası doğrulanır
                                     │  Token hash tutarlılığı kontrol
                                     │  firma_id eşleşme kontrolü
                                     │
                                     │  ✅ GİRİŞ İZNİ VERİLİR
```

---

## 4. Adli Süreç (Mahkeme Kararı ile Kimlik Tespiti)

```
MAHKEME           FİRMA            BTK             eDEVLET
  │                 │               │                 │
  │── talep ──────→│               │                 │
  │←─ token_paket ─│               │                 │
  │                 │               │                 │
  │── token_hash ─────────────────→│                 │
  │                 │               │                 │
  │                 │    lookup(token_hash)           │
  │←────────── h1, h2 ────────────│                 │
  │                 │               │                 │
  │── h1 ──────────────────────────────────────────→│
  │                 │               │                 │
  │                 │               │   indeks:       │
  │                 │               │   h1→uPub→TC    │
  │←────────────── TC_kimlik ───────────────────────│
```

---

## 5. Hangi Taraf Neyi Bilir?

| Bilgi | Kullanıcı | Firma | BTK | eDevlet |
|---|---|---|---|---|
| TC Kimlik | ✅ | ❌ | ❌ | ✅ |
| uPriv | ✅ (TEE'de) | ❌ | ❌ | ❌ |
| uPub | ✅ | ❌ | ❌ | ✅ |
| h1, h2 (oturumluk) | ✅ | ⚠️ sadece h2 | ✅ | ✅ |
| Firma kullanıcıyı tanır mı? | — | ❌ (sadece h2) | — | — |
| Kullanıcı oturumları ilişkilendirilebilir mi? | — | ❌ | ❌ (h1 rastgele) | ⚠️ sadece adli |

---

## 6. Veri Akış Şeması (Tek Bakışta)

```
KAYIT (bir kerelik):
  Kullanıcı ── uPub, TC ──→ eDevlet
  Kullanıcı ←── N×(BTK_token, Kullanici_token) ── eDevlet

GİRİŞ (her oturum):
  Kullanıcı ←── istek ── Firma
  Kullanıcı ── sifreli_talep (BTK_token_n + h1) ──→ BTK
  BTK ── sifreli_token + h2 ──→ Kullanıcı (TEE h2'yi doğrular)
  Kullanıcı ── sifreli_token ──→ Firma
  Firma: açar, BTK imzasını doğrular, giriş izni verir

ADLİ SÜREÇ (nadir):
  Mahkeme ←── token_paket ── Firma
  Mahkeme ── token_hash ──→ BTK ←── h1, h2
  Mahkeme ── h1 ──→ eDevlet ←── TC_kimlik
```

---

*Teknik detaylar için GUVENLI_KIMLIK_DOGRULAMA_PROTOKOLU_TEKNIK.md dosyasına bakınız.*
