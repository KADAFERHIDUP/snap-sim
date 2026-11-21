# snap-sim

Simulator **Open API SNAP** (Standar Nasional Open API Pembayaran) Bank Indonesia. Kamu bisa mencoba alur integrasi lengkap dari browser: daftar sebagai partner, minta token B2B, cek saldo, cek rekening tujuan, transfer intrabank, lalu cek status transfernya. Semua permintaan ditandatangani persis seperti yang diminta bank-bank di Indonesia.

Kunci privat RSA dibuat di browser (WebCrypto, *non-extractable*) dan tidak pernah dikirim. Server hanya menyimpan kunci publik.

Dibuat oleh **Ahmad Umraithi** (Teknik Informatika, Universitas Malikussaleh) untuk belajar dan portofolio. Ini bukan layanan bank sungguhan.

## Yang dijaga

| Ancaman | Cara snap-sim menanganinya |
|---|---|
| Orang lain meminta token atas nama partner | Token B2B hanya keluar untuk tanda tangan `SHA256withRSA` yang cocok dengan kunci publik partner. Kunci RSA di bawah 2048 bit ditolak saat registrasi. |
| Isi transaksi diubah di tengah jalan | Setiap transaksi ditandatangani `HMAC-SHA512` atas method, path, token, hash SHA-256 body, dan cap waktu. Satu karakter berubah, server menjawab `401xx00`. |
| Permintaan yang sah direkam lalu dikirim ulang | `X-EXTERNAL-ID` wajib unik per partner per hari (`409xx00`), dan cap waktu yang lebih dari 5 menit dari jam server ditolak. ID baru dicatat **setelah** tanda tangan lolos, jadi orang lain tidak bisa menghabiskan ID milik partner. |
| Token dicuri | Token berlaku 900 detik, terikat ke satu partner (`X-PARTNER-ID` lain langsung ditolak), dan yang disimpan server hanya hash SHA-256-nya. |
| Partner mengintip atau mendebit rekening partner lain | Partner hanya bisa membaca saldo dan mendebit rekening miliknya. Rekening milik orang lain dijawab `404xx11`, sama persis dengan rekening yang tidak ada. Status transfer orang lain juga `404xx01`. |
| Tombol kirim ditekan dua kali atau jaringan putus | `partnerReferenceNo` unik per partner. Permintaan ulang yang sama mendapat transfer yang pertama, tanpa potong saldo lagi. Nomor sama dengan isi berbeda ditolak `409xx01`. |
| Dua transfer bersamaan membuat saldo minus | Kedua rekening dikunci dalam urutan nomor rekening sebelum saldo dibaca. Diuji dengan 30 transfer paralel dari satu rekening dan 400 transfer bolak-balik tanpa deadlock. |
| Uang muncul atau hilang | Pembukuan double-entry: setiap transfer menulis satu debit dan satu kredit dengan nominal sama. Nominal disimpan dalam sen (`long`), tidak pernah `float`. |
| Nominal janggal | Wajib string dua desimal (`"150000.00"`), mata uang `IDR`, maksimal Rp50.000.000 per transaksi dan Rp100.000.000 per hari per rekening. |
| Nama nasabah dipanen lewat cek rekening | Nama disamarkan (`Ah*** Um******`). |
| Banjir permintaan | Batas per IP untuk semua endpoint SNAP dan untuk pembuatan sandbox (default 10 per jam). IP diambil dari entri terakhir `X-Forwarded-For`, jadi alamat palsu di depannya tidak memberi kuota baru. |
| Detail error bocor | Error tak terduga dijawab `500xx00 General Error`; detailnya hanya ada di log server. Halaman web memakai Content-Security-Policy ketat tanpa skrip dari luar. |

## Alur

```
Partner (browser)                                  snap-sim
  │  POST /sandbox/partners {publicKey}              │  simpan kunci publik, beri clientKey + clientSecret
  │─────────────────────────────────────────────────►│
  │  POST /snap/v1.0/access-token/b2b                │
  │  X-SIGNATURE = RSA(clientKey|X-TIMESTAMP)        │  verifikasi dengan kunci publik
  │─────────────────────────────────────────────────►│  → accessToken (900 detik)
  │  POST /snap/v1.0/transfer-intrabank              │
  │  Authorization: Bearer <token>                   │  cek token, partner, cap waktu,
  │  X-SIGNATURE = HMAC-SHA512(clientSecret, ...)    │  tanda tangan, lalu X-EXTERNAL-ID
  │─────────────────────────────────────────────────►│  → kunci rekening, debit, kredit
```

## Tanda tangan

**Token B2B (asimetris)**

```
stringToSign = clientKey + "|" + X-TIMESTAMP
X-SIGNATURE  = Base64( SHA256withRSA(privateKey, stringToSign) )
```

**Transaksi (simetris)**

```
stringToSign = HTTPMethod + ":" + EndpointUrl + ":" + AccessToken + ":"
             + Lowercase(HexEncode(SHA-256(minify(RequestBody)))) + ":" + X-TIMESTAMP
X-SIGNATURE  = Base64( HMAC-SHA512(clientSecret, stringToSign) )
```

`minify` hanya membuang spasi di luar string, tanpa mengubah urutan atau isi nilai. Body yang dikirim rapi (pretty) tetap lolos selama isinya sama.

## Endpoint

| Layanan | Kode | Path | Isi |
|---|---|---|---|
| Token B2B | 73 | `POST /snap/v1.0/access-token/b2b` | `{"grantType":"client_credentials"}` + header `X-TIMESTAMP`, `X-CLIENT-KEY`, `X-SIGNATURE` |
| Cek saldo | 11 | `POST /snap/v1.0/balance-inquiry` | `accountNo` |
| Cek rekening internal | 15 | `POST /snap/v1.0/account-inquiry-internal` | `beneficiaryAccountNo` |
| Transfer intrabank | 17 | `POST /snap/v1.0/transfer-intrabank` | `partnerReferenceNo`, `amount{value,currency}`, `sourceAccountNo`, `beneficiaryAccountNo`, `remark` |
| Status transfer | 36 | `POST /snap/v1.0/transfer/status` | `originalPartnerReferenceNo`, `serviceCode: "17"` |
| Sandbox | – | `POST /sandbox/partners` | `{"publicKey":"<SPKI Base64>"}` → `clientKey`, `clientSecret` (sekali saja), dua rekening |

Endpoint transaksi wajib membawa header `Authorization: Bearer <token>`, `X-TIMESTAMP`, `X-SIGNATURE`, `X-PARTNER-ID`, `X-EXTERNAL-ID` (angka, maks. 36 digit), dan `CHANNEL-ID`.

Kode respons 7 digit = HTTP + kode layanan + kode kasus. Contoh:

| Kode | Arti |
|---|---|
| `2001700` | Transfer berhasil |
| `4001702` | Field wajib kosong |
| `4011700` | Tanda tangan salah atau cap waktu kedaluwarsa |
| `4011101` | Token tidak valid atau kedaluwarsa |
| `4031714` | Saldo tidak cukup |
| `4031702` | Melebihi batas nominal |
| `4031718` | Rekening tujuan dormant |
| `4041111` | Rekening tidak ditemukan (atau bukan milikmu) |
| `4091100` | `X-EXTERNAL-ID` sudah dipakai hari ini |
| `4091701` | `partnerReferenceNo` sudah dipakai untuk transfer lain |

Rekening tujuan bersama: `8800112233` dan `8800445566` (aktif), `8800778899` (dormant).

## Menjalankan

Butuh Java 21 dan Maven.

```bash
mvn package
java -jar target/snap-sim.jar     # buka http://localhost:8080
```

Atau dengan Docker:

```bash
docker build -t snap-sim .
docker run -p 8080:8080 snap-sim
```

| Variabel | Default | Keterangan |
|---|---|---|
| `PORT` | `8080` | |
| `SNAP_RATE_LIMIT_PER_MINUTE` | `120` | Permintaan SNAP per IP per menit |
| `SANDBOX_PER_HOUR` | `10` | Sandbox baru per IP per jam |

Sandbox disimpan di memori dan dihapus setelah 24 jam.

## Test

```bash
mvn verify
```

Test memakai server sungguhan di port acak dan menandatangani permintaan seperti partner sungguhan. Yang diuji termasuk vektor HMAC-SHA512 RFC 4231, body yang diubah setelah ditandatangani, `X-EXTERNAL-ID` yang dipakai ulang, token kedaluwarsa, cap waktu basi, token partner lain, rekening dan transfer milik partner lain, 30 transfer paralel dari satu rekening, dan 400 transfer bolak-balik.

## Struktur kode

```
src/main/java/id/my/kadaferhidup/snapsim/
├── snap/   Signatures, SnapGateway (verifikasi), SnapServices (11/15/17/36), TokenStore, ReplayGuard, SnapException
├── bank/   Bank (rekening, transfer, kunci, double entry), Account, Partner, Transfer
├── http/   Api (routing), RateLimiter, StaticFiles
├── json/   Json: penulis dan pembaca JSON kecil
└── App.java
src/main/resources/web/   konsol web (HTML, CSS, JS tanpa framework)
```

Tanpa framework dan tanpa dependensi runtime: hanya JDK 21 (`com.sun.net.httpserver`, virtual thread, `java.security`).

## Lisensi

MIT
