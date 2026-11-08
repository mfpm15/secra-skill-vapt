---
name: api
description: Target memiliki HTTP API yang telah tercantum pada RoE dan metode baca aman.
---
# API surface and contract validation

## Pemicu pemilihan skill
1. Response memberi indikasi API.
2. Tersedia spesifikasi OpenAPI publik/diizinkan.
3. Ada GraphQL endpoint yang didokumentasikan.
4. Perlu memeriksa status HEAD pada route resmi.
5. Endpoint ditemukan dalam evidence.
6. Perlu memeriksa pengenal data sensitif.
7. Ada perbedaan status auth 401 dan 403.
8. Tool enumerasi parameter belum terintegrasi.

## Urutan tindakan yang diperbolehkan
1. Pastikan hanya metode read-only yang terotorisasi.
2. Tentukan route approved dari dokumen pengguna, bukan hasil generasi LLM.
3. Gunakan curl.http_head untuk observasi permukaan minimal.
4. Konfirmasi resource tidak mengalami perubahan akibat request.
5. Bandingkan HTTP status dengan metode dan konteks auth.
6. Ambil meta request, jangan simpan body pelanggan ke model.
7. Catat jumlah endpoint melalui parser endpoint_count.
8. Tinjau arjun sebagai katalog R3, tidak auto fuzz.
9. Tinjau kiterunner R3 hanya setelah route/rate disetujui.
10. Tinjau graphql-cop R3 hanya untuk schema review yang disetujui.
11. Jaga header Authorization di evidence saja.
12. Rangkum perubahan response sebagai observasi, bukan kelemahan terbukti.

## Kombinasi tool dan batasnya
1. Nmap HTTP port -> curl HEAD -> status parser.
2. httpx JSONL -> kumpulan status -> manual API review.
3. API spec lokal -> endpoint counter -> reporting.
4. GraphQL schema resmi -> daftar operasi manual yang berizin.
5. arjun -> review prior to adapter implementation.
6. kiterunner -> review rate and endpoint contract.
7. graphql-cop -> inspect known schema exposure manually.
8. curl HEAD -> jika data sensitif terlihat, hentikan pemrosesan model.

## Cara membaca keluaran
1. 401 berarti autentikasi perlu atau skema berbeda.
2. 403 berarti otorisasi ditolak, jangan cari jalan pintas.
3. 404 bisa routing bukan bukti resource hilang.
4. 429 berarti rate control aktif.
5. 5xx tidak otomatis bukti injection.
6. Endpoint URI dapat berisi ID pelanggan, hanya hitungan boleh keluar.
7. Parser generic tidak membuktikan hasil lengkap.
8. Beda JSONL dan JSON array ketika memilih parser.
9. Jangan simpan token di structured summary.
10. GraphQL introspection aktif bukan selalu salah konfigurasi.

## Jebakan interpretasi
1. Hindari mutasi data dalam verifikasi otomatis.
2. Jangan uji IDOR tanpa persetujuan eksplisit dan data sintetis.
3. Jangan mengubah auth header untuk menguji bypass otomatis.
4. Jangan menganggap endpoint discovery sama dengan finding.
5. Jangan mengirim body API yang mungkin memuat PII.
6. Jangan jalankan password stuffing.
7. Jangan menganggap HTTP HEAD sama dengan GET.
8. Jangan mengandalkan satu response error untuk kesimpulan.
9. Jangan mengeksekusi GraphQL mutation.
10. Jangan memperluas scope melalui redirect.

## Kondisi stop atau eskalasi
1. Endpoint tidak disetujui => blocked.
2. Metode write terdeteksi => review.
3. Rate limit tercapai => stop.
4. Token/raw PII berpotensi dikirim ke LLM => block.
5. Tool CLI tidak dipin => blocked.
6. Kernel fence tidak verified => blocked.
7. R3 membutuhkan persetujuan manusia.
8. Kesalahan parser => tidak ada temuan otomatis.

## Langkah penutupan
1. Gunakan tipe finding candidate dan confidence terpisah.
2. Cantumkan bukti status dan waktu.
3. Model tidak mengakses request mentah.
4. Batas maksimal 25 langkah tetap berlaku.
5. Loader skill dipilih dari service HTTP.
6. Tandai klaim otorisasi sebagai perlu review.
7. Pakai port dari inventaris, bukan dugaan.
8. Simpan hasil parsing tanpa endpoint literal.

## Kontrak kerja yang berlaku
1. Konfirmasi otorisasi engagement dan alias ASSET_001 sebelum memulai.
2. Gunakan data hasil pemeriksaan sebelumnya, jangan mencoba alamat baru.
3. Baca mode fence dan status ketersediaan adapter dari manifest.
4. Jika adapter BLOCKED, jangan membangun argv pengganti.
5. Simpan bukti mentah hanya pada vault terenkripsi lokal.
6. Ringkasan untuk model hanya field yang diizinkan parser.
7. Hindari memasukkan rahasia, cookie, token atau target mentah ke prompt.
8. Selesaikan satu tindakan terverifikasi sebelum memilih tindakan berikutnya.

## Kontrak hasil
1. Laporkan label SIMULATED untuk hasil fixture, jangan mengubahnya menjadi temuan.
2. Cantumkan referensi evidence tanpa menyalin keluaran mentah.
3. Bedakan keputusan model dari hasil aktual tool.
4. Akhiri bila ruang lingkup tidak cukup atau otorisasi berubah.
5. Hormati penghentian operator dan batas waktu agent.
6. Simpan ketidakpastian sebagai [ASUMSI], bukan fakta.
7. Eskalasi kebutuhan R3/R4 ke review tanpa eksekusi otomatis.
8. Gunakan hasil terstruktur saja untuk rekomendasi tindakan berikutnya.
