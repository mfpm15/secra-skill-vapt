---
name: web
description: Inventaris menyatakan HTTP/HTTPS dalam scope, dengan kewenangan read-only.
---
# Web surface review

## Pemicu pemilihan skill
1. Port HTTP/HTTPS diketahui terbuka.
2. Perlu mengamati status kode.
3. Ada indikasi redirect yang tidak boleh diikuti.
4. Perlu membedakan web server dan aplikasi.
5. Hasil httpx tersedia secara offline.
6. Ada daftar endpoint dari crawler resmi.
7. Butuh deteksi framework untuk review manual.
8. User ingin memilah kandidat template Nuclei.

## Urutan tindakan yang diperbolehkan
1. Ambil port HTTP dari parser Nmap, bukan tebakan model.
2. Periksa scope, fence dan status tool HTTP.
3. Untuk scope loopback tes aman gunakan local.http_head.
4. Pada jaringan approved gunakan curl.http_head melalui gateway tervalidasi.
5. Catat status HTTP, bukan full respons headers.
6. Gunakan katalog web.httpx hanya untuk analisis format sampai adapter tersedia.
7. Simpan daftar endpoint/URL mentah di vault, jangan ke model.
8. Ubah endpoint menjadi hitungan atau path digest bila perlu.
9. Tandai crawler katana sebagai blocked sampai batas domain/redirect diuji.
10. Tandai ffuf/gobuster/feroxbuster/dirsearch R3 sebagai review-only.
11. Tandai Nikto/WPScan R3 sampai template/rate kontrol disetujui.
12. Tandai Nuclei R3 dengan pemilihan template yang direview terpisah.

## Kombinasi tool dan batasnya
1. nmap -> curl HEAD -> parser status -> reporting.
2. httpx JSONL -> status per alias aset -> reporting.
3. katana + endpoint parser -> hitungan jalur saja.
4. whatweb + status HTTP -> hipotesis teknologi, bukan CVE.
5. nuclei JSONL -> severity/template ID -> verifikasi manual.
6. nikto -> validasi positive false secara manual.
7. wpScan -> cek versi produk dengan sumber patch resmi.
8. ffuf -> review request rate sebelum menghidupkan adapter.

## Cara membaca keluaran
1. Field status_code pada httpx dinormalisasi menjadi angka.
2. Field url dan host tidak dikirim ke model.
3. Parser Nuclei hanya menyimpan template-id dan severity.
4. Severity info/low/medium/high/critical tidak otomatis menjadi finding tervalidasi.
5. Signature matcher dapat false positive.
6. Location dan Set-Cookie tidak boleh masuk ringkasan.
7. Endpoint count adalah jumlah observasi, bukan endpoint valid.
8. HTTP 401 bisa menunjukkan proteksi aktif.
9. HTTP 404 bisa dibentuk WAF atau router.
10. Tidak ada raw HTML, JS, atau request body di prior model.

## Jebakan interpretasi
1. Redirect ke host luar scope dilarang.
2. Header auth dan cookie tetap terenkripsi di vault.
3. Jangan menilai HSTS dari satu path saja tanpa sumber yang benar.
4. Jangan mengeksekusi template yang membuat perubahan state.
5. Jangan menggunakan wordlist yang tidak dibatasi.
6. Jangan lakukan pengetesan kredensial.
7. Jangan menganggap HTTP 200 sebagai akses tanpa otorisasi.
8. Jangan mempercayai versi teknologi tanpa pembuktian.
9. Tidak ada brute force terhadap login.
10. Jangan mengira demo HTTPX adalah scan nyata.

## Kondisi stop atau eskalasi
1. Port tidak masuk daftar HTTP review => block.
2. Scope tidak termasuk URL => block.
3. Template Nuclei tidak direview => blocked.
4. Rate limit belum ditentukan => block.
5. Cookie/secret mendekati model boundary => block.
6. Model meminta metode POST write => approval.
7. Fence tidak attested => block.
8. Task cancelled => stopped.

## Langkah penutupan
1. Simpan evidence ref untuk HTTP HEAD.
2. Tulis label observed vs inferred.
3. Bandingkan hasil scan dengan dokumen konfigurasi yang tersedia.
4. Pakai specialist web atau verification sesuai fase.
5. Tampilkan status parser rejected secara eksplisit.
6. Jangan kehilangan konteks setelah satu tool selesai.
7. Lanjut hanya dari observasi yang tervalidasi.
8. Laporan sertakan keterbatasan akses tanpa autentikasi.

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
