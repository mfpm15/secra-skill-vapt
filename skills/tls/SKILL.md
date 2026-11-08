---
name: tls
description: Port TLS atau SSH diizinkan untuk pemeriksaan negosiasi non-invasif.
---
# TLS and SSH configuration review

## Pemicu pemilihan skill
1. HTTPS port terdeteksi.
2. SSH port terdeteksi.
3. Butuh inventaris protokol TLS.
4. Ada pertanyaan sertifikat yang telah kedaluwarsa.
5. Operator meminta pemeriksaan cipher posture.
6. Tersedia output sslscan/testssl untuk parsing.
7. Tersedia output ssh-audit tanpa kredensial.
8. Perlu membedakan temuan konfigurasi dan exploitability.

## Urutan tindakan yang diperbolehkan
1. Konfirmasi port yang disetujui dan fingerprint service.
2. Gunakan metadata dari gateway, bukan hostname dari model.
3. Pastikan control plane memblokir DNS di luar scope.
4. Tandai sslscan R2 sebagai katalog sampai adapter sandbox siap.
5. Tandai testssl R2 sebagai katalog sampai adapter sandbox siap.
6. Tandai ssh-audit R2 sebagai katalog sampai adapter sandbox siap.
7. Jika output disuplai manual, parse hanya versi protokol.
8. Hitung TLSv1.0/TLSv1.1 sebagai candidate legacy, bukan CVE pasti.
9. Jangan menyimpan raw certificate subject ke LLM.
10. Pisahkan temuan SSH handshake dari auth.
11. Review ketidaksesuaian service-port dengan operator.
12. Sampaikan ke reporting hanya nilai allowlist.

## Kombinasi tool dan batasnya
1. Nmap -> klasifikasi HTTPS -> TLS output parser.
2. Nmap -> SSH service -> ssh-audit parsed metadata.
3. sslscan + testssl -> korelasi protokol yang sama.
4. curl HTTP HEAD -> hanya status, bukan TLS cipher lengkap.
5. TLSv1.0 observation -> manual review standar organisasi.
6. TLSv1.3 observation -> tidak otomatis jaminan aman.
7. ssh-audit -> algoritma lemah sebagai candidate untuk review.
8. Sertifikat -> pemeriksaan chain dan trust secara terpisah.

## Cara membaca keluaran
1. TLS text parser hanya versi protokol yang dikenali.
2. Jika parser memberi unknown, catat hash raw tanpa echo.
3. Sertifikat CN/SAN dapat mengungkap domain privat.
4. Cipher list yang panjang tetap di evidence, bukan prompt.
5. Teks audit SSH bisa memuat host key fingerprint, jangan dipublikasikan.
6. Negosiasi gagal mungkin firewall, bukan protokol lemah.
7. Versi TLS unsupported berbeda dari kondisi blocked.
8. Output beberapa host tidak otomatis masuk scope.
9. Metadata severity berasal dari policy review.
10. Status handshake belum tentu menggambarkan konfigurasi akhir.

## Jebakan interpretasi
1. Tidak menggunakan --insecure sebagai pembenaran trust.
2. Jangan melakukan autentikasi SSH otomatis.
3. Jangan mengklaim sertifikat trusted tanpa validasi chain.
4. Jangan mencampur TLS dan SSH sebagai satu temuan.
5. Jangan mengirim private key/certificate raw.
6. Jangan mengikuti hostname yang di-resolve ke IP lain.
7. Jangan menyimpulkan HSTS dari TLS scan.
8. Jangan menyimpulkan absence of vuln dari TLSv1.3.
9. Jangan jalankan scan berulang pada device lemah.
10. Jangan menyalahartikan downgrade karena middlebox.

## Kondisi stop atau eskalasi
1. Port tidak di scope => blocked.
2. Handshake keluar target pinned => blocked.
3. R2 adapter belum tersedia => blocked.
4. Output memuat private key => quarantine.
5. Perlu credential access => stop.
6. User cancel => stopped.
7. Data parser rejected => review evidence manual.
8. Tidak ada attestation => tidak ada eksekusi live.

## Langkah penutupan
1. Sertakan versi tool saat laporan jika diketahui.
2. Simpan cap waktu pengamatan.
3. Pisahkan issue policy dari issue exploitable.
4. Gunakan asset alias untuk seluruh ringkasan.
5. Tag confidence unknown jika parser generic.
6. Korelasi dengan sumber vendor aktual.
7. Kenali false positive akibat terminasi proxy.
8. Akhiri dengan rekomendasi konfigurasi konservatif.

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
