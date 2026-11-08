---
name: recon
description: Ada target IPv4 dengan scope eksplisit dan belum ada inventaris port/servis yang tervalidasi.
---
# Recon dan inventaris layanan

## Pemicu pemilihan skill
1. Port belum terinventaris.
2. Perlu memilih antara mode demo dan live.
3. Ada indikasi DNS/domain dalam daftar aset resmi.
4. Pengguna membutuhkan ringkasan service exposure.
5. Tool Nmap tidak ditemukan di host Kali.
6. Data inventaris lama sudah kedaluwarsa.
7. Terdapat perbedaan status port antar pengamatan.
8. Perlu membedakan scope tunggal dan domain yang belum disetujui.

## Urutan tindakan yang diperbolehkan
1. Periksa scope target dan versi RoE yang dipakai worker.
2. Pastikan fence telah lolos attestation sebelum memilih tool jaringan nyata.
3. Untuk pengujian offline pilih fixture demo.nmap_scan yang diberi label simulasi.
4. Untuk live pilih nmap.tcp_top20 saja bila adapter siap dan fence attested.
5. Periksa binary pin dan timeout yang dilaporkan gateway.
6. Baca parser XML Nmap untuk state open/closed/filtered dan port numeric.
7. Cek service label terhadap daftar allowed_services, lainnya unknown.
8. Buat daftar observasi port tanpa mengklaim kerentanan.
9. Tandai Nmap SYN, UDP dan NSE sebagai katalog saja selama belum ada adapter.
10. Tandai masscan sebagai non-aktif agar laju pemindaian tidak lepas kendali.
11. Untuk domain/passive OSINT tampilkan ketersediaan subfinder/amass, jangan otomatis mencoba.
12. Untuk hasil DNS, tolak CNAME atau hasil resolusi keluar scope sebelum aksi lain.

## Kombinasi tool dan batasnya
1. nmap.tcp_top20 -> review port HTTP yang ditemukan -> curl.http_head.
2. nmap.tcp_top20 -> klasifikasi SSH -> review metadata tanpa login.
3. inventory.read -> nmap.tcp_top20 -> report.summary hanya bila tersedia.
4. whatweb adalah katalog fingerprint, bukan pembuktian komponen rentan.
5. subfinder -> dnsx tetap katalog sampai kontrol resolver dipin.
6. amass -> tinjau domain masuk scope, bukan otomatis memperluas target.
7. whois -> konfirmasi kepemilikan oleh manusia karena informasi dapat stale.
8. dig -> cek tipe DNS terpilih, bukan permintaan wildcard tanpa batas.

## Cara membaca keluaran
1. Nmap XML: portid angka 1..65535, protocol tcp/udp.
2. Nmap state open berarti ada respon, bukan celah keamanan.
3. State filtered bukan bukti host mati.
4. Service fingerprint bisa salah jika port non-standar.
5. Hostname/IP pada XML tetap tersimpan di evidence, bukan ke model.
6. Jika parser rejected, catat hash raw dan status gagal parse.
7. Catat jumlah port yang ditemukan dan perbedaan antar waktu.
8. Status scan cancelled/timedout tidak boleh dihitung sebagai selesai.
9. Gunakan evidence://id/id, bukan path filesystem untuk model.
10. Hasil OSINT domain harus di-hash atau disimpan lokal saja.

## Jebakan interpretasi
1. Jangan mengasumsikan service berasal dari port default.
2. Jangan menambahkan port tanpa persetujuan scope.
3. Jangan mengulang seluruh scan bila output terlambat.
4. Jangan melakukan SYN raw socket tanpa capability/sandbox terverifikasi.
5. Jangan menyalin contoh command HexStrike secara buta.
6. Jangan menyimpulkan CVE dari versi banner saja.
7. Jangan mengirim seluruh Nmap XML ke LLM.
8. Jangan menerima IP baru hanya dari CNAME target.
9. Jangan mengabaikan IPv6 yang belum didukung.
10. Jangan memaksa bypass ketika fence menolak.

## Kondisi stop atau eskalasi
1. Target di luar scope => blocked.
2. Tidak ada root-owned fence attestation => blocked.
3. Binary digest berubah => blocked.
4. DNS keluar scope => blocked.
5. Deadline habis => exhausted.
6. Operator stop => stopped.
7. Raw evidence gagal disegel => failed.
8. Kebutuhan script aktif => approval required.

## Langkah penutupan
1. Komitkan baseline port hanya setelah sealed parse.
2. Bedakan TCP connect dari SYN/UDP dalam report.
3. Pakai ID tool manifest, bukan nama binary langsung.
4. Status binary installed bukan bukti adapter aktif.
5. Agent boleh membaca skill network untuk hop berikutnya.
6. Audit harus merekam alasan penolakan.
7. Tampilkan jumlah port, bukan alamat host.
8. Korelasikan observasi dengan timestamp lokal.

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
