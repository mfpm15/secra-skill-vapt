---
name: network
description: RoE memuat target IP/CIDR terverifikasi dan fokus pada protokol/rute jaringan.
---
# Network exposure and segmentation review

## Pemicu pemilihan skill
1. Ada port scan gateway tervalidasi.
2. Target memiliki service non-web.
3. Operator minta exposure summary.
4. Ada perbedaan TCP/UDP observations.
5. Terdapat dugaan segmentasi antar aset.
6. Perlu memeriksa resolver pinned.
7. Koneksi IPv6 belum diizinkan.
8. Network appliance memerlukan rate rendah.

## Urutan tindakan yang diperbolehkan
1. Validasi target IP terhadap scope tepat sebelum koneksi.
2. Jalankan hanya adapter live yang mempunyai fence attestation.
3. Gunakan nmap.tcp_top20 fixed args untuk baseline jika siap.
4. Jangan menjalankan masscan tanpa kontrol laju sandbox.
5. Jangan menjalankan scan UDP saat adaptor belum tersedia.
6. Jangan mengubah IP allowlist dari hasil DNS.
7. Baca state per port dari XML yang disegel.
8. Korelasikan service dengan catatan tim jaringan.
9. Tentukan apakah port HTTP diteruskan ke skill web.
10. Tandai protokol management untuk review manual.
11. Jangan memaksa bypass dengan proxy.
12. Catat status filter dan timeout.

## Kombinasi tool dan batasnya
1. Nmap -> service count -> reporting.
2. Nmap -> HTTP HEAD untuk port yang diizinkan.
3. Nmap -> TLS review jika HTTPS teridentifikasi.
4. Nmap -> SSH algorithm review tanpa login.
5. DNS lookup -> scope check -> no automatic target expansion.
6. SNMP -> R3 review and approved OID plan.
7. Masscan -> blocked until separate rate proof.
8. Switch ACL -> review diagram segmentasi.

## Cara membaca keluaran
1. Filtered port dapat berarti packet loss.
2. Timeout bisa disebabkan host load.
3. ARP discovery beda dengan TCP connect.
4. BPF cgroup ingress/egress harus diverifikasi kernel.
5. Systemd IPAddressAllow tidak memfilter port DNS.
6. IPv4-mapped IPv6 perlu uji negatif.
7. CNAME target bukan izin scan lain.
8. Network status tidak mengungkap akun pengguna.
9. Non-HTTP service tidak diprobel dengan HEAD.
10. Perubahan ACL memerlukan maintenance window.

## Jebakan interpretasi
1. Jangan menganggap CIDR scope otomatis boleh semua port.
2. Jangan memperluas koneksi akibat redirect.
3. Jangan menggunakan proxy lingkungan yang tidak dipin.
4. Jangan mengirim IP pelanggan ke model asing.
5. Jangan mengabaikan anak proses saat stop.
6. Jangan menjalankan packet flooding.
7. Jangan mengubah DNS server target.
8. Jangan menyatakan firewall rules aman hanya dari port scan.
9. Jangan mengandalkan validator Python untuk isolasi.
10. Jangan mengklaim BPF attested tanpa witness nyata.

## Kondisi stop atau eskalasi
1. Fence gate gagal => blocked.
2. Loopback exception hanya untuk HEAD lokal.
3. IPv6 belum di scope => blocked.
4. DNS rebinding => blocked.
5. Unknown resolver => blocked.
6. Scan high rate => approval.
7. Proses sisa setelah stop => gagal release.
8. R3/R4 tidak dapat dieksekusi oleh adapter katalog.

## Langkah penutupan
1. Gunakan output_ref tersanitasi.
2. Audit per run ID dan request ID.
3. Berhenti setelah 20 menit maksimal.
4. Lacak timeout di event bus.
5. Pisahkan discovery dan proof.
6. Simpan cap waktu latensi.
7. Utamakan jalur read-only.
8. Laporkan keterbatasan network visibility.

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
