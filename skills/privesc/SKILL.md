---
name: privesc
description: Ada konfigurasi privilege yang dibagikan secara sah untuk audit defensif.
---
# Privilege boundary verification

## Pemicu pemilihan skill
1. Role memiliki izin terlalu luas menurut kebijakan.
2. Ada service account dengan hak yang perlu ditinjau.
3. User membagikan policy sudo yang telah disanitasi.
4. Terdapat file permission audit tanpa isi rahasia.
5. Perlu membedakan local admin vs global admin.
6. Ada laporan user yang mendapat hak istimewa.
7. Tersedia baseline hardening resmi.
8. Perlu membuat rekomendasi tanpa percobaan eksploit.

## Urutan tindakan yang diperbolehkan
1. Dapatkan baseline security policy yang berlaku.
2. Validasi pemilik data dan izin penggunaan.
3. Identifikasi least-privilege objective dari dokumen.
4. Kelompokkan izin menurut read/write/admin.
5. Bandingkan akses efektif dengan requirement tugas.
6. Catat kontrol compensating yang sudah ada.
7. Gunakan temuan konfigurasi sebagai candidate.
8. Mintakan review manusia untuk perubahan permission.
9. Jangan melakukan privilege escalation atau menulis payload.
10. Jangan mengubah file OS saat penilaian.
11. Jangan menjalankan script tidak ditinjau.
12. Gunakan model hanya untuk mapping rekomendasi.

## Kombinasi tool dan batasnya
1. Inventory aset -> policy review -> reporting.
2. Existing audit result -> parser generic -> human interpretation.
3. Sudo policy review -> least privilege check.
4. Service config -> permission boundary check.
5. IAM role export -> scope-of-access review.
6. Event log -> pattern review tanpa usernames.
7. CVE bulletin -> patch recommendation review.
8. Privilege graph -> display intent without execution.

## Cara membaca keluaran
1. ACL dibaca sesuai inheritance/deny order.
2. Bit setuid bukan bukti exploitability.
3. Writable path belum tentu remote exploitable.
4. Perbedaan user vs process token harus jelas.
5. Config snapshot mungkin outdated.
6. Scripted output dapat mengandung command injection.
7. Ringkasan parser generic tidak setara finding.
8. Hash raw membuktikan integritas, bukan kesimpulan.
9. Sumber bukti harus dapat diaudit manusia.
10. Finding confidence rendah bila akses efektif tak dibuktikan.

## Jebakan interpretasi
1. Tidak mengirim password, private key, token.
2. Tidak menjalankan root shell dari prompt model.
3. Tidak menurunkan sandbox.
4. Jangan menganggap seluruh sudo entry berbahaya.
5. Jangan melaporkan CVE tanpa versi dan bukti.
6. Jangan melakukan persistence.
7. Jangan melakukan credential dumping.
8. Jangan melewati operator stop.
9. Jangan menggabungkan file customer dalam prompt.
10. Jangan menyatakan akses sudah diperoleh.

## Kondisi stop atau eskalasi
1. Permintaan akses root operasi => human review.
2. Perubahan state => approval terpisah.
3. Scope tidak menyebut host => block.
4. Ada secret pada evidence => quarantine.
5. Perintah di luar manifest => block.
6. Kernel tidak verified => tidak ada live action.
7. Approval R4 bukan izin exploit otomatis.
8. Deadline/step limit => exhausted.

## Langkah penutupan
1. Buat rekomendasi hardening yang bisa diverifikasi.
2. Tambahkan kriteria rollback bagi perubahan manual.
3. Pilih checklist berbasis konfigurasi.
4. Catat owner control bila diketahui.
5. Gunakan bahasa observasi vs asumsi.
6. Jaga evidence immutable.
7. Catat prioritas remediation konservatif.
8. Report tidak boleh menyertakan payload eksploitasi.

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
