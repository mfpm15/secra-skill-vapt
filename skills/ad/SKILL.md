---
name: ad
description: Operator menyediakan inventaris AD berizin dan menginginkan telaah konfigurasi tanpa kredensial.
---
# Active Directory defensive inventory

## Pemicu pemilihan skill
1. Service LDAP/Kerberos/SMB tercatat.
2. Terdapat inventaris peran server resmi.
3. Perlu review boundary account privilege.
4. Ada catatan audit AD dari pelanggan.
5. Ada pertanyaan tentang delegation policy.
6. Operator ingin status tool enum4linux-ng.
7. Data jaringan belum membuktikan realm AD.
8. Perlu ringkasan aset kritis tanpa username.

## Urutan tindakan yang diperbolehkan
1. Konfirmasi entitas organisasi serta scope AD tertulis.
2. Gunakan daftar resmi yang diunggah pengguna, bukan query jaringan baru.
3. Periksa kategori account policy secara konseptual.
4. Jangan mengeksekusi netexec credential operations.
5. Jangan mengeksekusi Impacket secret extraction.
6. Tandai hydra R4 selalu blocked.
7. Tandai enum4linux-ng R3 sebagai review-only.
8. Catat risiko delegasi dari konfigurasi yang sudah disetujui.
9. Gunakan alias ASSET_001 untuk pengelompokan evidence.
10. Arahkan informasi sensitif ke vault lokal, bukan model.
11. Klasifikasi port 88/389/445 sebagai observed, bukan AD pasti.
12. Mintakan verifikasi manual sebelum membuat finding.

## Kombinasi tool dan batasnya
1. Nmap port inventory -> AD suspected -> manual asset review.
2. Approved directory export -> least-privilege analysis.
3. Event logs sanitized -> policy inference -> reviewer.
4. SMB service -> enum4linux-ng catalog availability check.
5. Credential exposure claim -> secure human review, no credentials exported.
6. Searchsploit local index -> source citation, no PoC execution.
7. Architecture diagram -> trust boundary review.
8. AD audit policy -> reporting with sanitized control state.

## Cara membaca keluaran
1. Port 445 tidak menjamin domain controller.
2. Kerberos port tidak membuktikan akun rentan.
3. Username/domain names adalah informasi privat.
4. Credential-related output harus diganti REDACTED.
5. Gagal login tidak boleh diuji ulang otomatis.
6. Privilege groups membutuhkan konteks ACL yang benar.
7. Service state filtered bukan kompromi.
8. Klasifikasi auth_summary tidak memuat password.
9. Audit log parsers hanya hitungan kategori.
10. Evidence ref bukan izin untuk mempublikasikan data.

## Jebakan interpretasi
1. Jangan melakukan password spraying.
2. Jangan membuat ticket request otomatis.
3. Jangan menjalankan secretsdump.
4. Jangan melakukan SMB lateral movement.
5. Jangan menguji relasi trust dengan eksploitasi.
6. Jangan mengekstraksi LDAP users tanpa izin.
7. Jangan mengasumsikan group member adalah admin di semua host.
8. Jangan mempercayai output tool tanpa mapping organisasi.
9. Jangan memuat credential pelanggan ke provider LLM.
10. Jangan menaikkan hak akses untuk memenuhi step.

## Kondisi stop atau eskalasi
1. R4 tool dipilih => blocked.
2. Approval tidak membuat adapter otomatis aktif.
3. RoE AD tidak ada => stop.
4. Output mengandung secret => quarantine.
5. Host tambahan ditemukan => scope review.
6. Alat paket tidak terpasang => BLOCKED_MISSING_BINARY.
7. Agent mencapai 25 langkah => exhausted.
8. Pelanggan menarik izin => stopped.

## Langkah penutupan
1. Prioritaskan review ACL least privilege.
2. Pisahkan data directory dan data host.
3. Laporkan jenis policy, bukan nama akun.
4. Gunakan specialist network untuk observasi port.
5. Gunakan reporting untuk susunan bukti.
6. Review perubahan state oleh manusia.
7. Simpan tiap keputusan di event ledger.
8. Jangan mengubah source truth terhadap ACL.

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
