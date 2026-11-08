---
name: reporting
description: Ada observasi terstruktur dengan bukti terenkripsi dan status task yang jelas.
---
# Evidence-focused security reporting

## Pemicu pemilihan skill
1. Task sudah completed/exhausted/stopped.
2. Perlu menulis ringkasan temuan untuk operator.
3. Output parser mengandung severity.
4. Laporan harus memisahkan hasil demo/live.
5. Ada tindakan gateway yang diblokir.
6. Perlu mengekspor ringkasan tanpa PII.
7. Ada temuan yang belum diverifikasi.
8. Butuh referensi evidence untuk auditor.

## Urutan tindakan yang diperbolehkan
1. Kumpulkan daftar receipt dari event bus berurutan.
2. Konfirmasi tiap receipt memiliki status dan output_ref bila berhasil.
3. Periksa raw_sha256 untuk korelasi internal, jangan membagikan raw.
4. Bagi observasi menjadi factual, inferred dan unverified.
5. Label SIMULATED untuk demo.nmap_scan dan demo.httpx_probe.
6. Jangan mengubah observation menjadi vulnerability tanpa validasi.
7. Tulis severity hanya jika berasal dari schema yang diterima.
8. Jangan masukkan username, IP pelanggan atau token.
9. Cantumkan timebox dan langkah yang diambil.
10. Catat denied/exhausted agar terlihat oleh pentester.
11. Sertakan rekomendasi perubahan kebijakan yang aman.
12. Sampaikan keterbatasan scan dan scope secara eksplisit.

## Kombinasi tool dan batasnya
1. Nmap XML parsed -> port table ringkas.
2. HTTPx JSONL -> status distribution.
3. Nuclei JSONL -> template-id dan severity candidate.
4. TLS versions -> legacy protocol review.
5. API endpoint counter -> exposure overview.
6. Auth output -> event count, credential data REDACTED.
7. Task event bus -> chronological audit trail.
8. Evidence vault -> read-only auditor verification.

## Cara membaca keluaran
1. Evidence hash memastikan integritas file, bukan nilai temuan.
2. Critical severity dari tool belum otomatis confirmed.
3. Tidak ada response bukan berarti host aman.
4. Parser rejected berarti tidak ada fakta terstruktur yang dapat dipercaya.
5. Parsed entry tidak boleh memuat url raw.
6. Waktu adalah UTC atau dicatat offsetnya.
7. R3 queued berarti belum pernah dijalankan.
8. R4 blocked bukan temuan keamanan pelanggan.
9. Exit code nonzero tidak sama dengan CVE.
10. Model inference selalu dibedakan dari measured result.

## Jebakan interpretasi
1. Jangan menyalin raw scan ke laporan publik.
2. Jangan mengarang PoC.
3. Jangan menyertakan kredensial.
4. Jangan menulis impact tanpa evidence.
5. Jangan menyebut passing fixture sebagai scan pelanggan.
6. Jangan menutup known uncertainty.
7. Jangan menyembunyikan blocked-by-fence.
8. Jangan menyimpulkan keterpaparan internet dari loopback.
9. Jangan menghapus event karena error.
10. Jangan memutus link ke evidence reference.

## Kondisi stop atau eskalasi
1. Output mentah terdeteksi pada model output => block.
2. Tidak ada scope/izin => report internal only.
3. Bukti belum disegel => report incomplete.
4. Parser status rejected => review required.
5. Tidak ada scan sungguhan => laporkan simulated saja.
6. R3 pending => jangan tulis executed.
7. Stop atau exhausted => laporkan status akhir.
8. Temuan yang belum diverifikasi => candidate.

## Langkah penutupan
1. Gunakan label hasil dari schema canonical.
2. Beri timestamp dan ID engagement.
3. Buat daftar evidence dengan hash.
4. Pisahkan quick wins dari long-term remediation.
5. Sediakan status approval di ringkasan.
6. Gunakan reviewer untuk severity override.
7. Pastikan placeholder alias tetap utuh.
8. Tulis keputusan batas keamanan secara gamblang.

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
