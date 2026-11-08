# Korpus SECRA Phase 1

Semua 9 berkas raw bertanda [SINTETIS]. Tidak ada Nmap, ProjectDiscovery httpx CLI, atau ffuf CLI yang dijalankan terhadap target. httpx yang ditemukan di lingkungan engineer adalah library Python, bukan CLI ProjectDiscovery. Struktur format diadaptasi dari dokumentasi tool.

- nmap-sv.txt [SINTETIS] — Nmap -sV console; https://nmap.org/book/vscan-examples.html
- httpx.jsonl [SINTETIS] — ProjectDiscovery httpx -json JSONL; https://github.com/projectdiscovery/httpx
- ffuf.json [SINTETIS] — ffuf -of json; https://github.com/ffuf/ffuf
- headers.http [SINTETIS] — header HTTP Set-Cookie dan Basic Authorization
- page.html [SINTETIS] — HTML hostname, email, home path
- ssh-banner.log [SINTETIS] — SSH server identification dan IPv6
- auth-failure.log [SINTETIS] — Unix auth log dengan IP, hostname dan email
- split-auth.log [SINTETIS] — Bearer header terputus antar-baris, sha256, email
- client-record.txt [SINTETIS] — nama pelanggan dari registry ("Helios Analytics")

Expected output di tests/corpus/expected/ ditulis manual SEBELUM implementasi masker. Semua expected UTF-8 dengan newline akhir, diuji exact equality. Tier foreign.
