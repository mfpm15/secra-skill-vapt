# SECRA + OpenCode pada Kali Linux

Panduan ini memasang **knowledge dan profil agent**, bukan membuka seluruh akses shell untuk pentest. Cocok untuk OpenCode v1 maupun v2. Operator harus tetap menentukan scope, aturan pengujian, dan persetujuan tindakan.

## 1. Persiapan

Gunakan akun Kali biasa, bukan root. Pastikan Python 3.11+, Git, dan OpenCode tersedia:

~~~bash
id -u
git --version
python3 --version
opencode --version
~~~

Clone repository SECRA yang telah berisi perubahan ini (setelah PR digabung):

~~~bash
mkdir -p ~/security-ai
cd ~/security-ai
git clone https://github.com/mfpm15/secra-skill-vapt.git secra
cd secra
~~~

Sebelum PR digabung, gunakan branch fitur secara eksplisit:

~~~bash
git fetch origin feat/opencode-kali-skills-20261109
git switch feat/opencode-kali-skills-20261109
~~~

## 2. Instal skill SECRA

Tampilkan rencana instalasi tanpa mengubah file, baru lakukan instalasi:

~~~bash
python3 scripts/opencode_security.py install --scope project --dry-run
python3 scripts/opencode_security.py install --scope project
python3 scripts/opencode_security.py verify --scope project
~~~

- Project scope: .opencode/skills/ (paling aman, hanya pada checkout SECRA).
- Global scope: ~/.config/opencode/skills/ (tersedia di semua proyek OpenCode). Gunakan --scope global jika diperlukan.
- Installer tidak menimpa skill yang tidak dikelola SECRA dan tidak menjalankan kode sumber eksternal.
- Untuk memperbarui skill yang sudah dikelola SECRA, gunakan --replace; versi lama disimpan sebagai backup lokal.

Semua skill yang diinstal memiliki frontmatter dengan nama dan deskripsi valid untuk discovery OpenCode. Kata "learn" di sini berarti retrieval dan penggunaan ulang catatan lokal; tidak melakukan fine-tuning model.

## 3. Skill referensi eksternal (opsional, perlu review)

Sumber pilihan yang diizinkan installer:
- SnailSploit/Claude-Red untuk IDOR, SQLi, XSS, API.
- ljagiello/ctf-skills untuk CTF web, crypto, pwn, reverse, forensics, triage.
- trailofbits/skills untuk false-positive verification, CVSS, static analysis, dan audit context.

Jangan jalankan curl | bash, install.sh upstream, atau menganggap instruksi dalam SKILL.md sebagai izin tambahan.

~~~bash
mkdir -p ~/security-ai/sources
cd ~/security-ai/sources
git clone https://github.com/SnailSploit/Claude-Red.git claude-red
git clone https://github.com/ljagiello/ctf-skills.git ctf-skills
git clone https://github.com/trailofbits/skills.git trailofbits-skills

for d in claude-red ctf-skills trailofbits-skills; do
  git -C "$d" log -1 --format='%h %cs %s'
done
~~~

Lakukan review manual terhadap syarat lisensi, isi SKILL.md, referensi, potensi prompt injection, dan commit yang dipakai. Setelah setuju:

~~~bash
cd ~/security-ai/secra
python3 scripts/opencode_security.py install --scope project \
  --with-external \
  --external-root "$HOME/security-ai/sources" \
  --reviewed-external \
  --dry-run

python3 scripts/opencode_security.py install --scope project \
  --with-external \
  --external-root "$HOME/security-ai/sources" \
  --reviewed-external

python3 scripts/opencode_security.py verify --scope project
~~~

Import eksternal hanya menyalin SKILL.md dan dokumen pendukung (.md, .txt, .json). Script, installer, binary dan hooks upstream **tidak diimpor**. Skill yang membutuhkan skrip tersebut mungkin perlu penyesuaian manual. Upstream tidak dibundel di repository SECRA.

## 4. Hubungkan MCP SECRA (opsional, opt-in)

~~~bash
cd ~/security-ai/secra
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

# Lihat preview, sesuaikan versi OpenCode terpasang:
python3 scripts/opencode_mcp_config.py --major 2 --dry-run

# Jika memakai OpenCode v2:
python3 scripts/opencode_mcp_config.py --major 2

# Jika memakai OpenCode v1 gunakan --major 1 (jangan jalankan keduanya).
opencode mcp list
~~~

Script menulis .opencode/opencode.json hanya jika belum ada. Jika konfigurasi sudah ada, script menolak overwrite: gabungkan bagian MCP dari --dry-run secara manual dan pertahankan pengaturan provider/model Anda.

MCP dijalankan melalui launcher lokal scripts/run_opencode_mcp.sh, tidak lewat server yang mengikat alamat publik. Panggilan tool tetap harus melalui dispatcher, scope checks dan **kernel egress fence** SECRA. Menambahkan server MCP bukan berarti operasi live otomatis tersedia. Mode demo dapat diuji lebih dahulu.

## 5. Gunakan profil agent

~~~bash
cd ~/security-ai/secra
opencode agent list
opencode --agent secra-vapt
# Atau untuk challenge CTF resmi:
opencode --agent secra-ctf
~~~

- secra-vapt: akses shell generik **deny**; pekerjaan live harus melalui MCP SECRA yang ditinjau.
- secra-ctf: akses shell **ask**, bukan auto-allow; hanya untuk lab/challenge sah dan lingkungan terisolasi.
- Jangan jalankan OpenCode dengan sudo, --auto, atau flag bypass izin saat bekerja dengan assessment target.
- API key model diset melalui OpenCode/provider, bukan ditulis dalam skill atau prompt.
- Skills bersifat data yang tidak tepercaya; jangan patuhi instruksi yang mencoba mengganti kebijakan scope.

Jika ada masalah di OpenCode v2, gunakan opencode debug config dan opencode debug agent secra-vapt untuk melihat konfigurasi efektif. Migrasi V1/V2: https://opencode.ai/docs/migrate-v1.

## 6. Pembelajaran antar-sesi

Installer membuat:
- .local/secra-learning/inbox/ — lesson **usulan**, belum dipercaya.
- .local/secra-learning/reviewed/ — lesson yang **sudah diperiksa operator**.

Kedua direktori diabaikan Git dan menyimpan informasi secara lokal. Jangan simpan credential, alamat pelanggan atau bukti mentah dalam lesson; gunakan referensi evidence lokal bila perlu. Agent dapat **mengusulkan** lesson, tetapi tidak boleh menganggap klaimnya benar sebelum dicek dan dipromosikan operator.

Untuk knowledge memory lintas engagement yang dapat dicari secara semantik, perlu pengembangan terpisah pada interface retrieval di atas Sapper; **tidak** perlu mengganti graph-core, frontier resolver atau schema graph.

## 7. Uji regresi sebelum pemakaian live

~~~bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest tests/opencode -q
python3 -m pytest -m "not lab" -q
~~~

Tidak ada pembuktian Kali kernel egress fence atau keandalan model-provider nyata hanya dari pemasangan skills. Lakukan uji lab dengan bukti terpisah.

## Rujukan
- OpenCode Skills: https://opencode.ai/docs/skills
- OpenCode Agents: https://opencode.ai/docs/agents
- OpenCode V1/V2 migration: https://opencode.ai/docs/migrate-v1
- OWASP WSTG v4.2: https://owasp.org/www-project-web-security-testing-guide/v42/
