# Instalasi Global SECRA Skills + Agents pada OpenCode V2 (Kali Linux)

**Fokus: OpenCode v2, tanpa perlu masuk folder proyek ketika memakai agent.**

Semua skills dan agent profile dipasang ke direktori pengguna `~/.config/opencode/`. Anda bisa menjalankan `opencode --agent secra-vapt` atau `opencode --agent secra-ctf` dari direktori kerja mana pun. Repo sumber tetap dibutuhkan untuk mengelola update dan menjalankan server MCP, tetapi **tidak perlu dijadikan current working directory**.

Referensi resmi:
- https://opencode.ai/docs/skills/
- https://opencode.ai/docs/agents/
- https://opencode.ai/docs/permissions/
- https://opencode.ai/docs/mcp-servers/

## 1. Persiapan user biasa

Gunakan akun Kali biasa, tidak perlu sudo saat menginstal global user-level skills. Pastikan OpenCode v2 tersedia:

~~~bash
id -u
opencode --version
python3 --version
git --version
~~~

Simpan source repository di lokasi permanen apa pun. Contoh yang tidak mengganggu folder pekerjaan:

~~~bash
mkdir -p "$HOME/.local/share/secra"
git clone https://github.com/mfpm15/secra-skill-vapt.git \
  "$HOME/.local/share/secra/repo"
~~~

Jika sudah pernah clone, gunakan checkout Anda yang sekarang; jangan clone dua kali atau menimpa perubahan lokal. Ganti path pada perintah berikut sesuai checkout Anda.

## 2. Pasang 20 skills asli + 13 agent global

~~~bash
SECRA_REPO="$HOME/.local/share/secra/repo"

python3 "$SECRA_REPO/scripts/opencode_global.py" install \
  --major 2 --dry-run

python3 "$SECRA_REPO/scripts/opencode_global.py" install \
  --major 2

python3 "$SECRA_REPO/scripts/opencode_global.py" verify \
  --major 2
~~~

Hasil:

- 20 keterampilan SECRA di `~/.config/opencode/skills/`.
- 2 agent utama: `secra-vapt` dan `secra-ctf`.
- 11 agent spesialis untuk recon, web, API, network, verification, reporting, dan CTF.
- Local learning di `~/.local/share/secra-learning/{inbox,reviewed}/`.
- Receipt dan checksum dipasang agar modifikasi file dan perubahan upstream bisa diperiksa.

Installer tidak mengubah provider/model, tidak memasang tools offensif, tidak mengaktifkan MCP, dan tidak menjalankan perintah dari referensi luar. Ia tidak menimpa agent/skill yang tidak dikelola SECRA.

## 3. Knowledge eksternal opsional

Jangan jalankan installer upstream; hanya clone untuk review. Ini bukan dependency wajib:

~~~bash
mkdir -p "$HOME/.local/share/secra/sources"
git clone https://github.com/SnailSploit/Claude-Red.git \
  "$HOME/.local/share/secra/sources/claude-red"
git clone https://github.com/ljagiello/ctf-skills.git \
  "$HOME/.local/share/secra/sources/ctf-skills"
git clone https://github.com/trailofbits/skills.git \
  "$HOME/.local/share/secra/sources/trailofbits-skills"
~~~

Catat commit SHA, tinjau lisensi, konten, tautan, instruksi prompt, referensi, dan script yang disebut dalam SKILL.md.

Setelah benar-benar direview dan disetujui:

~~~bash
SECRA_REPO="$HOME/.local/share/secra/repo"
python3 "$SECRA_REPO/scripts/opencode_global.py" install --major 2 \
  --with-external \
  --external-root "$HOME/.local/share/secra/sources" \
  --reviewed-external --dry-run

python3 "$SECRA_REPO/scripts/opencode_global.py" install --major 2 \
  --with-external \
  --external-root "$HOME/.local/share/secra/sources" \
  --reviewed-external

python3 "$SECRA_REPO/scripts/opencode_global.py" verify --major 2
~~~

Saat ini hanya 14 lokasi knowledge eksternal yang di-allowlist, bukan seluruh folder upstream. Importer menyalin markdown/txt/JSON reference, **tidak mengeksekusi dan tidak menyalin script runnable** dari upstream. Jika suatu skill menyebut file script upstream, agent tidak boleh menganggap script tersebut sudah tersedia. Untuk tool Kali, cek readiness pada langkah 5.

## 4. Konfigurasikan MCP secara global (opsional)

SECRA MCP memungkinkan model memilih tool *yang direview* dan memanggilnya lewat typed dispatcher. Instal dependensi pada virtual environment lokal:

~~~bash
SECRA_REPO="$HOME/.local/share/secra/repo"
python3 -m venv "$SECRA_REPO/.venv"
"$SECRA_REPO/.venv/bin/python" -m pip install \
  -r "$SECRA_REPO/requirements.txt"

# Lihat konfigurasi MCP V2 sebelum menulis
python3 "$SECRA_REPO/scripts/opencode_global.py" install \
  --major 2 --mcp-preview

# Pasang MCP pada global config user
python3 "$SECRA_REPO/scripts/opencode_global.py" install \
  --major 2 --with-mcp
~~~

Penting:
- Lokasi binary Python, launcher dan cwd MCP menggunakan path absolut repository yang dikloning. **Jangan hapus atau pindahkan clone setelah mengaktifkan MCP**; jika dipindahkan, perbarui konfigurasi.
- Gunakan OpenCode V2 `mcp.servers.secra` dengan `codemode: false` supaya tools dikontrol sebagai aksi `secra_*` dan tidak membutuhkan izin Code Mode generik.
- Jika `~/.config/opencode/opencode.jsonc` sudah ada, installer sengaja tidak mengubahnya. Gunakan `--mcp-preview` dan gabungkan entri MCP secara manual, agar config lama tidak rusak.
- Jika Anda memiliki setting `opencode.json` berbentuk JSON, installer akan mempertahankan setting yang ada, membuat backup, dan hanya menambah MCP.
- Jangan melakukan `sudo` atau menjalankan OpenCode dalam mode auto-approve.

Aktivasi MCP **tidak** membuka eksekusi bebas. Tool masih memerlukan task/engagement ID dan pemeriksaan scope. Operasi live yang membutuhkan Kali egress fence tetap gagal tertutup sampai attestation lokal terbukti.

## 5. Audit tools Kali (tidak mengeksekusi)

~~~bash
SECRA_REPO="$HOME/.local/share/secra/repo"

python3 "$SECRA_REPO/scripts/opencode_toolcheck.py"
python3 "$SECRA_REPO/scripts/opencode_toolcheck.py" --json

opencode debug agents
opencode debug skill
opencode mcp list
~~~

Toolcheck hanya memeriksa PATH dan manifest, tidak menjalankan scan dan tidak memasang binary. Kategori mencakup recon, web, API, TLS, CTF pwn, reverse, crypto dan forensics. Status *available* berarti binary ditemukan, **bukan** sudah berhasil diuji atau diberi izin jaringan.

Untuk verifikasi eksekusi MCP, gunakan task demo/offline SECRA dengan UUID yang valid, lalu pastikan server benar-benar merespons `tools/list` dan tool demonstrasi. Unit dan integration tests sudah menguji protokol resmi; uji OpenCode terpasang di Kali tetap wajib.

## 5a. Jalankan UI SECRA untuk mengisi scope secara lokal

Buka **terminal Kali kedua**; tidak perlu pindah folder aktif:

~~~bash
SECRA_REPO="$HOME/.local/share/secra/repo"
PYTHONPATH="$SECRA_REPO" \
  "$SECRA_REPO/.venv/bin/python" -m app
~~~

Buka `http://127.0.0.1:8765`, masukkan token operator yang tercetak di terminal, isi target dan scope sendiri, centang konfirmasi otorisasi, dan buat task. UI akan menampilkan **task ID (UUID)**. Untuk uji pertama pilih **offline demo**. Kirim hanya task ID ini ke agent OpenCode, bukan target mentah jika memakai model eksternal.

Untuk operasi real, backend tetap membutuhkan egress attestation yang independen. Mengisi scope bukan berarti semua tool live otomatis diaktifkan.

## 6. Scope selalu diisi operator, bukan hardcoded

Agent `secra-vapt` akan meminta Anda mengisi engagement melalui UI SECRA lokal:

- Nama engagement, persetujuan tertulis/reference.
- IP target dan CIDR yang benar-benar diizinkan.
- Batas waktu, metode yang boleh, pengecualian, dan syarat pembatasan lainnya.

**Pengguna sendiri yang mengisi dan mengedit scope**, bukan agent yang menciptakan IP atau memperluas target. Setelah task dibuat, berikan hanya ID task/engagement ke OpenCode. Ini menghindari target IP mentah masuk ke prompt provider model eksternal. SECRA memegang real target secara lokal dan memverifikasi scope sebelum operasi tool. Jika scope belum diisi, agent hanya boleh melakukan perencanaan.

## 7. Jalankan dari folder mana pun

~~~bash
cd /tmp
opencode --agent secra-vapt

# atau
cd "$HOME"
opencode --agent secra-ctf
~~~

VAPT:
- OpenCode V2 permission default **deny everything**, lalu secara eksplisit mengizinkan read/search/skill dan subagent analisis.
- Tool MCP `secra_*` memerlukan approval; direct shell tidak diizinkan.
- Subagent analisis tidak mempunyai kemampuan eksekusi independen.

CTF:
- Shell lokal *ask* per permintaan dan hanya untuk challenge resmi/lab yang diizinkan.
- CTF spesialis membantu menganalisis artefak, coordinator yang memegang eksekusi.
- Izin ini tidak boleh dipindahkan ke VAPT customer.

**Learning**: agent boleh mengusulkan lesson ke `~/.local/share/secra-learning/inbox/`. Hanya lesson yang telah direview operator yang boleh masuk `reviewed/`. Tidak ada fine-tuning otomatis ataupun self-improvement model weights.

## 8. Tests dan batas keberhasilan

~~~bash
SECRA_REPO="$HOME/.local/share/secra/repo"
"$SECRA_REPO/.venv/bin/python" -m pip install -r "$SECRA_REPO/requirements-dev.txt"

(cd "$SECRA_REPO" && .venv/bin/python -m pytest tests/opencode -q)
(cd "$SECRA_REPO" && .venv/bin/python -m pytest -m "not lab" -q)
~~~

Berhasilnya instalasi global bukan bukti bahwa semua tool Kali telah terpasang atau semua skill dapat otomatis dieksekusi. Knowledge memandu model; eksekusi memerlukan tool yang tersedia, adapter yang cocok, izin operator, dan bukti lulus pengujian. Skill yang tidak mempunyai adapter wajib menghasilkan *missing capability*—jangan menciptakan hasil palsu atau mengganti dengan shell tidak terkontrol.

**Jangan mengubah graph-core, frontier resolver, schema node/edge, masking gateway atau egress enforcement** hanya untuk mengatasi skill yang belum bisa menjalankan tool.
