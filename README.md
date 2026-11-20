# patraredirect-backend

Backend Google Apps Script untuk Patra Redirect. `Kode.js` di repo ini = `Kode.gs` di editor Apps Script.
Frontend: [kntgbkrs/patraredirect](https://github.com/kntgbkrs/patraredirect).

## Deploy otomatis
Setiap merge ke `main`, GitHub Actions (`.github/workflows/deploy-apps-script.yml`) mengirim kode ke Apps Script
dan memperbarui deployment web app. Alamat `/exec` tidak berubah.
**Jangan mengedit kode di editor Apps Script** — isinya akan tertimpa pada deploy berikutnya. Ubah lewat pull request.

### Setup (sekali saja)
1. Buka https://script.google.com/home/usersettings → nyalakan **Google Apps Script API**.
2. Di Mac (butuh Node.js dari https://nodejs.org), buka Terminal:
   ```bash
   npx @google/clasp@3.4.1 login
   ```
   Browser terbuka → pilih akun Google pemilik proyek → **Izinkan**.
3. Salin isi kunci akses:
   ```bash
   cat ~/.clasprc.json | pbcopy
   ```
4. GitHub repo ini → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**
   → Name: `CLASPRC_JSON` → Secret: tempel (Cmd+V) → **Add secret**.
5. Uji: tab **Actions** → **Deploy ke Apps Script** → **Run workflow**. Harus centang hijau.

Kalau suatu saat gagal dengan pesan login/`invalid_grant`, ulangi langkah 2–4 (kunci akses kadaluarsa atau dicabut).
