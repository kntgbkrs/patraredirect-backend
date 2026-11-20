# Patra Redirect — aturan kerja

Sistem ini terdiri dari dua repo:
- **Frontend** — `kntgbkrs/patraredirect` (HTML/CSS/JS statis). Merge ke `main` → Vercel menayangkan otomatis.
- **Backend** — `kntgbkrs/patraredirect-backend` (`Kode.js` = `Kode.gs` di Google Apps Script). Merge ke `main` → GitHub Actions mengirim kode ke Apps Script dan memperbarui deployment (alamat `/exec` tetap).

## Aturan
1. **Jangan ubah apa pun sebelum pemilik setuju.** Jelaskan dulu usulannya (apa, kenapa, file mana, risikonya) lalu tunggu persetujuan.
2. Setelah disetujui: kerjakan di branch, lalu buat **pull request ke `main`** di repo yang terkena — frontend, backend, atau keduanya. Jangan push langsung ke `main` dan jangan merge sendiri.
3. Perubahan yang menyentuh dua repo: buat PR di keduanya, saling tautkan, dan tulis urutan merge-nya (mis. frontend dulu bila backend mulai mewajibkan data baru dari frontend).
4. Jelaskan dalam bahasa Indonesia sederhana. Langkah yang harus dikerjakan pemilik ditulis langkah demi langkah.
5. Kedua repo **publik**: jangan pernah menulis kunci, API key, atau password di kode. Rahasia backend disimpan di Properti skrip Apps Script; frontend hanya boleh menyimpan hash.
6. Jangan menyuruh pemilik mengedit kode di editor Apps Script — deploy otomatis akan menimpanya. Perubahan backend selalu lewat PR.

## Catatan teknis
- `STAFF_GATE_HASH` (frontend `js/config.js`) = SHA-256 dari Properti skrip `STAFF_GATE_KEY` (backend). Ganti keduanya bersamaan.
- `GAS_URL` (frontend) memuat Deployment ID yang juga tertulis di workflow backend (`.github/workflows/deploy-apps-script.yml`). Bila deployment baru dibuat, perbarui keduanya.
- Frontend: naikkan `?v=` di `index.html` setiap kali file JS/CSS berubah.
