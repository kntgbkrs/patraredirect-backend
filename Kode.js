/**
 * ============================================================
 * REDIRECT NFC — Backend (Kode.gs)
 * Versi 1.0 · Google Apps Script + Google Sheets
 * ------------------------------------------------------------
 * ATURAN KEAMANAN PENTING
 * Semua fungsi global di proyek ini BISA dipanggil dari browser lewat
 * google.script.run, KECUALI yang namanya berakhiran garis bawah (_).
 * Karena itu:
 *  - semua helper internal memakai akhiran "_"
 *  - fungsi setup/maintenance dijaga assertOwner_()
 *  - fungsi API publik hanya yang ada di bagian "API" di bawah
 * ============================================================
 */

// ── Konstanta Global ──
const APP_NAME = 'Patra Redirect';
const FOLDER_NAME = 'Folder_RedirectNFC';
const SS_NAME = 'DB_RedirectNFC';

const SHEET = { KARTU: 'Kartu', LOG: 'Log_Scan', USER: 'Pengguna', AKT: 'Log_Aktivitas', CFG: 'AppConfig' };
const H_KARTU = ['nomor_kartu', 'status', 'tipe_tujuan', 'nama_lokasi', 'place_id', 'url_tujuan', 'whatsapp',
  'pin_hash', 'tanggal_registrasi', 'jumlah_scan', 'scan_terakhir', 'dibuat_pada', 'batch'];
const H_USER = ['username', 'nama', 'password_hash', 'role', 'aktif', 'terakhir_login'];
const H_LOG = ['waktu', 'nomor_kartu', 'status_hasil'];
const H_AKT = ['waktu', 'pelaku', 'aksi', 'nomor_kartu', 'detail'];

const CODE_RE = /^[A-Z0-9]{6,12}$/;
const SAFE_ALPHA = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';      // tanpa I, L, O, 0, 1
const ALL_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const SESSION_TTL = 3600;          // sesi staf: 60 menit tidak aktif
const SESSION_MAX_MS = 21600000;   // batas mutlak sesi: 6 jam
const CARD_TTL = 1800;             // cache data kartu publik: 30 menit
const HASH_ROUNDS = 150;
const PIN_MAX_FAIL = 5;
const LOCK_SEC = 900;              // kunci sementara 15 menit
const PIN_MAX_FAIL_LONG = 10;      // batas salah PIN per kartu dalam 6 jam
const LOCK_LONG_SEC = 21600;       // 6 jam (batas maksimal CacheService)
const SCAN_GAP_SEC = 10;           // satu kartu dihitung maksimal 1 scan per 10 detik
const DAY_MS = 86400000;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];
const DAYS_S = ['Min', 'Sen', 'Sel', 'Rab', 'Kam', 'Jum', 'Sab'];
const DAYS_L = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];

// ════════════════════════════════════════════════════════
// BAGIAN 1: ENTRY POINT (SPA — satu halaman, URL tidak berubah)
// ════════════════════════════════════════════════════════

/** Helper template HTML */
function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

/**
 * Entry point TUNGGAL. Satu-satunya parameter URL yang dibaca adalah
 * ?id=KODE_KARTU (identitas kartu NFC, wajib agar kartu bisa dikenali)
 * dan ?aksi=kelola. Tidak ada routing halaman dan tidak ada token di URL.
 * Status kartu langsung di-resolve di sini (dari cache) supaya browser
 * tidak perlu satu kali perjalanan server lagi sebelum redirect.
 */
function doGet(e) {
  const p = (e && e.parameter) || {};
  const action = p.action || '';

  // REST API: GET action=card
  if (action === 'card') {
    return jsonOut_(run_(function () {
      const code = normCode_(p.id);
      if (!code) throw uerr_('Kode kartu tidak valid.');
      const card = getCardPublic_(code);
      if (!card) throw uerr_('Kartu tidak ditemukan.');
      if (p.log === '1' || p.log === 1) queueScan_(code, card.status === 'terhubung');
      return { card: card, waAdmin: publicCfg_().wa };
    }));
  }

  // REST API: GET action=config
  if (action === 'config') {
    return jsonOut_(run_(function () {
      return { app: APP_NAME, wa: publicCfg_().wa, baseUrl: getBaseUrl_() };
    }));
  }

  // REST API: Healthcheck / root test
  if (action === 'ping' || !p.id) {
    if (p.format !== 'html') {
      return jsonOut_({ success: true, data: { app: APP_NAME, time: Date.now() }, message: 'OK' });
    }
  }

  const code = normCode_(p.id);
  const init = { code: null, aksi: '', card: null, waAdmin: '', appName: APP_NAME, error: '' };
  try {
    init.waAdmin = publicCfg_().wa;
    if (code) {
      init.code = code;
      init.aksi = p.aksi === 'kelola' ? 'kelola' : '';
      init.card = getCardPublic_(code);
      if (init.card && !init.aksi) queueScan_(code, init.card.status === 'terhubung');
    }
  } catch (err) {
    logErr_(err);
    init.error = 'Terjadi gangguan sementara. Silakan coba pindai ulang.';
  }
  const t = HtmlService.createTemplateFromFile('Index');
  t.initJson = JSON.stringify(init).replace(/</g, '\u003c').replace(/\u2028/g, '\u2028').replace(/\u2029/g, '\u2029');
  return t.evaluate()
    .setTitle(APP_NAME)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1, viewport-fit=cover')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

function doPost(e) {
  let body = {};
  try {
    const raw = (e && e.postData && e.postData.contents) || '{}';
    body = JSON.parse(raw);
    if (body.action === 'login' && !staffGateOk_(body.gate)) {
      return ContentService.createTextOutput(JSON.stringify({ success: false, code: 'AUTH', message: 'Username atau kata sandi salah.' }))
        .setMimeType(ContentService.MimeType.JSON);
    }
  } catch (err) {
    return jsonOut_({ success: false, code: 'BAD_JSON', message: 'Format request JSON tidak valid.' });
  }

  const act = body.action || '';
  let res;

  switch (act) {
    case 'searchPlaces':
      res = searchPlaces(body.ctx, body.query);
      break;
    case 'register':
      res = registerCard(body.code, body.payload);
      break;
    case 'verifyPin':
      res = verifyPin(body.code, body.pin);
      break;
    case 'ownerUpdate':
      res = updateCardOwner(body.cardToken, body.patch);
      break;
    case 'ownerReset':
      res = resetCardOwner(body.cardToken);
      break;
    case 'login':
      res = doLogin(body.username, body.password);
      break;
    case 'logout':
      res = doLogout(body.token);
      break;
    case 'bootstrap':
      res = staffBootstrap(body.token);
      break;
    case 'staffUpdate':
      res = updateCardStaff(body.token, body.code, body.patch);
      break;
    case 'staffReset':
      res = resetCardStaff(body.token, body.code);
      break;
    case 'staffDelete':
      res = deleteCardStaff(body.token, body.code);
      break;
    case 'generate':
      res = generateCodes(body.token, body.jumlah, body.panjang, body.aman, body.label);
      break;
    case 'scanReport':
      res = getScanReport(body.token, body.params);
      break;
    case 'exportPdf':
      res = exportCardReportPdf(body.token, body.codes, body.meta);
      break;
    case 'exportQrPdf':
      res = exportCardQrPdf(body.token, body.code);
      break;
    case 'saveSettings':
      res = saveSettings(body.token, body.settings);
      break;
    case 'createUser':
      res = createUser(body.token, body.user);
      break;
    case 'setUserActive':
      res = setUserActive(body.token, body.username, body.aktif);
      break;
    case 'resetUserPassword':
      res = resetUserPassword(body.token, body.username, body.password);
      break;
    case 'changePassword':
      res = changeOwnPassword(body.token, body.oldPw, body.newPw);
      break;
    default:
      res = { success: false, code: 'UNKNOWN_ACTION', message: 'Aksi API tidak dikenal: ' + act };
  }

  return jsonOut_(res);
}

function jsonOut_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

// ════════════════════════════════════════════════════════
// BAGIAN 2: UTILITAS INTERNAL
// ════════════════════════════════════════════════════════

function uerr_(msg, code) {
  const e = new Error(msg);
  e.userFacing = true;
  e.code = code || 'ERR';
  return e;
}

/** Pembungkus standar: { success, data, message, code } — semua API publik lewat sini */
function run_(fn) {
  try {
    const d = fn();
    return { success: true, data: d === undefined ? null : d, message: 'OK' };
  } catch (err) {
    const m = String((err && err.message) || err);
    if (m === 'AUTH') return { success: false, data: null, code: 'AUTH', message: 'Sesi berakhir. Silakan masuk kembali.' };
    if (m === 'FORBIDDEN') return { success: false, data: null, code: 'FORBIDDEN', message: 'Akses ditolak.' };
    if (err && err.userFacing) return { success: false, data: null, code: err.code || 'ERR', message: m };
    logErr_(err);
    return { success: false, data: null, code: 'ERR', message: 'Terjadi gangguan pada server. Coba lagi sebentar.' };
  }
}

function logErr_(err) {
  try { console.error(String(err && err.stack || err)); } catch (e) { /* abaikan */ }
}

function props_() { return PropertiesService.getScriptProperties(); }
function getProp_(k) { return props_().getProperty(k); }
function tz_() { return Session.getScriptTimeZone(); }

let _ss = null;
function getSS_() {
  if (_ss) return _ss;
  const id = getProp_('spreadsheetId');
  if (!id) throw new Error('Aplikasi belum di-setup. Jalankan setupAppEnvironment().');
  _ss = SpreadsheetApp.openById(id);
  return _ss;
}

function withLock_(fn, waitMs) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(waitMs || 10000)) throw uerr_('Sistem sedang sibuk. Coba lagi sebentar.');
  try { return fn(); } finally { lock.releaseLock(); }
}

function assertOwner_() {
  const eff = Session.getEffectiveUser().getEmail();
  const act = Session.getActiveUser().getEmail();
  if (!eff || eff !== act) throw new Error('FORBIDDEN');
}

function ts_(v) { return v instanceof Date ? v.getTime() : (v ? (Number(v) || 0) : 0); }
function isTrue_(v) { return v === true || String(v).toUpperCase() === 'TRUE'; }

// ── Validasi ──
function normCode_(v) {
  const c = String(v || '').trim().toUpperCase();
  return CODE_RE.test(c) ? c : '';
}
function needCode_(v) {
  const c = normCode_(v);
  if (!c) throw uerr_('Kode kartu tidak valid.');
  return c;
}
function normWa_(v) {
  let d = String(v || '').replace(/\D/g, '');
  if (d.indexOf('0') === 0) d = '62' + d.slice(1);
  else if (d.indexOf('8') === 0) d = '62' + d;
  if (!/^62\d{8,13}$/.test(d)) throw uerr_('Nomor WhatsApp tidak valid. Contoh: 812-3456-7890');
  return d;
}
function validPin_(v) {
  const p = String(v || '');
  if (!/^\d{4,6}$/.test(p)) throw uerr_('PIN harus 4-6 digit angka.');
  return p;
}
function validUrl_(v) {
  const u = String(v || '').trim();
  if (u.length > 1800 || !/^https?:\/\/[^\s]+$/i.test(u)) throw uerr_('URL harus diawali http:// atau https://');
  const m = u.match(/^https?:\/\/([^\/?#:@]+)/i);
  if (!m || m[1].indexOf('.') < 0) throw uerr_('Alamat URL tidak valid.');
  return u;
}
function hostOf_(u) {
  const m = String(u).match(/^https?:\/\/([^\/?#:]+)/i);
  return m ? m[1].replace(/^www\./i, '') : 'Link Lain';
}

/** Normalisasi tujuan redirect (Google Review atau link lain) */
function normalizeDest_(p) {
  p = p || {};
  if (p.tipe === 'google_review') {
    const pl = p.place || {};
    const id = String(pl.id || '');
    const nama = String(pl.name || '').trim().slice(0, 150);
    if (!/^[A-Za-z0-9_-]{10,300}$/.test(id) || !nama) throw uerr_('Pilih lokasi dari hasil pencarian Google.');
    return { tipe: 'google_review', nama: nama, placeId: id, url: 'https://search.google.com/local/writereview?placeid=' + encodeURIComponent(id) };
  }
  if (p.tipe === 'link_lain') {
    const url = validUrl_(p.url);
    return { tipe: 'link_lain', nama: hostOf_(url), placeId: '', url: url };
  }
  throw uerr_('Tipe tujuan tidak dikenal.');
}

// ── Hash (garam + iterasi) ──
function hexOf_(bytes) {
  return bytes.map(function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join('');
}
function hashSecret_(secret, salt) {
  const saltBytes = Utilities.newBlob(salt).getBytes();
  let d = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + ':' + secret);
  for (let i = 0; i < HASH_ROUNDS; i++) {
    d = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, d.concat(saltBytes));
  }
  return hexOf_(d);
}
function makeSecret_(secret) {
  const salt = Utilities.getUuid().replace(/-/g, '').slice(0, 14);
  return salt + '$' + hashSecret_(secret, salt);
}
function verifySecret_(secret, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 2) { hashSecret_(secret, 'x'); return false; }
  return hashSecret_(secret, parts[0]) === parts[1];
}

/** Karakter acak dari entropi UUID (bebas bias modulo) */
function randChars_(n, alpha) {
  const len = alpha.length;
  const lim = Math.floor(256 / len) * len;
  let out = '';
  while (out.length < n) {
    const u = Utilities.getUuid().replace(/-/g, '');
    for (let i = 0; i + 1 < u.length && out.length < n; i += 2) {
      if (i === 12 || i === 16) continue;           // byte dengan bit tetap (versi/varian UUID)
      const b = parseInt(u.substr(i, 2), 16);
      if (b < lim) out += alpha.charAt(b % len);
    }
  }
  return out;
}

// ── Sheet & data kartu ──
function rowToCard_(r) {
  const o = {};
  H_KARTU.forEach(function (h, i) { o[h] = r[i]; });
  return o;
}
function staffCard_(o) {
  return {
    code: String(o.nomor_kartu), status: String(o.status || 'belum_setup'), tipe: o.tipe_tujuan || '',
    nama: o.nama_lokasi || '', placeId: o.place_id || '', url: o.url_tujuan || '', wa: String(o.whatsapp || ''),
    regTs: ts_(o.tanggal_registrasi), scans: Number(o.jumlah_scan) || 0, lastTs: ts_(o.scan_terakhir),
    createdTs: ts_(o.dibuat_pada), batch: o.batch || ''
  };
}
function ownerCard_(o) {
  return { code: String(o.nomor_kartu), status: String(o.status), tipe: o.tipe_tujuan || '', nama: o.nama_lokasi || '',
    placeId: o.place_id || '', url: o.url_tujuan || '', scans: Number(o.jumlah_scan) || 0 };
}
function readAllCards_(ss) {
  const sh = ss.getSheetByName(SHEET.KARTU);
  const last = sh.getLastRow();
  if (last < 2) return [];
  return sh.getRange(2, 1, last - 1, H_KARTU.length).getValues().map(rowToCard_);
}
function findCardRow_(sh, code) {
  const rng = sh.getRange(2, 1, Math.max(sh.getLastRow() - 1, 1), 1);
  const f = rng.createTextFinder(code).matchEntireCell(true).matchCase(true).findNext();
  return f ? f.getRow() : 0;
}
function cardRowOrNull_(code) {
  const sh = getSS_().getSheetByName(SHEET.KARTU);
  const row = findCardRow_(sh, code);
  if (!row) return null;
  return { sh: sh, row: row, o: rowToCard_(sh.getRange(row, 1, 1, H_KARTU.length).getValues()[0]) };
}
function cardRow_(code) {
  const c = cardRowOrNull_(code);
  if (!c) throw uerr_('Kartu tidak ditemukan.');
  return c;
}

/** Data kartu untuk publik (tanpa PIN/WhatsApp), cache-first */
function getCardPublic_(code) {
  const cache = CacheService.getScriptCache();
  const hit = cache.get('card:' + code);
  if (hit) return JSON.parse(hit);
  const c = cardRowOrNull_(code);
  if (!c) return null;
  const o = c.o;
  const pub = { code: code, status: String(o.status || 'belum_setup'), tipe: o.tipe_tujuan || '', nama: o.nama_lokasi || '',
    url: o.status === 'terhubung' ? (o.url_tujuan || '') : '' };
  cache.put('card:' + code, JSON.stringify(pub), CARD_TTL);
  return pub;
}
function invalidateCard_(code) { CacheService.getScriptCache().remove('card:' + code); }
function invalidateStats_() { CacheService.getScriptCache().put('sver', String(Date.now()), 21600); }
function statsVer_() { return CacheService.getScriptCache().get('sver') || '0'; }

function publicCfg_() {
  const cache = CacheService.getScriptCache();
  const c = cache.get('pubcfg');
  if (c) return JSON.parse(c);
  const cfg = { wa: getProp_('waAdmin') || '' };
  cache.put('pubcfg', JSON.stringify(cfg), 21600);
  return cfg;
}
function getBaseUrl_() {
  return getProp_('baseUrl') || ScriptApp.getService().getUrl();
}

function log_(actor, aksi, code, detail) {
  try {
    const sh = getSS_().getSheetByName(SHEET.AKT);
    sh.appendRow([new Date(), actor, aksi, code || '', String(detail || '').slice(0, 400)]);
  } catch (e) { logErr_(e); }
}

// ════════════════════════════════════════════════════════
// BAGIAN 3: ANTRIAN SCAN (cepat, tanpa menulis Sheets saat redirect)
// ════════════════════════════════════════════════════════

/** Catat scan ke antrian cache (milidetik). Ditulis ke Sheets secara batch oleh flushScanQueue(). */
function queueScan_(code, ok) {
  const evt = [Date.now(), code, ok ? 1 : 0];
  const cache = CacheService.getScriptCache();
  const sk = 'sl:' + code;                          // penanda "baru dihitung": cegah penggelembungan jumlah scan
  try {
    const lock = LockService.getScriptLock();
    if (lock.tryLock(1500)) {
      try {
        if (cache.get(sk)) return;
        const raw = cache.get('scanq');
        const q = raw ? JSON.parse(raw) : [];
        q.push(evt);
        cache.put('scanq', JSON.stringify(q), 21600);
        cache.put(sk, '1', SCAN_GAP_SEC);
      } finally { lock.releaseLock(); }
      return;
    }
  } catch (e) { logErr_(e); }
  // Cadangan bila lock penuh: tulis langsung ke log (hitungan kartu menyusul dari laporan)
  // shortcut: cek di jalur ini tanpa lock, scan yang benar-benar bersamaan bisa lolos beberapa; cukup agar sheet tidak membengkak.
  if (cache.get(sk)) return;
  cache.put(sk, '1', SCAN_GAP_SEC);
  try {
    getSS_().getSheetByName(SHEET.LOG).appendRow([new Date(evt[0]), code, ok ? 'berhasil' : 'ditolak']);
  } catch (e) { logErr_(e); }
}

/** Pindahkan antrian scan ke Sheets (1x tulis log + 1x tulis penghitung). Dipanggil trigger tiap 5 menit & saat staf membuka dashboard. */
function flushScanQueue() {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(8000)) return;
  try {
    const cache = CacheService.getScriptCache();
    const raw = cache.get('scanq');
    if (!raw) return;
    const q = JSON.parse(raw);
    if (!q.length) { cache.remove('scanq'); return; }
    const ss = getSS_();
    const logSh = ss.getSheetByName(SHEET.LOG);
    logSh.getRange(logSh.getLastRow() + 1, 1, q.length, 3)
      .setValues(q.map(function (r) { return [new Date(r[0]), r[1], r[2] ? 'berhasil' : 'ditolak']; }));

    const agg = {};
    q.forEach(function (r) {
      if (!r[2]) return;
      const a = agg[r[1]] || (agg[r[1]] = { n: 0, t: 0 });
      a.n++; a.t = Math.max(a.t, r[0]);
    });
    const kSh = ss.getSheetByName(SHEET.KARTU);
    const last = kSh.getLastRow();
    if (last >= 2 && Object.keys(agg).length) {
      const codes = kSh.getRange(2, 1, last - 1, 1).getValues();
      const cIdx = H_KARTU.indexOf('jumlah_scan') + 1;
      const cnt = kSh.getRange(2, cIdx, last - 1, 2).getValues();
      codes.forEach(function (c, i) {
        const a = agg[String(c[0])];
        if (a) { cnt[i][0] = (Number(cnt[i][0]) || 0) + a.n; cnt[i][1] = new Date(a.t); }
      });
      kSh.getRange(2, cIdx, last - 1, 2).setValues(cnt);
    }
    cache.remove('scanq');
    invalidateStats_();
  } catch (err) {
    logErr_(err);
  } finally {
    lock.releaseLock();
  }
}

// ════════════════════════════════════════════════════════
// BAGIAN 4: SETUP OTOMATIS (jalankan manual dari editor, sekali saja)
// ════════════════════════════════════════════════════════

function setupAppEnvironment() {
  assertOwner_();
  const folders = DriveApp.getFoldersByName(FOLDER_NAME);
  const folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(FOLDER_NAME);
  let ss;
  const files = folder.getFilesByName(SS_NAME);
  if (files.hasNext()) {
    ss = SpreadsheetApp.open(files.next());
  } else {
    ss = SpreadsheetApp.create(SS_NAME);
    DriveApp.getFileById(ss.getId()).moveTo(folder);
  }
  props_().setProperty('spreadsheetId', ss.getId());
  _ss = ss;

  const kartu = ensureSheet_(ss, SHEET.KARTU, H_KARTU);
  const user = ensureSheet_(ss, SHEET.USER, H_USER);
  ensureSheet_(ss, SHEET.LOG, H_LOG);
  ensureSheet_(ss, SHEET.AKT, H_AKT);
  const cfg = ensureSheet_(ss, SHEET.CFG, ['Key', 'Value']);

  // Format teks agar kode/nomor tidak diubah Sheets (mis. angka depan 0, rumus)
  fmtText_(kartu.sheet, 2, kartu.sheet.getMaxRows() - 1);
  [1, 2].forEach(function (c) { user.sheet.getRange(2, c, Math.max(user.sheet.getMaxRows() - 1, 1), 1).setNumberFormat('@'); });

  let masterPassword = null;
  if (user.created) {
    masterPassword = genPassword_();
    user.sheet.appendRow(['master', 'Master', makeSecret_(masterPassword), 'master', true, '']);
  }
  if (kartu.created) seedDemo_(kartu.sheet);
  if (cfg.created) {
    cfg.sheet.getRange(2, 1, 3, 2).setValues([['appName', APP_NAME], ['folderId', folder.getId()], ['dibuat', new Date().toISOString()]]);
  }
  const def = ss.getSheetByName('Sheet1');
  if (def && ss.getSheets().length > 1) ss.deleteSheet(def);

  installTriggers_();

  Logger.log('📁 Folder: ' + folder.getUrl());
  Logger.log('📊 Spreadsheet: ' + ss.getUrl());
  if (masterPassword) {
    Logger.log('🔑 AKUN MASTER → username: master | password: ' + masterPassword + '  (SIMPAN, hanya tampil sekali. Ganti di menu profil setelah login.)');
  } else {
    Logger.log('ℹ️ Akun master sudah ada. Lupa password? jalankan resetMasterPassword().');
  }
  Logger.log('✅ Setup selesai. Lanjut: Deploy → Web App, lalu login sebagai master → Pengaturan (API key & WhatsApp admin).');
  return { spreadsheetUrl: ss.getUrl(), masterPassword: masterPassword };
}

function ensureSheet_(ss, name, headers) {
  let sh = ss.getSheetByName(name);
  let created = false;
  if (!sh) {
    sh = ss.insertSheet(name);
    created = true;
    sh.getRange(1, 1, 1, headers.length).setValues([headers])
      .setFontWeight('bold').setBackground('#14532D').setFontColor('#ffffff');
    sh.setFrozenRows(1);
    for (let i = 1; i <= headers.length; i++) sh.setColumnWidth(i, i === 1 ? 130 : 150);
  }
  return { sheet: sh, created: created };
}

/** Paksa kolom teks (kode, nama, URL, WhatsApp, hash, batch) agar tidak diubah/dianggap rumus oleh Sheets */
function fmtText_(sh, row, n) {
  if (n < 1) return;
  [1, 4, 5, 6, 7, 8, 13].forEach(function (c) { sh.getRange(row, c, n, 1).setNumberFormat('@'); });
}

function seedDemo_(sh) {
  const now = new Date();
  const mk = function (code, status, tipe, nama, pid, url, wa, scans, daysAgo) {
    const r = new Array(H_KARTU.length).fill('');
    r[0] = code; r[1] = status; r[2] = tipe; r[3] = nama; r[4] = pid; r[5] = url; r[6] = wa;
    r[7] = wa ? makeSecret_('1234') : '';
    r[8] = wa ? new Date(now.getTime() - daysAgo * DAY_MS) : '';
    r[9] = scans; r[11] = new Date(now.getTime() - 5 * DAY_MS); r[12] = 'DEMO';
    return r;
  };
  const rows = [
    mk('DEMO0001', 'terhubung', 'google_review', 'Kopi Contoh (Demo)', 'ChIJDEMO00000001',
      'https://search.google.com/local/writereview?placeid=ChIJDEMO00000001', '6281200000001', 0, 2),
    mk('DEMO0002', 'terhubung', 'link_lain', 'example.com', '', 'https://example.com/menu', '6281200000002', 0, 1),
    mk('DEMO0003', 'belum_setup', '', '', '', '', '', 0, 0),
    mk('DEMO0004', 'nonaktif', 'link_lain', 'example.org', '', 'https://example.org', '6281200000004', 0, 3)
  ];
  sh.getRange(2, 1, rows.length, H_KARTU.length).setValues(rows);
}

function genPassword_() {
  return randChars_(4, 'abcdefghjkmnpqrstuvwxyz') + randChars_(4, 'ABCDEFGHJKMNPQRSTUVWXYZ') + randChars_(4, '23456789');
}

function installTriggers_() {
  try {
    ScriptApp.getProjectTriggers().forEach(function (t) {
      if (t.getHandlerFunction() === 'flushScanQueue') ScriptApp.deleteTrigger(t);
    });
    ScriptApp.newTrigger('flushScanQueue').timeBased().everyMinutes(5).create();
  } catch (e) {
    Logger.log('⚠️ Trigger gagal dipasang: ' + e.message);
  }
}

/** Hapus kartu contoh (batch DEMO) */
function hapusDataDemo() {
  assertOwner_();
  const sh = getSS_().getSheetByName(SHEET.KARTU);
  const last = sh.getLastRow();
  if (last < 2) return;
  const bIdx = H_KARTU.indexOf('batch');
  const vals = sh.getRange(2, 1, last - 1, H_KARTU.length).getValues();
  for (let i = vals.length - 1; i >= 0; i--) {
    if (String(vals[i][bIdx]) === 'DEMO') { invalidateCard_(String(vals[i][0])); sh.deleteRow(i + 2); }
  }
  invalidateStats_();
  Logger.log('🗑️ Data demo dihapus.');
}

/** Darurat: buat ulang password akun master (jalankan dari editor) */
function resetMasterPassword() {
  assertOwner_();
  const sh = getSS_().getSheetByName(SHEET.USER);
  const data = sh.getDataRange().getValues();
  const pw = genPassword_();
  const idx = data.findIndex(function (r, i) { return i > 0 && String(r[0]).toLowerCase() === 'master'; });
  if (idx < 0) sh.appendRow(['master', 'Master', makeSecret_(pw), 'master', true, '']);
  else sh.getRange(idx + 1, 3, 1, 3).setValues([[makeSecret_(pw), 'master', true]]);
  CacheService.getScriptCache().put('ue:master', String(Date.now()), 21600);
  Logger.log('🔑 Password master baru: ' + pw);
}

// ════════════════════════════════════════════════════════
// BAGIAN 5: SESI STAF
// ════════════════════════════════════════════════════════

function authStaff_(token, roles) {
  if (!token) throw new Error('AUTH');
  const cache = CacheService.getScriptCache();
  const raw = cache.get('ss:' + token);
  if (!raw) throw new Error('AUTH');
  const s = JSON.parse(raw);
  const ue = Number(cache.get('ue:' + s.u) || 0);
  if (Date.now() - s.e > SESSION_MAX_MS || s.e < ue) { cache.remove('ss:' + token); throw new Error('AUTH'); }
  if (roles && roles.indexOf(s.r) < 0) throw new Error('FORBIDDEN');
  cache.put('ss:' + token, raw, SESSION_TTL);   // sliding
  return s;
}

function readUsers_() {
  const sh = getSS_().getSheetByName(SHEET.USER);
  const data = sh.getDataRange().getValues();
  return { sh: sh, rows: data.slice(1) };
}

// ════════════════════════════════════════════════════════
// BAGIAN 6: API PUBLIK — KONSUMEN
// ════════════════════════════════════════════════════════

/** Registrasi kartu oleh konsumen (kartu harus berstatus belum_setup) */
function registerCard(code, payload) {
  return run_(function () {
    code = needCode_(code);
    payload = payload || {};
    const wa = normWa_(payload.whatsapp);
    const pin = validPin_(payload.pin);
    const dest = normalizeDest_(payload);
    const pinHash = makeSecret_(pin);
    return withLock_(function () {
      const c = cardRow_(code);
      if (c.o.status !== 'belum_setup') throw uerr_('Kartu ini sudah terdaftar atau sedang tidak tersedia.');
      const now = new Date();
      c.sh.getRange(c.row, 2, 1, 8).setValues([['terhubung', dest.tipe, dest.nama, dest.placeId, dest.url, wa, pinHash, now]]);
      invalidateCard_(code);
      invalidateStats_();
      log_('konsumen', 'registrasi', code, dest.tipe + ' · ' + dest.nama);
      return { code: code, tipe: dest.tipe, nama: dest.nama, url: dest.url, whatsapp: wa, regTs: now.getTime(),
        manageLink: getBaseUrl_() + '?id=' + code + '&aksi=kelola' };
    });
  });
}

/** Verifikasi PIN → token kartu berumur 15 menit untuk mengelola kartu */
function verifyPin(code, pin) {
  return run_(function () {
    code = normCode_(code);
    if (!code) throw uerr_('Kode kartu tidak valid.');
    const cache = CacheService.getScriptCache();
    const fk = 'pf:' + code, dk = 'pd:' + code;
    pin = String(pin || '');
    const c = /^\d{4,6}$/.test(pin) ? cardRowOrNull_(code) : null;
    if (c && c.o.status === 'belum_setup') throw uerr_('Kartu ini belum diregistrasi.', 'UNREG');
    if (c && c.o.status === 'nonaktif') throw uerr_('Kartu ini sedang nonaktif. Hubungi admin.', 'INACTIVE');
    // Jatah percobaan diambil di dalam lock SEBELUM PIN diperiksa, jadi tebakan serentak tidak bisa melewati batas.
    // shortcut: penghitung di CacheService (maks. 6 jam, bisa terhapus lebih awal); pindah ke Sheet bila perlu kunci permanen.
    const f = withLock_(function () {
      const n = Number(cache.get(fk) || 0), d = Number(cache.get(dk) || 0);
      if (n < PIN_MAX_FAIL && d < PIN_MAX_FAIL_LONG) {
        cache.put(fk, String(n + 1), LOCK_SEC);
        cache.put(dk, String(d + 1), LOCK_LONG_SEC);
      }
      return { n: n, d: d };
    });
    if (f.d >= PIN_MAX_FAIL_LONG) throw uerr_('Terlalu banyak percobaan. Coba lagi dalam 6 jam.', 'LOCKED');
    if (f.n >= PIN_MAX_FAIL) throw uerr_('Terlalu banyak percobaan. Coba lagi dalam 15 menit.', 'LOCKED');
    const ok = !!(c && verifySecret_(pin, c.o.pin_hash));
    if (!ok) {
      if (!c) hashSecret_(pin, 'x');                    // samakan waktu respons
      const leftShort = PIN_MAX_FAIL - (f.n + 1), leftLong = PIN_MAX_FAIL_LONG - (f.d + 1);
      const left = Math.min(leftShort, leftLong);
      if (left <= 0) throw uerr_('Terlalu banyak percobaan. Coba lagi dalam ' + (leftLong <= 0 ? '6 jam.' : '15 menit.'), 'LOCKED');
      throw uerr_('PIN salah. Sisa ' + left + ' percobaan.', 'BADPIN');
    }
    cache.removeAll([fk, dk]);
    const token = Utilities.getUuid();
    cache.put('ct:' + token, JSON.stringify({ code: code }), 900);
    return { token: token, card: ownerCard_(c.o) };
  });
}

function ownerCode_(token) {
  if (!token) throw new Error('AUTH');
  const cache = CacheService.getScriptCache();
  const raw = cache.get('ct:' + token);
  if (!raw) throw new Error('AUTH');
  cache.put('ct:' + token, raw, 900);
  return JSON.parse(raw).code;
}

/** Ubah tujuan kartu oleh pemilik */
function updateCardOwner(cardToken, patch) {
  return run_(function () {
    const code = ownerCode_(cardToken);
    return ownerCard_(applyCardUpdate_(code, patch, 'pemilik', false));
  });
}

/** Reset kartu oleh pemilik */
function resetCardOwner(cardToken) {
  return run_(function () {
    const code = ownerCode_(cardToken);
    resetCard_(code, 'pemilik');
    CacheService.getScriptCache().remove('ct:' + cardToken);
    return { code: code, scans: 0, lastTs: 0 };
  });
}

function applyCardUpdate_(code, patch, actor, allowStatus) {
  patch = patch || {};
  return withLock_(function () {
    const c = cardRow_(code);
    const o = c.o;
    let status = String(o.status), tipe = o.tipe_tujuan, nama = o.nama_lokasi, pid = o.place_id, url = o.url_tujuan;
    if (patch.tipe) {
      if (status !== 'terhubung' && !(allowStatus && status === 'nonaktif')) throw uerr_('Kartu belum diregistrasi atau sedang nonaktif.');
      const d = normalizeDest_(patch);
      tipe = d.tipe; nama = d.nama; pid = d.placeId; url = d.url;
    } else if (!allowStatus) {
      throw uerr_('Tidak ada perubahan.');
    }
    if (allowStatus && typeof patch.aktif === 'boolean') {
      if (patch.aktif) { if (status === 'nonaktif') status = url ? 'terhubung' : 'belum_setup'; }
      else status = 'nonaktif';
    }
    c.sh.getRange(c.row, 2, 1, 5).setValues([[status, tipe, nama, pid, url]]);
    invalidateCard_(code);
    invalidateStats_();
    log_(actor, 'ubah_kartu', code, status + ' · ' + tipe + ' · ' + nama);
    o.status = status; o.tipe_tujuan = tipe; o.nama_lokasi = nama; o.place_id = pid; o.url_tujuan = url;
    return o;
  });
}

function resetCard_(code, actor) {
  withLock_(function () {
    const c = cardRow_(code);
    c.sh.getRange(c.row, 2, 1, 10).setValues([['belum_setup', '', '', '', '', '', '', '', 0, '']]);
    invalidateCard_(code);
    invalidateStats_();
    CacheService.getScriptCache().removeAll(['pf:' + code, 'pd:' + code]);
    log_(actor, 'reset_kartu', code, '');
  });
}

/**
 * Pencarian lokasi (Google Places API baru — Text Search).
 * ctx: { code } saat registrasi | { cardToken } saat kelola | { staffToken } untuk staf.
 * API key hanya ada di server (Script Properties) dan tidak pernah dikirim ke browser.
 */
function searchPlaces(ctx, query) {
  return run_(function () {
    ctx = ctx || {};
    query = String(query || '').trim().slice(0, 100);
    if (query.length < 2) return [];
    let who;
    if (ctx.cardToken) { who = 'c' + ownerCode_(ctx.cardToken); }
    else if (ctx.staffToken) { who = 's' + authStaff_(ctx.staffToken, ['admin', 'master']).u; }
    else {
      const code = needCode_(ctx.code);
      const pub = getCardPublic_(code);
      if (!pub || pub.status !== 'belum_setup') throw uerr_('Pencarian tidak tersedia untuk kartu ini.');
      who = 'r' + code;
    }
    const cache = CacheService.getScriptCache();
    const rk = 'ps:' + who;
    const used = Number(cache.get(rk) || 0);
    if (used >= 50) throw uerr_('Terlalu banyak pencarian. Coba lagi dalam beberapa menit.');
    cache.put(rk, String(used + 1), 3600);

    const ck = 'pl:' + Utilities.base64EncodeWebSafe(Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, query.toLowerCase())).slice(0, 22);
    const cached = cache.get(ck);
    if (cached) return JSON.parse(cached);

    const key = getProp_('placesApiKey');
    if (!key) throw uerr_('Pencarian lokasi belum diaktifkan. Hubungi admin.');

    let out = [];

    // METODE 1 (Utama): Google Places Autocomplete (New) — mendukung kata parsial, singkatan, & tanpa nama kota
    try {
      const autoRes = UrlFetchApp.fetch('https://places.googleapis.com/v1/places:autocomplete', {
        method: 'post', contentType: 'application/json', muteHttpExceptions: true,
        headers: { 'X-Goog-Api-Key': key },
        payload: JSON.stringify({
          input: query,
          languageCode: 'id',
          includedRegionCodes: ['ID']
        })
      });
      if (autoRes.getResponseCode() === 200) {
        const autoBody = JSON.parse(autoRes.getContentText() || '{}');
        if (autoBody.placePredictions && autoBody.placePredictions.length) {
          out = autoBody.placePredictions.map(function (p) {
            const name = (p.structuredFormat && p.structuredFormat.mainText && p.structuredFormat.mainText.text) || (p.text && p.text.text) || '';
            const addr = (p.structuredFormat && p.structuredFormat.secondaryText && p.structuredFormat.secondaryText.text) || (p.text && p.text.text) || '';
            return { id: p.placeId, name: name, address: addr };
          }).filter(function (p) { return p.id && p.name; });
        }
      } else {
        logErr_('Places Autocomplete API ' + autoRes.getResponseCode() + ': ' + autoRes.getContentText().slice(0, 300));
      }
    } catch (eAuto) {
      logErr_('Places Autocomplete exception: ' + eAuto.message);
    }

    // METODE 2 (Fallback): Text Search bila autocomplete tidak menghasilkan data
    if (!out.length) {
      try {
        const textRes = UrlFetchApp.fetch('https://places.googleapis.com/v1/places:searchText', {
          method: 'post', contentType: 'application/json', muteHttpExceptions: true,
          headers: { 'X-Goog-Api-Key': key, 'X-Goog-FieldMask': 'places.id,places.displayName,places.formattedAddress' },
          payload: JSON.stringify({ textQuery: query, languageCode: 'id', pageSize: 7 })
        });
        if (textRes.getResponseCode() === 200) {
          const textBody = JSON.parse(textRes.getContentText() || '{}');
          out = (textBody.places || []).map(function (p) {
            return { id: p.id, name: (p.displayName && p.displayName.text) || '', address: p.formattedAddress || '' };
          }).filter(function (p) { return p.id && p.name; });
        }
      } catch (eText) {
        logErr_('Places Text Search exception: ' + eText.message);
      }
    }

    cache.put(ck, JSON.stringify(out), 3600);
    countPlacesUse_();
    return out;
  });
}

function countPlacesUse_() {
  try {
    const k = 'placesUse:' + Utilities.formatDate(new Date(), tz_(), 'yyyy-MM');
    props_().setProperty(k, String((Number(getProp_(k)) || 0) + 1));
  } catch (e) { /* abaikan */ }
}

// ════════════════════════════════════════════════════════
// BAGIAN 7: API STAF — LOGIN & DATA
// ════════════════════════════════════════════════════════

function doLogin(username, password) {
  return run_(function () {
    username = String(username || '').trim().toLowerCase();
    password = String(password || '');
    if (!username || !password) throw uerr_('Isi username dan kata sandi.');
    const cache = CacheService.getScriptCache();
    const fk = 'lf:' + username;
    const fails = Number(cache.get(fk) || 0);
    if (fails >= 5) throw uerr_('Terlalu banyak percobaan. Coba lagi dalam 15 menit.', 'LOCKED');
    const u = readUsers_();
    const idx = u.rows.findIndex(function (r) { return String(r[0]).toLowerCase() === username; });
    const rec = idx >= 0 ? u.rows[idx] : null;
    const ok = !!(rec && isTrue_(rec[4]) && verifySecret_(password, rec[2]));
    if (!rec) hashSecret_(password, 'x');
    if (!ok) {
      cache.put(fk, String(fails + 1), LOCK_SEC);
      const left = 5 - (fails + 1);
      throw uerr_(left > 0 ? 'Username atau password salah. Sisa ' + left + ' percobaan.' : 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.');
    }
    cache.remove(fk);
    const s = { u: String(rec[0]).toLowerCase(), n: String(rec[1] || rec[0]), r: String(rec[3]), e: Date.now() };
    const token = Utilities.getUuid() + Utilities.getUuid().replace(/-/g, '');
    cache.put('ss:' + token, JSON.stringify(s), SESSION_TTL);
    u.sh.getRange(idx + 2, 6).setValue(new Date());
    return { token: token, boot: buildBootstrap_(s) };
  });
}

function doLogout(token) {
  return run_(function () {
    if (token) CacheService.getScriptCache().remove('ss:' + token);
    return null;
  });
}

/** Satu panggilan untuk semua data dashboard (kartu, ringkasan, pengaturan, akun) */
function staffBootstrap(token) {
  return run_(function () { return buildBootstrap_(authStaff_(token)); });
}

function buildBootstrap_(s) {
  flushScanQueue();
  const ss = getSS_();
  const cards = readAllCards_(ss).map(staffCard_);
  const out = { user: { username: s.u, nama: s.n, role: s.r }, cards: cards, baseUrl: getBaseUrl_(),
    waAdmin: publicCfg_().wa, serverTime: Date.now() };
  if (s.r === 'master') {
    out.overview = buildOverview_(cards, readLog_(ss));
    out.settings = settingsView_();
    out.users = usersView_();
  }
  return out;
}

function updateCardStaff(token, code, patch) {
  return run_(function () {
    const s = authStaff_(token, ['admin', 'master']);
    return staffCard_(applyCardUpdate_(needCode_(code), patch, s.u, true));
  });
}

function resetCardStaff(token, code) {
  return run_(function () {
    const s = authStaff_(token, ['admin', 'master']);
    resetCard_(needCode_(code), s.u);
    return { code: code, scans: 0, lastTs: 0 };
  });
}

/** Hapus kartu secara permanen oleh staf (admin/master) */
function deleteCardStaff(token, code) {
  return run_(function () {
    const s = authStaff_(token, ['admin', 'master']);
    return withLock_(function () {
      const c = cardRow_(needCode_(code));
      c.sh.deleteRow(c.row);
      invalidateCard_(code);
      invalidateStats_();
      CacheService.getScriptCache().remove('pf:' + code);
      log_(s.u, 'hapus_kartu', code, '');
      return { code: code };
    });
  });
}

/** Buat kode kartu acak massal (status awal: belum_setup) */
function generateCodes(token, jumlah, panjang, aman, label) {
  return run_(function () {
    const s = authStaff_(token, ['admin', 'master']);
    jumlah = Math.floor(Number(jumlah));
    panjang = Math.floor(Number(panjang));
    if (!(jumlah >= 1 && jumlah <= 1000)) throw uerr_('Jumlah kode harus 1-1000.');
    if (!(panjang >= 8 && panjang <= 10)) throw uerr_('Panjang kode harus 8-10 karakter.');
    const alpha = aman === false ? ALL_ALPHA : SAFE_ALPHA;
    return withLock_(function () {
      const sh = getSS_().getSheetByName(SHEET.KARTU);
      const last = sh.getLastRow();
      const exist = {};
      if (last >= 2) sh.getRange(2, 1, last - 1, 1).getValues().forEach(function (r) { exist[String(r[0])] = 1; });
      const now = new Date();
      const batchId = 'BATCH-' + Utilities.formatDate(now, tz_(), 'yyyyMMdd-HHmm');
      const lbl = String(label || '').trim().slice(0, 60);
      const batch = batchId + (lbl ? ' · ' + lbl : '');
      const codes = [];
      let guard = 0;
      while (codes.length < jumlah) {
        if (++guard > jumlah * 30) throw uerr_('Gagal membuat kode unik. Coba lagi.');
        const c = randChars_(panjang, alpha);
        if (!/[A-Z]/.test(c) || exist[c]) continue;
        exist[c] = 1; codes.push(c);
      }
      const rows = codes.map(function (c) {
        const r = new Array(H_KARTU.length).fill('');
        r[0] = c; r[1] = 'belum_setup'; r[9] = 0; r[11] = now; r[12] = batch;
        return r;
      });
      fmtText_(sh, last + 1, rows.length);
      sh.getRange(last + 1, 1, rows.length, H_KARTU.length).setValues(rows);
      invalidateStats_();
      log_(s.u, 'buat_kode', '', jumlah + ' kode · ' + batch);
      return { batch: batch, createdTs: now.getTime(), baseUrl: getBaseUrl_(), codes: codes };
    });
  });
}

// ════════════════════════════════════════════════════════
// BAGIAN 8: LAPORAN (MASTER)
// ════════════════════════════════════════════════════════

function readLog_(ss) {
  const sh = ss.getSheetByName(SHEET.LOG);
  const last = sh.getLastRow();
  if (last < 2) return [];
  return sh.getRange(2, 1, last - 1, 3).getValues();
}
function tzOff_() {
  const z = Utilities.formatDate(new Date(), tz_(), 'Z');
  return (z.charAt(0) === '-' ? -1 : 1) * (parseInt(z.substr(1, 2), 10) * 60 + parseInt(z.substr(3, 2), 10)) * 60000;
}
function isoOfIdx_(idx) { return new Date(idx * DAY_MS).toISOString().slice(0, 10); }
function idxOfIso_(iso) { return Math.floor(Date.parse(iso + 'T00:00:00Z') / DAY_MS); }
function bucketKey_(idx, gran) {
  if (gran === 'week') return idx - ((idx + 3) % 7);          // awal minggu (Senin)
  if (gran === 'month') return isoOfIdx_(idx).slice(0, 7);
  return idx;
}
function bucketLabel_(k, gran) {
  if (gran === 'month') { const p = String(k).split('-'); return MONTHS[Number(p[1]) - 1] + ' ' + p[0]; }
  const d = new Date(k * DAY_MS);
  return d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()];
}
/** Hitung scan berhasil per bucket (hari/minggu/bulan) */
function bucketize_(rows, fromIdx, toIdx, gran, accept) {
  const off = tzOff_();
  const keys = [], map = {};
  for (let i = fromIdx; i <= toIdx; i++) {
    const k = bucketKey_(i, gran);
    if (!(k in map)) { map[k] = 0; keys.push(k); }
  }
  let total = 0;
  const codes = {};
  rows.forEach(function (r) {
    if (r[2] !== 'berhasil') return;
    const code = String(r[1]);
    if (accept && !accept(code)) return;
    const idx = Math.floor((ts_(r[0]) + off) / DAY_MS);
    if (idx < fromIdx || idx > toIdx) return;
    map[bucketKey_(idx, gran)]++;
    total++;
    codes[code] = 1;
  });
  return {
    keys: keys,
    values: keys.map(function (k) { return map[k]; }),
    labels: keys.map(function (k) { return bucketLabel_(k, gran); }),
    subs: keys.map(function (k) { return gran === 'day' ? DAYS_S[(k + 4) % 7] : ''; }),
    total: total, distinct: Object.keys(codes).length
  };
}
function countRange_(rows, fromIdx, toIdx, accept) {
  const off = tzOff_();
  let n = 0;
  rows.forEach(function (r) {
    if (r[2] !== 'berhasil') return;
    if (accept && !accept(String(r[1]))) return;
    const idx = Math.floor((ts_(r[0]) + off) / DAY_MS);
    if (idx >= fromIdx && idx <= toIdx) n++;
  });
  return n;
}

function buildOverview_(cards, logRows) {
  const ver = statsVer_();
  const cache = CacheService.getScriptCache();
  const hit = cache.get('ov:' + ver);
  if (hit) return JSON.parse(hit);
  const off = tzOff_();
  const todayIdx = Math.floor((Date.now() + off) / DAY_MS);
  const b = bucketize_(logRows, todayIdx - 6, todayIdx, 'day');
  const counts = { terhubung: 0, belum_setup: 0, nonaktif: 0 };
  cards.forEach(function (c) { counts[c.status] = (counts[c.status] || 0) + 1; });
  const today = b.values[6], yest = b.values[5];
  let peak = 0;
  b.values.forEach(function (v, i) { if (v > b.values[peak]) peak = i; });
  const latest = cards.filter(function (c) { return c.regTs; })
    .sort(function (a, z) { return z.regTs - a.regTs; }).slice(0, 5);
  const ov = {
    total: cards.length, counts: counts, scansToday: today,
    trendPct: yest > 0 ? Math.round((today - yest) / yest * 100) : null,
    series: { labels: b.labels, subs: b.subs, values: b.values }, total7: b.total,
    avg7: Math.round(b.total / 7),
    peak: { label: b.labels[peak], sub: b.subs[peak], value: b.values[peak] },
    latest: latest
  };
  cache.put('ov:' + ver, JSON.stringify(ov), 120);
  return ov;
}

/** Laporan scan: params { gran: day|week|month, from, to (yyyy-MM-dd), tipe: all|google_review|link_lain } */
function getScanReport(token, params) {
  return run_(function () {
    authStaff_(token, ['master']);
    params = params || {};
    const gran = ['day', 'week', 'month'].indexOf(params.gran) >= 0 ? params.gran : 'day';
    const tipe = ['google_review', 'link_lain'].indexOf(params.tipe) >= 0 ? params.tipe : 'all';
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(params.from)) || !/^\d{4}-\d{2}-\d{2}$/.test(String(params.to))) throw uerr_('Rentang tanggal tidak valid.');
    const fromIdx = idxOfIso_(params.from), toIdx = idxOfIso_(params.to);
    if (toIdx < fromIdx) throw uerr_('Tanggal akhir harus setelah tanggal awal.');
    if (toIdx - fromIdx > 730) throw uerr_('Rentang maksimal 2 tahun.');
    const cache = CacheService.getScriptCache();
    const ck = 'sr:' + statsVer_() + ':' + [gran, tipe, fromIdx, toIdx].join(':');
    const hit = cache.get(ck);
    if (hit) return JSON.parse(hit);

    flushScanQueue();
    const ss = getSS_();
    const cards = readAllCards_(ss);
    const tipeOf = {};
    cards.forEach(function (c) { tipeOf[String(c.nomor_kartu)] = c.tipe_tujuan; });
    const log = readLog_(ss);
    const accept = tipe === 'all' ? null : function (code) { return tipeOf[code] === tipe; };
    const b = bucketize_(log, fromIdx, toIdx, gran, accept);
    const len = toIdx - fromIdx + 1;
    const prev = countRange_(log, fromIdx - len, fromIdx - 1, accept);
    let pk = 0;
    b.values.forEach(function (v, i) { if (v > b.values[pk]) pk = i; });
    const dayIdx = gran === 'day' ? b.keys[pk] : null;
    const tc = { google_review: 0, link_lain: 0 };
    const off = tzOff_();
    log.forEach(function (r) {
      if (r[2] !== 'berhasil') return;
      const idx = Math.floor((ts_(r[0]) + off) / DAY_MS);
      if (idx < fromIdx || idx > toIdx) return;
      const t = tipeOf[String(r[1])];
      if (t in tc) tc[t]++;
    });
    const activeCards = cards.filter(function (c) { return c.status === 'terhubung' && (tipe === 'all' || c.tipe_tujuan === tipe); }).length;
    const out = {
      labels: b.labels, subs: b.subs, values: b.values, total: b.total, prev: prev,
      changePct: prev > 0 ? Math.round((b.total - prev) / prev * 100) : null,
      peak: { label: b.labels[pk], value: b.values[pk],
        long: dayIdx === null ? b.labels[pk] : DAYS_L[(dayIdx + 4) % 7] + ', ' + b.labels[pk] },
      distinct: b.distinct, activeCards: activeCards, tipe: tc, avg: Math.round(b.total / Math.max(1, b.keys.length))
    };
    cache.put(ck, JSON.stringify(out), 90);
    return out;
  });
}

function esc_(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

/** Ekspor laporan kartu ke PDF (daftar kode yang sedang difilter di layar) */
function exportCardReportPdf(token, codes, meta) {
  return run_(function () {
    const s = authStaff_(token, ['master']);
    meta = meta || {};
    const want = {};
    (codes || []).slice(0, 3000).forEach(function (c) { want[String(c)] = 1; });
    const all = readAllCards_(getSS_()).filter(function (c) { return want[String(c.nomor_kartu)]; }).map(staffCard_);
    const fmt = function (ms) { return ms ? Utilities.formatDate(new Date(ms), tz_(), 'dd MMM yyyy HH:mm') : '-'; };
    const lbl = { terhubung: 'Terhubung', belum_setup: 'Belum Setup', nonaktif: 'Nonaktif' };
    const tipeLbl = { google_review: 'Google Review', link_lain: 'Link Lain' };
    const sum = { t: 0, b: 0, n: 0, scans: 0 };
    all.forEach(function (c) { sum.scans += c.scans; if (c.status === 'terhubung') sum.t++; else if (c.status === 'belum_setup') sum.b++; else sum.n++; });
    const rows = all.map(function (c, i) {
      return '<tr><td>' + (i + 1) + '</td><td class="m">' + esc_(c.code) + '</td><td>' + esc_(lbl[c.status] || c.status) + '</td><td>' +
        esc_(tipeLbl[c.tipe] || '-') + '</td><td>' + esc_(c.nama || '-') + '</td><td>' + esc_(fmt(c.regTs)) + '</td><td class="r">' + c.scans + '</td></tr>';
    }).join('');
    const html = '<html><head><meta charset="utf-8"><style>' +
      'body{font-family:Arial,sans-serif;color:#0F1F17;font-size:10px}h1{font-size:18px;color:#14532D;margin:0 0 4px}' +
      '.s{color:#5E6E66;margin-bottom:12px}table{border-collapse:collapse;width:100%}' +
      'th{background:#14532D;color:#fff;text-align:left;padding:6px;font-size:9px}td{padding:5px 6px;border-bottom:1px solid #E2E8F0}' +
      '.m{font-family:Courier New,monospace;font-weight:bold}.r{text-align:right}.k{margin:10px 0;padding:8px;background:#E8F5EC}</style></head><body>' +
      '<h1>Laporan Kartu NFC</h1><div class="s">Dibuat ' + esc_(fmt(Date.now())) + ' oleh ' + esc_(s.n) + (meta.filter ? ' · Filter: ' + esc_(meta.filter) : '') + '</div>' +
      '<div class="k"><b>' + all.length + '</b> kartu · Terhubung <b>' + sum.t + '</b> · Belum Setup <b>' + sum.b + '</b> · Nonaktif <b>' + sum.n + '</b> · Total scan <b>' + sum.scans + '</b></div>' +
      '<table><tr><th>No</th><th>Kode</th><th>Status</th><th>Tipe</th><th>Tujuan</th><th>Registrasi</th><th>Scan</th></tr>' + rows + '</table></body></html>';
    const pdf = HtmlService.createHtmlOutput(html).getBlob().getAs('application/pdf');
    return { filename: 'laporan-kartu-nfc-' + Utilities.formatDate(new Date(), tz_(), 'yyyyMMdd') + '.pdf', base64: Utilities.base64Encode(pdf.getBytes()) };
  });
}

/** Ekspor QR tag NFC tunggal ke PDF siap cetak */
function exportCardQrPdf(token, code) {
  return run_(function () {
    const s = authStaff_(token, ['admin', 'master']);
    const cCode = needCode_(code);
    const c = cardRow_(cCode).o;
    const tagUrl = getBaseUrl_() + '?id=' + encodeURIComponent(cCode);
    const qrApi = 'https://api.qrserver.com/v1/create-qr-code/?size=360x360&margin=0&data=' + encodeURIComponent(tagUrl);
    const nowStr = Utilities.formatDate(new Date(), tz_(), 'dd MMM yyyy HH:mm');
    const statusLbl = { terhubung: 'Terhubung', belum_setup: 'Belum Setup', nonaktif: 'Nonaktif' };
    const html = '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      '<style>' +
      '@page { size: A4 portrait; margin: 20mm; }' +
      'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; color: #0F1F17; margin: 0; padding: 24px; }' +
      '.sheet { max-width: 440px; margin: 0 auto; border: 2px dashed #14532D; border-radius: 20px; padding: 28px; text-align: center; background: #ffffff; }' +
      '.brand { font-size: 13px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #14532D; margin-bottom: 4px; }' +
      '.title { font-size: 22px; font-weight: 800; margin: 0 0 16px; color: #0F1F17; }' +
      '.qr-wrap { background: #ffffff; border: 1px solid #CBD5E1; border-radius: 16px; padding: 16px; display: inline-block; margin-bottom: 16px; }' +
      '.qr-wrap img { display: block; width: 220px; height: 220px; }' +
      '.code-badge { font-family: "Courier New", monospace; font-size: 22px; font-weight: 800; letter-spacing: 0.12em; background: #E8F5EC; color: #14532D; padding: 6px 18px; border-radius: 999px; display: inline-block; margin-bottom: 12px; }' +
      '.url-box { font-family: "Courier New", monospace; font-size: 11px; word-break: break-all; background: #F4F6F5; padding: 10px 14px; border-radius: 10px; color: #334155; margin-bottom: 16px; border: 1px solid #E2E8F0; }' +
      '.guide { font-size: 12px; color: #5E6E66; line-height: 1.6; text-align: left; background: #F8FAFC; border-radius: 12px; padding: 12px 14px; border: 1px solid #E2E8F0; }' +
      '.guide b { color: #0F1F17; }' +
      '.foot { margin-top: 18px; font-size: 10px; color: #94A3B8; text-align: center; }' +
      '</style></head><body>' +
      '<div class="sheet">' +
      '<div class="brand">Redirect NFC · Tag Card</div>' +
      '<h1 class="title">Kartu Tag NFC & QR</h1>' +
      '<div class="qr-wrap"><img src="' + esc_(qrApi) + '" alt="QR Code" width="220" height="220" /></div>' +
      '<div><span class="code-badge">' + esc_(cCode) + '</span></div>' +
      '<div class="url-box">' + esc_(tagUrl) + '</div>' +
      '<div class="guide">' +
      '<b>Petunjuk Penggunaan:</b><br>' +
      '1. <b>Chip NFC:</b> Flash / tulis URL di atas ke dalam chip NFC tag kartu Anda.<br>' +
      '2. <b>Pindai Langsung:</b> Pengunjung dapat mendekatkan HP ke tag NFC atau memindai QR Code di atas menggunakan kamera HP.<br>' +
      '3. <b>Status Kartu:</b> ' + esc_(statusLbl[c.status] || c.status) + (c.batch ? ' · Batch: ' + esc_(c.batch) : '') +
      '</div>' +
      '<div class="foot">Dicetak pada ' + esc_(nowStr) + ' oleh ' + esc_(s.n || s.u) + '</div>' +
      '</div></body></html>';
    const pdf = HtmlService.createHtmlOutput(html).getBlob().getAs('application/pdf');
    return {
      filename: 'QR-Tag-' + cCode + '.pdf',
      base64: Utilities.base64Encode(pdf.getBytes())
    };
  });
}

// ════════════════════════════════════════════════════════
// BAGIAN 9: PENGATURAN & AKUN (MASTER)
// ════════════════════════════════════════════════════════

function settingsView_() {
  const uk = 'placesUse:' + Utilities.formatDate(new Date(), tz_(), 'yyyy-MM');
  return { waAdmin: getProp_('waAdmin') || '', baseUrl: getProp_('baseUrl') || '', autoBaseUrl: ScriptApp.getService().getUrl(),
    apiKeySet: !!getProp_('placesApiKey'), placesUse: Number(getProp_(uk)) || 0 };
}
function usersView_() {
  return readUsers_().rows.map(function (r) {
    return { username: String(r[0]), nama: String(r[1]), role: String(r[3]), aktif: isTrue_(r[4]), lastTs: ts_(r[5]) };
  });
}

function saveSettings(token, st) {
  return run_(function () {
    const s = authStaff_(token, ['master']);
    st = st || {};
    if (typeof st.waAdmin === 'string') {
      const w = st.waAdmin.trim();
      if (w) props_().setProperty('waAdmin', normWa_(w)); else props_().deleteProperty('waAdmin');
      CacheService.getScriptCache().remove('pubcfg');
    }
    if (typeof st.baseUrl === 'string') {
      const b = st.baseUrl.trim();
      if (b) props_().setProperty('baseUrl', validUrl_(b).replace(/[?#].*$/, '')); else props_().deleteProperty('baseUrl');
    }
    if (typeof st.apiKey === 'string' && st.apiKey.trim()) {
      const k = st.apiKey.trim();
      if (!/^[A-Za-z0-9_\-]{20,80}$/.test(k)) throw uerr_('Format API key tidak valid.');
      props_().setProperty('placesApiKey', k);
    }
    log_(s.u, 'ubah_pengaturan', '', '');
    return { settings: settingsView_(), baseUrl: getBaseUrl_(), waAdmin: publicCfg_().wa };
  });
}

function createUser(token, u) {
  return run_(function () {
    const s = authStaff_(token, ['master']);
    u = u || {};
    const username = String(u.username || '').trim().toLowerCase();
    const nama = String(u.nama || '').trim().slice(0, 60) || username;
    if (!/^[a-z0-9._-]{3,30}$/.test(username)) throw uerr_('Username 3-30 karakter: huruf kecil, angka, titik, strip.');
    if (String(u.password || '').length < 8) throw uerr_('Kata sandi minimal 8 karakter.');
    return withLock_(function () {
      const us = readUsers_();
      if (us.rows.some(function (r) { return String(r[0]).toLowerCase() === username; })) throw uerr_('Username sudah dipakai.');
      us.sh.appendRow([username, nama, makeSecret_(String(u.password)), 'admin', true, '']);
      log_(s.u, 'tambah_admin', '', username);
      return usersView_();
    });
  });
}

function setUserActive(token, username, aktif) {
  return run_(function () {
    const s = authStaff_(token, ['master']);
    username = String(username || '').toLowerCase();
    return withLock_(function () {
      const us = readUsers_();
      const i = us.rows.findIndex(function (r) { return String(r[0]).toLowerCase() === username; });
      if (i < 0) throw uerr_('Akun tidak ditemukan.');
      if (String(us.rows[i][3]) === 'master') throw uerr_('Akun master tidak dapat dinonaktifkan.');
      us.sh.getRange(i + 2, 5).setValue(!!aktif);
      if (!aktif) CacheService.getScriptCache().put('ue:' + username, String(Date.now()), 21600);
      log_(s.u, aktif ? 'aktifkan_admin' : 'nonaktifkan_admin', '', username);
      return usersView_();
    });
  });
}

function resetUserPassword(token, username, newPassword) {
  return run_(function () {
    const s = authStaff_(token, ['master']);
    username = String(username || '').toLowerCase();
    if (String(newPassword || '').length < 8) throw uerr_('Kata sandi minimal 8 karakter.');
    return withLock_(function () {
      const us = readUsers_();
      const i = us.rows.findIndex(function (r) { return String(r[0]).toLowerCase() === username; });
      if (i < 0) throw uerr_('Akun tidak ditemukan.');
      us.sh.getRange(i + 2, 3).setValue(makeSecret_(String(newPassword)));
      if (username !== s.u) CacheService.getScriptCache().put('ue:' + username, String(Date.now()), 21600);
      log_(s.u, 'reset_password', '', username);
      return usersView_();
    });
  });
}

function changeOwnPassword(token, oldPw, newPw) {
  return run_(function () {
    const s = authStaff_(token);
    if (String(newPw || '').length < 8) throw uerr_('Kata sandi baru minimal 8 karakter.');
    return withLock_(function () {
      const us = readUsers_();
      const i = us.rows.findIndex(function (r) { return String(r[0]).toLowerCase() === s.u; });
      if (i < 0 || !verifySecret_(String(oldPw || ''), us.rows[i][2])) throw uerr_('Kata sandi lama salah.');
      us.sh.getRange(i + 2, 3).setValue(makeSecret_(String(newPw)));
      log_(s.u, 'ganti_password', '', '');
      return null;
    });
  });
}

/** Pintu Login Petugas — kunci disimpan di Properti skrip: STAFF_GATE_KEY */
function staffGateOk_(gate) {
  var key = PropertiesService.getScriptProperties().getProperty('STAFF_GATE_KEY');
  if (!key) return true;
  gate = String(gate || '');
  if (gate.length !== key.length) return false;
  var diff = 0;
  for (var i = 0; i < key.length; i++) diff |= key.charCodeAt(i) ^ gate.charCodeAt(i);
  return diff === 0;
}
