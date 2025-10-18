// index.js — Backend: licencje + rejestracja/logowanie użytkowników (Firestore + Render)
// Wersja z poprawkami: brak wewnętrznych fetchy, expiresAt = "YYYY-MM-DD" (UTC), keep-alive.

const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const admin = require("firebase-admin");

// ================= Firebase credentials =================
const serviceAccountPath = path.join(__dirname, "serviceAccountKey.json");
let serviceAccount = null;

if (fs.existsSync(serviceAccountPath)) {
  serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));
} else if (process.env.SERVICE_ACCOUNT_JSON) {
  serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_JSON);
} else {
  console.error("❌ Brak poświadczeń: dodaj serviceAccountKey.json ALBO ustaw SERVICE_ACCOUNT_JSON (pełny JSON).");
  process.exit(1);
}

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

// ================= App =================
const app = express();
app.use(express.json());

// Healthcheck
app.get("/", (_req, res) => res.status(200).send("License server OK ✅"));

// ================= Helpers =================

// Z klucza w formacie "HAMSTER-<dni>D-..." wyciąga liczbę dni
function parseDurationDaysFromKey(licenseKey) {
  const m = /^HAMSTER-(\d+)D-/i.exec(String(licenseKey || "").trim());
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

// Zwraca Date w UTC dla północy z dzisiejszej daty + days
function calcExpiresAtUTCString(days) {
  if (!days || days <= 0) return null;
  const d = new Date();
  d.setUTCHours(0, 0, 0, 0);
  d.setUTCDate(d.getUTCDate() + days);
  // zwracamy "YYYY-MM-DD"
  return d.toISOString().slice(0, 10);
}
function timestampFromYYYYMMDD(str) {
  // tworzymy Timestamp z północy UTC dla "YYYY-MM-DD"
  if (!str || str.length < 10) return null;
  const Y = parseInt(str.slice(0, 4), 10);
  const M = parseInt(str.slice(5, 7), 10);
  const D = parseInt(str.slice(8, 10), 10);
  if (!Y || !M || !D) return null;
  const dt = new Date(Date.UTC(Y, M - 1, D, 0, 0, 0, 0));
  return admin.firestore.Timestamp.fromDate(dt);
}
function todayUTC_YYYYMMDD() {
  const d = new Date();
  d.setUTCHours(0, 0, 0, 0);
  return d.toISOString().slice(0, 10);
}

// Wspólna logika licencji: sprawdza i (jeśli trzeba) przypina HWID/username.
// Zwraca { ok, code?, message?, expiresAt? } gdzie expiresAt = "YYYY-MM-DD".
async function checkAndBindLicense({ username, licenseKey, deviceId }) {
  const key = String(licenseKey || "").trim();
  const licRef = db.collection("licenses").doc(key);
  const snap = await licRef.get();

  if (!snap.exists) {
    return { ok: false, code: "invalid", message: "Invalid license key" };
  }
  const lic = snap.data() || {};

  // 1) aktywność
  if (lic.active === false) {
    return { ok: false, code: "inactive", message: "License inactive" };
  }

  // 2) ważność — używamy pola expiresAt (Timestamp lub string) LUB wyliczamy
  const durationDays = parseDurationDaysFromKey(key); // np. 30 z "HAMSTER-30D-..."
  // preferuj pole w bazie (Timestamp/string); w razie braku — wylicz po pierwszej aktywacji
  let expiresAtStr = null;

  if (typeof lic.expiresAt === "string") {
    expiresAtStr = lic.expiresAt.slice(0, 10);
  } else if (lic.expiresAt && typeof lic.expiresAt.toDate === "function") {
    const d = lic.expiresAt.toDate();
    // wymuś północ UTC w prezentacji
    d.setUTCHours(0, 0, 0, 0);
    expiresAtStr = d.toISOString().slice(0, 10);
  }

  // jeśli nieprzypięta licencja
  if (!lic.hwid) {
    // Pierwsza aktywacja — przypnij HWID i username, ustaw expiresAt jako YYYY-MM-DD (UTC)
    const expStr = expiresAtStr || calcExpiresAtUTCString(durationDays);
    const nowTs = admin.firestore.Timestamp.now();

    await licRef.set(
      {
        hwid: deviceId,
        ownerUsername: username,
        activatedAt: nowTs,
        firstActivatedAt: nowTs,
        lastLoginAt: nowTs,
        durationDays: durationDays || null,
        expiresAt: expStr ? timestampFromYYYYMMDD(expStr) : null,
        expiresAtStr: expStr || null, // dodatkowo przechowujemy string dla spójności UI
      },
      { merge: true }
    );

    await licRef.collection("accessLogs").add({
      type: "first_activation",
      username,
      deviceId,
      timestamp: nowTs,
    });

    return { ok: true, code: "ok", message: "License bound", expiresAt: expStr || null };
  }

  // 3) HWID musi pasować
  if (lic.hwid !== deviceId) {
    await licRef.collection("accessLogs").add({
      type: "hwid_mismatch",
      username,
      attemptedDeviceId: deviceId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
    return { ok: false, code: "hwid_mismatch", message: "Device mismatch" };
  }

  // 4) Username musi pasować
  if (lic.ownerUsername && lic.ownerUsername !== username) {
    await licRef.collection("accessLogs").add({
      type: "username_mismatch",
      usernameAttempt: username,
      ownerUsername: lic.ownerUsername,
      deviceId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
    return { ok: false, code: "username_mismatch", message: "Username mismatch" };
  }

  // 5) sprawdź wygaśnięcie: porównanie DAT "YYYY-MM-DD" bez godzin
  const today = todayUTC_YYYYMMDD();
  const expStr = expiresAtStr || lic.expiresAtStr || null;

  if (durationDays && expStr && today > expStr) {
    await licRef.set(
      { active: false, expiredAt: admin.firestore.FieldValue.serverTimestamp() },
      { merge: true }
    );
    return { ok: false, code: "expired", message: "License expired", expiresAt: expStr };
  }

  // 6) OK — odśwież lastLoginAt
  await licRef.set({ lastLoginAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

  return { ok: true, code: "ok", message: "OK", expiresAt: expStr || null };
}

// ================= /licenseLogin =================
// - 1. pierwsze logowanie: przypina HWID + ownerUsername; ustawia expiresAt="YYYY-MM-DD" (UTC)
// - 2. kolejne logowania: sprawdza HWID/username oraz ważność licencji
app.post("/licenseLogin", async (req, res) => {
  const { username, licenseKey, deviceId } = req.body || {};
  if (!username || !licenseKey || !deviceId) {
    return res.status(400).json({ Allowed: false, message: "Missing username, licenseKey or deviceId" });
  }

  try {
    const out = await checkAndBindLicense({ username, licenseKey, deviceId });

    if (!out.ok) {
      const code = out.code || "invalid";
      const map403 = ["expired", "hwid_mismatch", "username_mismatch", "inactive", "invalid"];
      const status = map403.includes(code) ? 403 : 500;

      return res.status(status).json({
        Allowed: false,
        message: out.message || "License invalid",
        expiresAt: out.expiresAt || null, // zawsze "YYYY-MM-DD"
      });
    }

    return res.status(200).json({
      Allowed: true,
      message: out.message,
      expiresAt: out.expiresAt || null, // "YYYY-MM-DD"
    });
  } catch (err) {
    console.error("licenseLogin error:", err);
    return res.status(500).json({ Allowed: false, message: "Server error" });
  }
});

// ================= Users (Firestore) =================
function usersRef() {
  return db.collection("users");
}

// /user/register — body: { username, password, deviceId, licenseKey }
// 1) sprawdza/przypina licencję (przy 1. użyciu przypnie HWID+username, zapisze expiresAt)
// 2) zakłada użytkownika (username lowercase) i zapisuje bcrypt hash hasła
app.post("/user/register", async (req, res) => {
  const { username, password, deviceId, licenseKey } = req.body || {};
  if (!username || !password || !deviceId || !licenseKey) {
    return res.status(400).json({ ok: false, message: "missing_fields" });
  }

  const usernameId = String(username).toLowerCase();
  const uref = usersRef().doc(usernameId);
  const usnap = await uref.get();
  if (usnap.exists) return res.status(409).json({ ok: false, message: "username_taken" });

  const lic = await checkAndBindLicense({ username, licenseKey, deviceId });
  if (!lic.ok) {
    const m = (lic.message || "").toLowerCase();
    if (m.includes("expired")) return res.status(403).json({ ok: false, message: "license_expired" });
    if (m.includes("device mismatch")) return res.status(403).json({ ok: false, message: "hwid_mismatch" });
    if (m.includes("username mismatch")) return res.status(403).json({ ok: false, message: "username_invalid" });
    return res.status(403).json({ ok: false, message: "license_invalid" });
  }

  const hash = await bcrypt.hash(password, 10);
  await uref.set({
    username,
    passHash: hash,
    hwid: deviceId,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    licenseKey,
  });

  return res.json({ ok: true, expiresAt: lic.expiresAt || null }); // "YYYY-MM-DD"
});

// /user/login — body: { username, password, deviceId }
// Sprawdza username, hasło (bcrypt), HWID, a potem status licencji
app.post("/user/login", async (req, res) => {
  const { username, password, deviceId } = req.body || {};
  if (!username || !password || !deviceId) {
    return res.status(400).json({ ok: false, message: "missing_fields" });
  }

  const uref = usersRef().doc(String(username).toLowerCase());
  const usnap = await uref.get();
  if (!usnap.exists) return res.status(403).json({ ok: false, message: "username_invalid" });

  const user = usnap.data();
  if (user.username !== username) return res.status(403).json({ ok: false, message: "username_invalid" });
  if (user.hwid !== deviceId) return res.status(403).json({ ok: false, message: "hwid_mismatch" });

  const ok = await bcrypt.compare(password, user.passHash || "");
  if (!ok) return res.status(403).json({ ok: false, message: "password_invalid" });

  // licencja (bezpośrednio)
  const lic = await checkAndBindLicense({ username, licenseKey: user.licenseKey, deviceId });
  if (!lic.ok) {
    const m = (lic.message || "").toLowerCase();
    if (m.includes("expired")) return res.status(403).json({ ok: false, message: "license_expired" });
    if (m.includes("device mismatch")) return res.status(403).json({ ok: false, message: "hwid_mismatch" });
    if (m.includes("username mismatch")) return res.status(403).json({ ok: false, message: "username_invalid" });
    return res.status(403).json({ ok: false, message: "license_invalid" });
  }

  return res.json({ ok: true, expiresAt: lic.expiresAt || null }); // "YYYY-MM-DD"
});

// ================= Start =================
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => console.log(`Server listening on ${PORT}`));

// ================= Keep-alive (jak w poprzedniej wersji) =================
const KEEPALIVE_URLS = ["https://hwid-servers.onrender.com"];
const KEEPALIVE_INTERVAL_MS = 2 * 60 * 1000;
const KEEPALIVE_TIMEOUT_MS = 5000;

app.get("/keepalive", (_req, res) => {
  res.status(200).json({ ok: true, ts: new Date().toISOString() });
});

async function pingOnce(url) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), KEEPALIVE_TIMEOUT_MS);
    /** @type {Response} */
    let r = await fetch(url, { method: "HEAD", signal: controller.signal });
    clearTimeout(t);
    if (!r.ok || r.status === 405) {
      const controller2 = new AbortController();
      const t2 = setTimeout(() => controller2.abort(), KEEPALIVE_TIMEOUT_MS);
      r = await fetch(url, { method: "GET", signal: controller2.signal });
      clearTimeout(t2);
    }
    console.log(`[KEEP-ALIVE] ${new Date().toISOString()} ${url} -> ${r.status}`);
  } catch (e) {
    console.error(`[KEEP-ALIVE] ${new Date().toISOString()} ${url} -> ERROR: ${e.message}`);
  }
}

if (KEEPALIVE_URLS.length > 0 && typeof fetch !== "undefined") {
  console.log(`[KEEP-ALIVE] enabled: ${KEEPALIVE_URLS.join(", ")} | interval=${KEEPALIVE_INTERVAL_MS}ms`);
  (async () => { for (const u of KEEPALIVE_URLS) await pingOnce(u); })();
  setInterval(() => { KEEPALIVE_URLS.forEach(u => pingOnce(u)); }, KEEPALIVE_INTERVAL_MS);
} else {
  console.log("[KEEP-ALIVE] disabled (no URLs provided)");
}
