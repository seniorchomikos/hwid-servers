// index.js — Backend: licencje + rejestracja/logowanie użytkowników (Firestore + Render)

const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const admin = require("firebase-admin");

// ============ Firebase credentials ============
const serviceAccountPath = path.join(__dirname, "serviceAccountKey.json");
let serviceAccount = null;

if (fs.existsSync(serviceAccountPath)) {
  serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));
} else if (process.env.SERVICE_ACCOUNT_JSON) {
  serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_JSON);
} else {
  console.error("❌ Brak credentials: dodaj serviceAccountKey.json albo ustaw SERVICE_ACCOUNT_JSON.");
  process.exit(1);
}

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

// ============ App ============
const app = express();
app.use(express.json());

// Healthcheck
app.get("/", (req, res) => {
  res.status(200).send("License server OK ✅");
});

// ============ Helpers ============
function parseDurationDaysFromKey(licenseKey) {
  const m = /^HAMSTER-(\d+)D-/i.exec(String(licenseKey || "").trim());
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function toDate(val) {
  if (!val) return null;
  return typeof val.toDate === "function" ? val.toDate() : new Date(val);
}

function calcExpiresAt(activatedAt, days) {
  if (!activatedAt || !days) return null;
  const base = toDate(activatedAt);
  if (!base || isNaN(base.getTime())) return null;
  const ex = new Date(base.getTime());
  ex.setDate(ex.getDate() + days);
  return ex;
}

// ============ /licenseLogin ============
// - 1. pierwsze logowanie: przypina HWID + ownerUsername; ustawia expiresAt
// - 2. kolejne logowania: sprawdza HWID/username oraz ważność licencji
app.post("/licenseLogin", async (req, res) => {
  const { username, licenseKey, deviceId } = req.body || {};
  if (!username || !licenseKey || !deviceId) {
    return res.status(400).json({ Allowed: false, message: "Missing username, licenseKey or deviceId" });
  }

  const key = String(licenseKey).trim();
  const licRef = db.collection("licenses").doc(key);

  try {
    const snap = await licRef.get();
    if (!snap.exists) {
      return res.status(403).json({ Allowed: false, message: "Invalid license key" });
    }
    const lic = snap.data() || {};

    // 1) aktywność
    if (lic.active === false) {
      return res.status(403).json({ Allowed: false, message: "License inactive" });
    }

    // 2) ważność
    const days = parseDurationDaysFromKey(key);
    const expiresAt = lic.expiresAt ? toDate(lic.expiresAt) : null;

    if (days && expiresAt) {
      if (new Date() > expiresAt) {
        await licRef.set({ active: false, expiredAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
        return res.status(403).json({
          Allowed: false,
          message: `License expired after ${days} days`,
          expiresAt: expiresAt.toISOString(),
        });
      }
    }

    // 3) Pierwsze logowanie — przypnij HWID, zapisz username, duration i expiresAt
    if (!lic.hwid) {
      const now = admin.firestore.Timestamp.now();
      let calcExDate = null;
      if (days) {
        calcExDate = calcExpiresAt(new Date(), days);
      }

      await licRef.set(
        {
          hwid: deviceId,
          ownerUsername: username,
          activatedAt: now,
          firstActivatedAt: now,
          lastLoginAt: now,
          durationDays: days || null,
          expiresAt: calcExDate ? admin.firestore.Timestamp.fromDate(calcExDate) : null,
        },
        { merge: true }
      );

      await licRef.collection("accessLogs").add({
        type: "first_activation",
        username,
        deviceId,
        timestamp: now,
      });

      return res.status(200).json({
        Allowed: true,
        message: "License bound to this device (first login)",
        durationDays: days || null,
        expiresAt: calcExDate ? calcExDate.toISOString() : null,
      });
    }

    // 4) HWID przypięty — musi pasować
    if (lic.hwid !== deviceId) {
      await licRef.collection("accessLogs").add({
        type: "hwid_mismatch",
        username,
        attemptedDeviceId: deviceId,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
      });
      return res.status(403).json({ Allowed: false, message: "Device mismatch" });
    }

    // 5) username musi być ten sam
    if (lic.ownerUsername && lic.ownerUsername !== username) {
      await licRef.collection("accessLogs").add({
        type: "username_mismatch",
        usernameAttempt: username,
        ownerUsername: lic.ownerUsername,
        deviceId,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
      });
      return res.status(403).json({ Allowed: false, message: "Username mismatch" });
    }

    // 6) OK — aktualizacja lastLoginAt, zwróć expiresAt
    await licRef.set(
      { lastLoginAt: admin.firestore.FieldValue.serverTimestamp() },
      { merge: true }
    );

    const expiresISO = expiresAt ? expiresAt.toISOString() : null;

    return res.status(200).json({
      Allowed: true,
      message: "Login OK",
      durationDays: days || null,
      expiresAt: expiresISO,
    });

  } catch (err) {
    console.error("licenseLogin error:", err);
    return res.status(500).json({ Allowed: false, message: "Server error" });
  }
});

// ============ Users (Firestore) ============
function usersRef() { return db.collection("users"); }

// /user/register  — body: { username, password, deviceId, licenseKey }
// 1) sprawdza licencję przez /licenseLogin (pierwsza aktywacja przypnie HWID+username)
// 2) zakłada użytkownika (username lowercase) i zapisuje bcrypt hash hasła
app.post("/user/register", async (req, res) => {
  const { username, password, deviceId, licenseKey } = req.body || {};
  if (!username || !password || !deviceId || !licenseKey) {
    return res.status(400).json({ ok: false, message: "missing_fields" });
  }

  const usernameId = String(username).toLowerCase();
  const uref = usersRef().doc(usernameId);
  const usnap = await uref.get();
  if (usnap.exists) {
    return res.status(409).json({ ok: false, message: "username_taken" });
  }

  // sprawdź/aktywuj licencję (to też przypnie HWID przy 1. razie)
  const licResp = await fetch(`${process.env.PUBLIC_BASE_URL || ""}/licenseLogin`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, licenseKey, deviceId }),
  }).catch(() => null);

  if (!licResp) return res.status(502).json({ ok:false, message:"license_server_unreachable" });

  const licJson = await licResp.json().catch(() => ({}));
  if (!licResp.ok || !licJson.Allowed) {
    // mapowanie na Twoje komunikaty w kliencie
    if ((licJson.message || "").toLowerCase().includes("expired")) {
      return res.status(403).json({ ok:false, message:"license_expired" });
    }
    if ((licJson.message || "").toLowerCase().includes("device mismatch")) {
      return res.status(403).json({ ok:false, message:"hwid_mismatch" });
    }
    if ((licJson.message || "").toLowerCase().includes("username mismatch")) {
      return res.status(403).json({ ok:false, message:"username_invalid" });
    }
    return res.status(403).json({ ok:false, message:"license_invalid" });
  }

  const hash = await bcrypt.hash(password, 10);
  await uref.set({
    username,
    passHash: hash,
    hwid: deviceId,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    licenseKey
  });

  return res.json({ ok: true });
});

// /user/login — body: { username, password, deviceId }
// Sprawdza username, hasło (bcrypt), HWID, potem status licencji przez /licenseLogin
app.post("/user/login", async (req, res) => {
  const { username, password, deviceId } = req.body || {};
  if (!username || !password || !deviceId) {
    return res.status(400).json({ ok: false, message: "missing_fields" });
  }

  const uref = usersRef().doc(String(username).toLowerCase());
  const usnap = await uref.get();
  if (!usnap.exists) {
    return res.status(403).json({ ok:false, message:"username_invalid" });
  }
  const user = usnap.data();

  // username/hwid spójność
  if (user.username !== username) {
    return res.status(403).json({ ok:false, message:"username_invalid" });
  }
  if (user.hwid !== deviceId) {
    return res.status(403).json({ ok:false, message:"hwid_mismatch" });
  }

  const ok = await bcrypt.compare(password, user.passHash || "");
  if (!ok) {
    return res.status(403).json({ ok:false, message:"password_invalid" });
  }

  // sprawdź ważność licencji
  const licResp = await fetch(`${process.env.PUBLIC_BASE_URL || ""}/licenseLogin`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, licenseKey: user.licenseKey, deviceId }),
  }).catch(() => null);

  if (!licResp) return res.status(502).json({ ok:false, message:"license_server_unreachable" });

  const licJson = await licResp.json().catch(() => ({}));
  if (!licResp.ok || !licJson.Allowed) {
    if ((licJson.message || "").toLowerCase().includes("expired")) {
      return res.status(403).json({ ok:false, message:"license_expired" });
    }
    if ((licJson.message || "").toLowerCase().includes("device mismatch")) {
      return res.status(403).json({ ok:false, message:"hwid_mismatch" });
    }
    if ((licJson.message || "").toLowerCase().includes("username mismatch")) {
      return res.status(403).json({ ok:false, message:"username_invalid" });
    }
    return res.status(403).json({ ok:false, message:"license_invalid" });
  }

  return res.json({ ok: true, expiresAt: licJson.expiresAt || null });
});

// ============ Start ============
const PORT = process.env.PORT || 10000;
const PUBLIC_BASE = process.env.PUBLIC_BASE_URL || `http://127.0.0.1:${PORT}`;

app.listen(PORT, "0.0.0.0", () => console.log(`Server listening on ${PORT} (PUBLIC_BASE=${PUBLIC_BASE})`));

// ============ Keep-alive ============
const KEEPALIVE_URLS = [
  "https://hwid-servers.onrender.com"
];
const KEEPALIVE_INTERVAL_MS = 2 * 60 * 1000;
const KEEPALIVE_TIMEOUT_MS = 5000;

app.get("/keepalive", (req, res) => {
  res.status(200).json({ ok: true, ts: new Date().toISOString() });
});

async function pingOnce(url) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), KEEPALIVE_TIMEOUT_MS);
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
