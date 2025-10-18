// index.js — Backend: licencje + rejestracja/logowanie użytkowników (Firestore)
// Wersja self-contained: bez lokalnych fetchy, wszystko w 1 procesie.

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

// Wspólna funkcja: sprawdza/wiąże licencję.
// Zwraca { ok, code?, message?, expiresAt? }.
// code ∈ ["invalid","inactive","expired","hwid_mismatch","username_mismatch","ok"]
async function checkAndBindLicense({ username, licenseKey, deviceId }) {
  const key = String(licenseKey).trim();
  const licRef = db.collection("licenses").doc(key);
  const snap = await licRef.get();
  if (!snap.exists) return { ok: false, code: "invalid", message: "Invalid license key" };

  const lic = snap.data() || {};

  // 1) Czy wyłączona?
  if (lic.active === false) return { ok: false, code: "inactive", message: "License inactive" };

  // 2) Wygaśnięcie
  const days = parseDurationDaysFromKey(key);
  const expiresAt = lic.expiresAt ? toDate(lic.expiresAt) : null;

  if (days && expiresAt && new Date() > expiresAt) {
    await licRef.set({ active: false, expiredAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    return {
      ok: false,
      code: "expired",
      message: `License expired after ${days} days`,
      expiresAt: expiresAt.toISOString(),
    };
  }

  // 3) Pierwsza aktywacja — przypnij HWID i username, ustaw expiresAt
  if (!lic.hwid) {
    const now = admin.firestore.Timestamp.now();
    const calcExDate = days ? calcExpiresAt(new Date(), days) : null;

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

    return {
      ok: true,
      code: "ok",
      message: "License bound to this device (first login)",
      expiresAt: calcExDate ? calcExDate.toISOString() : null,
    };
  }

  // 4) HWID musi się zgadzać
  if (lic.hwid !== deviceId) {
    await licRef.collection("accessLogs").add({
      type: "hwid_mismatch",
      username,
      attemptedDeviceId: deviceId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
    return { ok: false, code: "hwid_mismatch", message: "Device mismatch" };
  }

  // 5) Username musi się zgadzać (klucz nie może być używany przez innego usera)
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

  // 6) OK — update lastLoginAt
  await licRef.set({ lastLoginAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

  return {
    ok: true,
    code: "ok",
    message: "Login OK",
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
  };
}

// ============ /licenseLogin ============
// (używane przez klienta oraz wewnętrznie przez /user/*)
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
        expiresAt: out.expiresAt || null,
      });
    }

    return res.status(200).json({
      Allowed: true,
      message: out.message,
      expiresAt: out.expiresAt || null,
    });
  } catch (err) {
    console.error("licenseLogin error:", err);
    return res.status(500).json({ Allowed: false, message: "Server error" });
  }
});

// ============ Users (Firestore) ============
function usersRef() { return db.collection("users"); } // zgodnie z obecnym plikiem :contentReference[oaicite:2]{index=2}

// /user/register — body: { username, password, deviceId, licenseKey }
// 1) sprawdza/przypina licencję (to też przypnie HWID+username przy 1. razie)
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

  // sprawdź/aktywuj licencję bezpośrednio (bez HTTP)
  const lic = await checkAndBindLicense({ username, licenseKey, deviceId });
  if (!lic.ok) {
    // te same mapowania co wcześniej
    const m = (lic.message || "").toLowerCase();
    if (m.includes("expired")) return res.status(403).json({ ok:false, message:"license_expired" });
    if (m.includes("device mismatch")) return res.status(403).json({ ok:false, message:"hwid_mismatch" });
    if (m.includes("username mismatch")) return res.status(403).json({ ok:false, message:"username_invalid" });
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

  return res.json({ ok: true, expiresAt: lic.expiresAt || null });
});

// /user/login — body: { username, password, deviceId }
// Sprawdza username, hasło (bcrypt), HWID, potem status licencji (bez HTTP)
app.post("/user/login", async (req, res) => {
  const { username, password, deviceId } = req.body || {};
  if (!username || !password || !deviceId) {
    return res.status(400).json({ ok: false, message: "missing_fields" });
  }

  const uref = usersRef().doc(String(username).toLowerCase());
  const usnap = await uref.get();
  if (!usnap.exists) return res.status(403).json({ ok:false, message:"username_invalid" });
  const user = usnap.data();

  // spójność username/hwid (tak miałeś) :contentReference[oaicite:3]{index=3}
  if (user.username !== username) return res.status(403).json({ ok:false, message:"username_invalid" });
  if (user.hwid !== deviceId) return res.status(403).json({ ok:false, message:"hwid_mismatch" });

  const ok = await bcrypt.compare(password, user.passHash || "");
  if (!ok) return res.status(403).json({ ok:false, message:"password_invalid" });

  // licencja (bezpośrednio)
  const lic = await checkAndBindLicense({ username, licenseKey: user.licenseKey, deviceId });
  if (!lic.ok) {
    const m = (lic.message || "").toLowerCase();
    if (m.includes("expired")) return res.status(403).json({ ok:false, message:"license_expired" });
    if (m.includes("device mismatch")) return res.status(403).json({ ok:false, message:"hwid_mismatch" });
    if (m.includes("username mismatch")) return res.status(403).json({ ok:false, message:"username_invalid" });
    return res.status(403).json({ ok:false, message:"license_invalid" });
  }

  return res.json({ ok: true, expiresAt: lic.expiresAt || null });
});

// ============ Start ============
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => console.log(`Server listening on ${PORT}`));
