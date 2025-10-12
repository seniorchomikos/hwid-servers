// index.js — License backend z obsługą okresu ważności i konfigurowalnym keep-alive

const express = require("express");
const fs = require("fs");
const path = require("path");
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

// ============ App setup ============
const app = express();
app.use(express.json());

// Healthcheck endpoint
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

// ============ License Login ============
app.post("/licenseLogin", async (req, res) => {
  const { username, licenseKey, deviceId } = req.body || {};

  if (!username || !licenseKey || !deviceId) {
    return res.status(400).json({
      Allowed: false,
      message: "Missing username, licenseKey or deviceId",
    });
  }

  const key = String(licenseKey).trim();
  const licRef = db.collection("licenses").doc(key);

  try {
    const licSnap = await licRef.get();
    if (!licSnap.exists) {
      return res.status(403).json({
        Allowed: false,
        message: "Invalid license key",
      });
    }

    const lic = licSnap.data() || {};

    // 1️⃣ Sprawdzenie aktywności
    if (lic.active === false) {
      return res.status(403).json({
        Allowed: false,
        message: "License inactive",
      });
    }

    // 2️⃣ Sprawdzenie okresu ważności z prefixu
    const days = parseDurationDaysFromKey(key);
    if (days) {
      const activatedAt = toDate(lic.activatedAt || lic.firstActivatedAt);
      if (activatedAt) {
        const expiresAt = new Date(activatedAt.getTime());
        expiresAt.setDate(expiresAt.getDate() + days);

        if (new Date() > expiresAt) {
          await licRef.set({ active: false, expiredAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
          return res.status(403).json({
            Allowed: false,
            message: `License expired after ${days} days`,
            expiresAt: expiresAt.toISOString(),
          });
        }
      }
    }

    // 3️⃣ Pierwsze logowanie — przypnij HWID i username
    if (!lic.hwid) {
      const now = admin.firestore.FieldValue.serverTimestamp();
      await licRef.set(
        {
          hwid: deviceId,
          ownerUsername: username,
          activatedAt: lic.activatedAt || now,
          firstActivatedAt: lic.firstActivatedAt || now,
          lastLoginAt: now,
          durationDays: lic.durationDays || days || null,
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
      });
    }

    // 4️⃣ Kolejne logowania — HWID musi pasować
    if (lic.hwid === deviceId) {
      await licRef.set(
        { ownerUsername: username, lastLoginAt: admin.firestore.FieldValue.serverTimestamp() },
        { merge: true }
      );

      return res.status(200).json({
        Allowed: true,
        message: "Login OK",
        durationDays: days || null,
      });
    }

    // 5️⃣ Inne urządzenie
    await licRef.collection("accessLogs").add({
      type: "hwid_mismatch",
      username,
      attemptedDeviceId: deviceId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.status(403).json({
      Allowed: false,
      message: "Device mismatch",
    });
  } catch (err) {
    console.error("licenseLogin error:", err);
    return res.status(500).json({ Allowed: false, message: "Server error" });
  }
});

// ============ Start serwera ============
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => console.log(`License server listening on ${PORT}`));

// ============ Keep-alive (własny URL) ============
/*
  Konfiguracja:
  - KEEPALIVE_URLS           - lista URL-i rozdzielona przecinkami (np. "https://twoj-projekt.onrender.com")
  - KEEPALIVE_INTERVAL_MS    - interwał pinga (domyślnie 120000 ms = 2 min)
  - KEEPALIVE_TIMEOUT_MS     - timeout jednego pinga (domyślnie 5000 ms)
*/

const urlsRaw = process.env.KEEPALIVE_URLS || process.env.SELF_URL || "";
const KEEPALIVE_URLS = urlsRaw
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

const KEEPALIVE_INTERVAL_MS = Number(process.env.KEEPALIVE_INTERVAL_MS || 120000);
const KEEPALIVE_TIMEOUT_MS = Number(process.env.KEEPALIVE_TIMEOUT_MS || 5000);

// pomocniczy endpoint do testu
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
  console.log(
    `[KEEP-ALIVE] enabled: ${KEEPALIVE_URLS.join(", ")} | interval=${KEEPALIVE_INTERVAL_MS}ms timeout=${KEEPALIVE_TIMEOUT_MS}ms`
  );

  (async () => {
    for (const u of KEEPALIVE_URLS) await pingOnce(u);
  })();

  setInterval(() => {
    KEEPALIVE_URLS.forEach(u => pingOnce(u));
  }, KEEPALIVE_INTERVAL_MS);
} else {
  console.log("[KEEP-ALIVE] disabled (set KEEPALIVE_URLS or SELF_URL to enable)");
}
