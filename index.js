// index.js — License backend: username + licenseKey + HWID + duration (HAMSTER-<ND>-...)
// Node 18+, Express, Firebase Admin

require("dotenv").config();
const express = require("express");
const fs = require("fs");
const path = require("path");
const admin = require("firebase-admin");

// ---------- Credentials (file or ENV) ----------
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

// ---------- App ----------
const app = express();
app.use(express.json());

// Healthcheck
app.get("/", (req, res) => {
  res.status(200).send("License server OK ✅");
});

// Helpers
function parseDurationDaysFromKey(licenseKey) {
  // dopasowuje np. HAMSTER-7D-XXXX, HAMSTER-30D-XXXX, HAMSTER-90D-XXXX
  const m = /^HAMSTER-(\d+)D-/i.exec(String(licenseKey || "").trim());
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function toDate(val) {
  // Firestore Timestamp -> Date
  if (!val) return null;
  return typeof val.toDate === "function" ? val.toDate() : new Date(val);
}

// ---------- Main endpoint ----------
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

    // 1) aktywność
    if (lic.active === false) {
      return res.status(403).json({
        Allowed: false,
        message: "License inactive",
      });
    }

    // 2) okres ważności na podstawie prefiksu HAMSTER-<ND>-
    const days = parseDurationDaysFromKey(key);
    if (days) {
      // jeśli mamy activatedAt, licz datę wygaśnięcia i sprawdź
      const activatedAt = toDate(lic.activatedAt || lic.firstActivatedAt);
      if (activatedAt) {
        const expiresAt = new Date(activatedAt.getTime());
        expiresAt.setDate(expiresAt.getDate() + days);

        if (new Date() > expiresAt) {
          // możesz też dezaktywować dokument
          await licRef.set({ active: false, expiredAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
          return res.status(403).json({
            Allowed: false,
            message: `License expired after ${days} days`,
            expiresAt: expiresAt.toISOString(),
          });
        }
      }
    }

    // 3) pierwsze logowanie -> przypnij HWID i zapisz activatedAt
    if (!lic.hwid) {
      const now = admin.firestore.FieldValue.serverTimestamp();
      await licRef.set(
        {
          hwid: deviceId,
          ownerUsername: username,
          activatedAt: lic.activatedAt || now, // ustaw tylko raz
          firstActivatedAt: lic.firstActivatedAt || now,
          lastLoginAt: now,
          durationDays: lic.durationDays || days || null, // informacyjnie
        },
        { merge: true }
      );

      await licRef.collection("accessLogs").add({
        type: "first_activation",
        username,
        deviceId,
        timestamp: now,
      });

      // policz expiresAt do odpowiedzi (jeśli znamy days)
      let expiresAtISO = null;
      if (days) {
        const start = new Date();
        const a = toDate(lic.activatedAt) || start;
        const ex = new Date(a.getTime());
        ex.setDate(ex.getDate() + days);
        expiresAtISO = ex.toISOString();
      }

      return res.status(200).json({
        Allowed: true,
        message: "License bound to this device (first login)",
        durationDays: days || null,
        expiresAt: expiresAtISO,
      });
    }

    // 4) kolejne logowania -> HWID musi pasować
    if (lic.hwid === deviceId) {
      await licRef.set(
        { ownerUsername: username, lastLoginAt: admin.firestore.FieldValue.serverTimestamp() },
        { merge: true }
      );

      // (opcjonalnie) policz expiresAt do odpowiedzi
      let expiresAtISO = null;
      if (days && lic.activatedAt) {
        const ex = new Date(toDate(lic.activatedAt).getTime());
        ex.setDate(ex.getDate() + days);
        expiresAtISO = ex.toISOString();
      }

      return res.status(200).json({
        Allowed: true,
        message: "Login OK",
        durationDays: days || null,
        expiresAt: expiresAtISO,
      });
    }

    // 5) inne urządzenie
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

// ---------- Start ----------
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => console.log(`License server listening on ${PORT}`));

// ---------- Keep-alive (Render / Railway) ----------
const SELF_URL = process.env.SELF_URL || "";
if (SELF_URL) {
  setInterval(async () => {
    try {
      const r = await fetch(SELF_URL);
      console.log(`[KEEP-ALIVE] ${new Date().toISOString()} status=${r.status}`);
    } catch (e) {
      console.error(`[KEEP-ALIVE] ${new Date().toISOString()} error=${e.message}`);
    }
  }, 2 * 60 * 1000);
}

