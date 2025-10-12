// index.js — licencje: email + licenseKey + HWID, bez UID

const express = require("express");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const fetch = require("node-fetch"); // keep-alive ping

// === Poświadczenia Firebase Admin (ENV lub plik) ===
const serviceAccountPath = path.join(__dirname, "serviceAccountKey.json");
let serviceAccount = null;

if (fs.existsSync(serviceAccountPath)) {
  serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));
} else if (process.env.SERVICE_ACCOUNT_JSON) {
  serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_JSON);
} else {
  console.error("Brak credentials: dodaj serviceAccountKey.json lub SERVICE_ACCOUNT_JSON env var.");
  process.exit(1);
}

// === Inicjalizacja Admin SDK + Firestore ===
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

// === App ===
const app = express();
app.use(bodyParser.json());

// Healthcheck / keep-alive
app.get("/", (req, res) => {
  res.status(200).send("License server is running ✅");
});

// ======================================================================
//  POST /licenseLogin
//  Body: { email: string, licenseKey: string, deviceId: string }   (deviceId = HWID)
//  Logika:
//   1) Pobierz dokument licenses/{licenseKey}. Jeśli nie ma → 403 "Invalid license key".
//   2) Jeśli active === false → 403 "License inactive".
//   3) Jeśli brak hwid → pierwsze logowanie: zapisz hwid, ownerEmail, znaczniki czasu → 200 Allowed.
//   4) Jeśli hwid == deviceId → update lastLoginAt (+opcjonalnie ownerEmail) → 200 Allowed.
//   5) Inaczej → 403 "Device mismatch", dopisz log do subkolekcji accessLogs.
//
//  Struktura dokumentu licenses/{licenseKey} (przykład):
//   {
//     active: true,
//     hwid?: "MACHINE-GUID...",
//     ownerEmail?: "kupujacy@domena.pl",
//     firstActivatedAt?: <timestamp>,
//     lastLoginAt?: <timestamp>
//   }
// ======================================================================
app.post("/licenseLogin", async (req, res) => {
  const { email, licenseKey, deviceId } = req.body || {};

  // Walidacja wejścia
  if (!email || !licenseKey || !deviceId) {
    return res.status(400).json({
      Allowed: false,
      message: "Missing email, licenseKey or deviceId",
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

    // Aktywność licencji
    if (lic.active === false) {
      return res.status(403).json({
        Allowed: false,
        message: "License inactive",
      });
    }

    // Pierwsze logowanie → przypnij HWID do licencji
    if (!lic.hwid) {
      await licRef.set(
        {
          hwid: deviceId,
          ownerEmail: email,
          firstActivatedAt: admin.firestore.FieldValue.serverTimestamp(),
          lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );

      await licRef.collection("accessLogs").add({
        type: "first_activation",
        email,
        deviceId,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
      });

      return res.status(200).json({
        Allowed: true,
        message: "License bound to this device (first login)",
      });
    }

    // Kolejne logowania → HWID musi się zgadzać
    if (lic.hwid === deviceId) {
      await licRef.set(
        {
          ownerEmail: email, // aktualizuj (opcjonalnie)
          lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );

      return res.status(200).json({
        Allowed: true,
        message: "Login OK",
      });
    }

    // HWID nie pasuje
    await licRef.collection("accessLogs").add({
      type: "hwid_mismatch",
      email,
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

// === Start serwera ===
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => console.log(`License server listening on ${PORT}`));

// === KEEP ALIVE co 2 min (np. Render/railway) ===
const SELF_URL = process.env.SELF_URL || `https://hwid-servers.onrender.com`;
setInterval(async () => {
  try {
    const resp = await fetch(SELF_URL);
    console.log(`[KEEP-ALIVE] ${new Date().toISOString()} - Ping status: ${resp.status}`);
  } catch (err) {
    console.error(`[KEEP-ALIVE] ${new Date().toISOString()} - Error pinging self:`, err.message);
  }
}, 2 * 60 * 1000);
