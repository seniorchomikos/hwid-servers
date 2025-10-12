// index.js — wersja z username + licenseKey + HWID

const express = require("express");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const fetch = require("node-fetch");

// 🔸 Wczytaj service account (plik lub ENV)
const serviceAccountPath = path.join(__dirname, "serviceAccountKey.json");
let serviceAccount = null;

if (fs.existsSync(serviceAccountPath)) {
  serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));
} else if (process.env.SERVICE_ACCOUNT_JSON) {
  serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_JSON);
} else {
  console.error("❌ Brak credentials: dodaj serviceAccountKey.json lub zmienną SERVICE_ACCOUNT_JSON");
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

const app = express();
app.use(bodyParser.json());

// ✅ Healthcheck
app.get("/", (req, res) => {
  res.status(200).send("License server OK ✅");
});

// ✅ Endpoint logowania
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

    // 🔸 Sprawdź aktywność
    if (lic.active === false) {
      return res.status(403).json({
        Allowed: false,
        message: "License inactive",
      });
    }

    // 🔸 Pierwsze logowanie — przypnij HWID
    if (!lic.hwid) {
      await licRef.set(
        {
          hwid: deviceId,
          ownerUsername: username,
          firstActivatedAt: admin.firestore.FieldValue.serverTimestamp(),
          lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );

      await licRef.collection("accessLogs").add({
        type: "first_activation",
        username,
        deviceId,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
      });

      return res.status(200).json({
        Allowed: true,
        message: "License bound to this device (first login)",
      });
    }

    // 🔸 Kolejne logowania — sprawdź HWID
    if (lic.hwid === deviceId) {
      await licRef.set(
        {
          ownerUsername: username,
          lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );

      return res.status(200).json({
        Allowed: true,
        message: "Login OK",
      });
    }

    // 🔸 Inne urządzenie
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

// ✅ Start serwera
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => console.log(`License server listening on ${PORT}`));

// ✅ Keep-alive (Render)
const SELF_URL = process.env.SELF_URL || `https://twoj-serwer.onrender.com`;
setInterval(async () => {
  try {
    const resp = await fetch(SELF_URL);
    console.log(`[KEEP-ALIVE] ${new Date().toISOString()} - ${resp.status}`);
  } catch (err) {
    console.error(`[KEEP-ALIVE] ${new Date().toISOString()} - Error:`, err.message);
  }
}, 2 * 60 * 1000);
