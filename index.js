// index.js
const express = require("express");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const fetch = require("node-fetch"); // <--- dodane

// Wczytanie serviceAccountKey.json lub ENV var
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

// Inicjalizacja Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const app = express();
app.use(bodyParser.json());

// Endpoint weryfikacji urządzenia i zapis email + HWID
app.post("/verifyDevice", async (req, res) => {
  const { uid, deviceId, email } = req.body || {};

  if (!uid || !deviceId || !email) {
    return res.status(400).json({ Allowed: false, message: "Missing uid, deviceId or email" });
  }

  try {
    // Sprawdzenie, czy użytkownik istnieje w Auth
    try {
      await admin.auth().getUser(uid);
    } catch (err) {
      return res.status(400).json({ Allowed: false, message: "User not found in Auth" });
    }

    const userRef = db.collection("users").doc(uid);
    const doc = await userRef.get();

    if (!doc.exists) {
      // Pierwsze logowanie: tworzymy dokument i zapisujemy deviceId + email
      await userRef.set({
        deviceId: deviceId,
        email: email,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
      return res.status(200).json({ Allowed: true, message: "Device registered (first login)" });
    }

    const userData = doc.data() || {};

    // Aktualizacja email jeśli się zmienił
    if (userData.email !== email) {
      await userRef.update({
        email: email,
        lastEmailUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    // Zapis deviceId jeśli brak
    if (!userData.deviceId) {
      await userRef.update({
        deviceId: deviceId,
        lastRegisteredAt: admin.firestore.FieldValue.serverTimestamp()
      });
      return res.status(200).json({ Allowed: true, message: "Device registered" });
    }

    // Sprawdzenie zgodności HWID
    if (userData.deviceId === deviceId) {
      return res.status(200).json({ Allowed: true, message: "Device authorized" });
    }

    // Nie pasuje HWID -> blokada
    await admin.auth().revokeRefreshTokens(uid);
    await userRef.collection("accessLogs").add({
      type: "unauthorized_device_attempt",
      attemptedDeviceId: deviceId,
      emailAttempted: email,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.status(403).json({ Allowed: false, message: "Device mismatch" });

  } catch (err) {
    console.error("verifyDevice error:", err);
    return res.status(500).json({ Allowed: false, message: "Server error" });
  }
});

// Start serwera
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => console.log(`HWID server listening on ${PORT}`));

// 🔥 KEEP ALIVE PING co 4 minuty
const SELF_URL = process.env.SELF_URL || `https://twoja-aplikacja-na-render.onrender.com`;

setInterval(async () => {
  try {
    const resp = await fetch(SELF_URL);
    console.log(`[KEEP-ALIVE] ${new Date().toISOString()} - Ping status: ${resp.status}`);
  } catch (err) {
    console.error(`[KEEP-ALIVE] ${new Date().toISOString()} - Error pinging self:`, err.message);
  }
}, 4 * 60 * 1000);
