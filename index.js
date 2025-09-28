// index.js (poprawiona wersja)
const express = require("express");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");

// Wczytanie serviceAccountKey.json
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

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const app = express();
app.use(bodyParser.json());

app.post("/verifyDevice", async (req, res) => {
  const { uid, deviceId } = req.body || {};

  if (!uid || !deviceId) {
    return res.status(400).json({ Allowed: false, message: "Missing uid or deviceId" });
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
      // Pierwsze logowanie: tworzymy dokument i zapisujemy deviceId
      await userRef.set({
        deviceId: deviceId,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
      return res.status(200).json({ Allowed: true, message: "Device registered (first login)" });
    }

    const userData = doc.data() || {};

    if (!userData.deviceId) {
      // Brak zapisanej tablicy deviceId -> zapisujemy
      await userRef.update({
        deviceId: deviceId,
        lastRegisteredAt: admin.firestore.FieldValue.serverTimestamp()
      });
      return res.status(200).json({ Allowed: true, message: "Device registered" });
    }

    if (userData.deviceId === deviceId) {
      // Pasuje HWID
      return res.status(200).json({ Allowed: true, message: "Device authorized" });
    }

    // Nie pasuje HWID -> blokada
    await admin.auth().revokeRefreshTokens(uid);
    await db.collection("users").doc(uid).collection("accessLogs").add({
      type: "unauthorized_device_attempt",
      attemptedDeviceId: deviceId,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.status(403).json({ Allowed: false, message: "Device mismatch" });

  } catch (err) {
    console.error("verifyDevice error:", err);
    return res.status(500).json({ Allowed: false, message: "Server error" });
  }
});

// Bind na 0.0.0.0 i port z Render env
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => console.log(`HWID server listening on ${PORT}`));
