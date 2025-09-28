// index.js (poprawiona wersja)
const express = require("express");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");

// Jeśli używasz serviceAccountKey.json w repo, wczytaj go:
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

// Endpoint weryfikacji urządzenia
app.post("/verifyDevice", async (req, res) => {
  const { uid, deviceId } = req.body || {};

  if (!uid || !deviceId) {
    return res.status(400).json({ Allowed: false, message: "Missing uid or deviceId" });
  }

  try {
    // Opcjonalnie: sprawdź, że użytkownik istnieje w Auth (może być pominięte,
    // ale lepiej mieć tę weryfikację)
    try {
      await admin.auth().getUser(uid);
    } catch (err) {
      return res.status(400).json({ Allowed: false, message: "User not found in Auth" });
    }

    const userRef = db.collection("users").doc(uid);
    const doc = await userRef.get();

    // Jeśli dokument użytkownika nie istnieje -> utwórz i zarejestruj deviceId
    if (!doc.exists) {
      await userRef.set({
        deviceId: deviceId,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
      return res.status(200).json({ Allowed: true, message: "Device registered (new user)" });
    }

    const userData = doc.data() || {};

    // Jeśli dokument istnieje, ale brak deviceId -> zarejestruj
    if (!userData.deviceId) {
      await userRef.update({
        deviceId: deviceId,
        lastRegisteredAt: admin.firestore.FieldValue.serverTimestamp()
      });
      return res.status(200).json({ Allowed: true, message: "Device registered" });
    }

    // Jeśli deviceId pasuje -> pozwól
    if (userData.deviceId === deviceId) {
      return res.status(200).json({ Allowed: true, message: "Device authorized" });
    }

    // Jeśli deviceId nie pasuje -> blokuj i unieważnij refresh tokeny
    await admin.auth().revokeRefreshTokens(uid);
    // opcjonalnie: zapisz log nieautoryzowanego dostępu
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`HWID server listening on ${PORT}`));
