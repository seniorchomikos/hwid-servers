const express = require("express");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");

// 1️⃣ Wczytanie pliku serviceAccountKey.json
const serviceAccountPath = path.join(__dirname, "serviceAccountKey.json");
const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));

// 2️⃣ Inicjalizacja Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// 3️⃣ Stworzenie serwera Express
const app = express();
app.use(bodyParser.json());

// 4️⃣ Endpoint do weryfikacji HWID
app.post("/verifyDevice", async (req, res) => {
  const { uid, deviceId } = req.body;

  if (!uid || !deviceId) {
    return res.status(400).json({ allowed: false, message: "Brak uid lub deviceId" });
  }

  try {
    const userRef = db.collection("users").doc(uid);
    const doc = await userRef.get();

    if (!doc.exists) {
      return res.status(404).json({ allowed: false, message: "Użytkownik nie istnieje" });
    }

    const userData = doc.data();

    if (!userData.deviceId) {
      // zapisujemy HWID przy pierwszym logowaniu
      await userRef.update({ deviceId });
      return res.json({ allowed: true });
    } else if (userData.deviceId === deviceId) {
      return res.json({ allowed: true });
    } else {
      return res.json({ allowed: false, message: "Nieautoryzowane urządzenie" });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ allowed: false, message: "Błąd serwera" });
  }
});

// 5️⃣ Start serwera
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`HWID server działa na porcie ${PORT}`);
});
