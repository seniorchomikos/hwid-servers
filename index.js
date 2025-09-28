const express = require("express")
const admin = require("firebase-admin")
const app = express()
app.use(express.json())

// Wklej tutaj pobrany plik JSON z Firebase Service Account
const serviceAccount = require("./serviceAccountKey.json")

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
})
const db = admin.firestore()

app.post("/verifyDevice", async (req, res) => {
  const { uid, deviceId } = req.body
  try {
    const userDoc = await db.collection("users").doc(uid).get()
    const userData = userDoc.data() || {}

    if (!userData.deviceId) {
      await db.collection("users").doc(uid).set({deviceId: deviceId}, {merge: true})
      return res.json({allowed: true})
    }

    if (userData.deviceId === deviceId) {
      return res.json({allowed: true})
    }

    await admin.auth().revokeRefreshTokens(uid)
    return res.status(403).json({allowed: false})
  } catch (err) {
    res.status(500).json({error: err.message})
  }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
