const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

const app = express();
app.use(cors());
app.use(express.json());

// ─── FIREBASE ADMIN (lazy init) ──────────────────────────────────
let db = null;

function getDb() {
  if (db) return db;

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT env var not set");
  }

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch (e) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT is not valid JSON: " + e.message);
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });

  db = admin.firestore();
  return db;
}

// ─── HEALTH CHECK ────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "atrox-fcm-backend" });
});

// ─── ENVIAR ALERTA DE FRAUDE ─────────────────────────────────────
app.post("/send-alert", async (req, res) => {
  try {
    // 1. Validar API Key
    const apiKey = req.headers["x-api-key"];
    if (apiKey !== process.env.APP_API_KEY) {
      return res.status(401).json({ error: "No autorizado" });
    }

    // 2. Validar campos requeridos
    const { sponsorUid, alias, threatType } = req.body;
    if (!sponsorUid || !alias || !threatType) {
      return res.status(400).json({
        error: "Faltan campos requeridos: sponsorUid, alias, threatType",
      });
    }

    // 3. Conectar a Firestore
    const firestore = getDb();

    // 4. Buscar FCM token del sponsor
    const sponsorDoc = await firestore.collection("users").doc(sponsorUid).get();
    if (!sponsorDoc.exists) {
      return res.status(404).json({ error: "Sponsor no encontrado" });
    }

    const fcmToken = sponsorDoc.data().fcmToken;
    if (!fcmToken) {
      return res.status(404).json({ error: "Sponsor sin FCM token" });
    }

    // 5. Enviar notificación Push via FCM v1
    const message = {
      token: fcmToken,
      notification: {
        title: `\u26A0\uFE0F ${alias} detect\u00F3 una amenaza`,
        body: `Se bloque\u00F3: ${threatType}. Revis\u00E1 la protecci\u00F3n de tu familiar.`,
      },
      data: {
        type: "fraud_alert",
        alias: alias,
        threatType: threatType,
        timestamp: Date.now().toString(),
      },
      android: {
        priority: "high",
        notification: {
          channelId: "fraud_alerts",
          priority: "max",
        },
      },
    };

    const response = await admin.messaging().send(message);
    console.log(`FCM enviado OK: ${response}`);

    return res.status(200).json({ success: true, messageId: response });
  } catch (error) {
    console.error("Error en /send-alert:", error);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

// ─── START SERVER ────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Atrox FCM Backend corriendo en puerto ${PORT}`);
});
