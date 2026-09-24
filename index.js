const express = require("express");
const admin = require("firebase-admin");
const { randomInt } = require("node:crypto");

const app = express();
app.use(express.json({ limit: "8kb" }));

let db;
function getDb() {
  if (db) return db;
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw || raw === "undefined") throw new Error("FIREBASE_SERVICE_ACCOUNT no configurado");
  const json = raw.trim().startsWith("{") ? raw : Buffer.from(raw, "base64").toString("utf8");
  if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(JSON.parse(json)) });
  db = admin.firestore();
  return db;
}

class RequestError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function linkedIds(user = {}) {
  return [...new Set([...(user.linkedAbuelos || []), ...(user.linkedProtectors || [])])];
}

async function authenticate(req, res, next) {
  try {
    getDb();
    const match = /^Bearer (.+)$/.exec(req.get("Authorization") || "");
    if (!match) throw new RequestError(401, "Sesión requerida");
    try {
      req.uid = (await admin.auth().verifyIdToken(match[1])).uid;
    } catch (_) {
      throw new RequestError(401, "Sesión inválida o vencida");
    }
    next();
  } catch (error) {
    next(error);
  }
}

app.get("/", async (req, res) => {
  try {
    await getDb().collection("users").limit(1).get();
    res.json({ status: "ok", service: "atrox-fcm-backend" });
  } catch (error) {
    console.error("Health check falló:", error);
    res.status(503).json({ status: "unavailable" });
  }
});

app.post("/pairing-codes", authenticate, async (req, res, next) => {
  try {
    const firestore = getDb();
    const sponsorRef = firestore.collection("users").doc(req.uid);
    for (let attempt = 0; attempt < 10; attempt++) {
      const code = randomInt(100000, 1000000).toString();
      const codeRef = firestore.collection("pairing_codes").doc(code);
      const created = await firestore.runTransaction(async tx => {
        const [sponsorSnap, existing] = await Promise.all([tx.get(sponsorRef), tx.get(codeRef)]);
        if (!sponsorSnap.exists) throw new RequestError(404, "Cuenta no encontrada");
        const sponsor = sponsorSnap.data();
        if (!["PERSONAL", "COMMERCE"].includes(sponsor.planTier))
          throw new RequestError(403, "Necesitás un plan Personal o Comerciante");
        const max = sponsor.maxDevices || (sponsor.planTier === "PERSONAL" ? 1 : 3);
        if (linkedIds(sponsor).length >= max) throw new RequestError(409, "Límite de dispositivos alcanzado");
        if (existing.exists) return false;
        const now = Date.now();
        tx.create(codeRef, { code, sponsorUid: req.uid, createdAt: now, expiresAt: now + 600000 });
        return true;
      });
      if (created) return res.json({ code });
    }
    throw new RequestError(503, "No se pudo generar un código. Reintentá.");
  } catch (error) { next(error); }
});

app.post("/pairing-codes/redeem", authenticate, async (req, res, next) => {
  try {
    const { code, alias } = req.body;
    if (!/^\d{6}$/.test(code) || typeof alias !== "string" || !alias.trim() || alias.trim().length > 30)
      throw new RequestError(400, "Ingresá tu nombre y un código de 6 dígitos");
    const firestore = getDb();
    const protectedRef = firestore.collection("users").doc(req.uid);
    const codeRef = firestore.collection("pairing_codes").doc(code);
    const sponsorUid = await firestore.runTransaction(async tx => {
      const [protectedSnap, codeSnap] = await Promise.all([tx.get(protectedRef), tx.get(codeRef)]);
      if (!protectedSnap.exists) throw new RequestError(404, "Cuenta no encontrada");
      if (protectedSnap.get("planTier") !== "FREE")
        throw new RequestError(403, "Los administradores no pueden vincularse como protegidos");
      if (protectedSnap.get("sponsorUid")) throw new RequestError(409, "Ya tenés un protector vinculado");
      if (!codeSnap.exists || codeSnap.get("expiresAt") < Date.now())
        throw new RequestError(404, "Código inexistente o vencido");
      const sid = codeSnap.get("sponsorUid");
      if (sid === req.uid) throw new RequestError(400, "No podés vincularte a vos mismo");
      const sponsorRef = firestore.collection("users").doc(sid);
      const sponsorSnap = await tx.get(sponsorRef);
      if (!sponsorSnap.exists) throw new RequestError(404, "Protector no encontrado");
      const sponsor = sponsorSnap.data();
      if (!["PERSONAL", "COMMERCE"].includes(sponsor.planTier))
        throw new RequestError(403, "El protector no tiene plan de administrador");
      const linked = linkedIds(sponsor);
      const max = sponsor.maxDevices || (sponsor.planTier === "PERSONAL" ? 1 : 3);
      if (linked.length >= max) throw new RequestError(409, "El protector alcanzó su límite de dispositivos");
      const updated = [...linked, req.uid];
      tx.update(sponsorRef, { linkedAbuelos: updated, linkedProtectors: updated, maxDevices: max });
      tx.update(protectedRef, { sponsorUid: sid, alias: alias.trim() });
      tx.delete(codeRef);
      return sid;
    });
    res.json({ sponsorUid });
  } catch (error) { next(error); }
});

app.post("/links/unlink", authenticate, async (req, res, next) => {
  try {
    const { protectedUid } = req.body;
    if (typeof protectedUid !== "string" || !protectedUid) throw new RequestError(400, "Dispositivo requerido");
    const firestore = getDb();
    const sponsorRef = firestore.collection("users").doc(req.uid);
    const protectedRef = firestore.collection("users").doc(protectedUid);
    await firestore.runTransaction(async tx => {
      const [sponsorSnap, protectedSnap] = await Promise.all([tx.get(sponsorRef), tx.get(protectedRef)]);
      if (!sponsorSnap.exists || !linkedIds(sponsorSnap.data()).includes(protectedUid))
        throw new RequestError(403, "Ese dispositivo no está vinculado a tu cuenta");
      if (!["PERSONAL", "COMMERCE"].includes(sponsorSnap.get("planTier")))
        throw new RequestError(403, "Cuenta de administrador requerida");
      const updated = linkedIds(sponsorSnap.data()).filter(uid => uid !== protectedUid);
      tx.update(sponsorRef, { linkedAbuelos: updated, linkedProtectors: updated });
      // Si el usuario anónimo desapareció, igual libera el cupo sin crear un perfil vacío.
      if (protectedSnap.exists && protectedSnap.get("sponsorUid") === req.uid)
        tx.update(protectedRef, { sponsorUid: admin.firestore.FieldValue.delete(), alias: admin.firestore.FieldValue.delete() });
    });
    res.json({ success: true });
  } catch (error) { next(error); }
});

app.post("/links/leave", authenticate, async (req, res, next) => {
  try {
    const firestore = getDb();
    const protectedRef = firestore.collection("users").doc(req.uid);
    await firestore.runTransaction(async tx => {
      const protectedSnap = await tx.get(protectedRef);
      if (!protectedSnap.exists || !protectedSnap.get("sponsorUid"))
        throw new RequestError(404, "No tenés protector vinculado");
      const sponsorRef = firestore.collection("users").doc(protectedSnap.get("sponsorUid"));
      const sponsorSnap = await tx.get(sponsorRef);
      if (sponsorSnap.exists) {
        const updated = linkedIds(sponsorSnap.data()).filter(uid => uid !== req.uid);
        tx.update(sponsorRef, { linkedAbuelos: updated, linkedProtectors: updated });
      }
      tx.update(protectedRef, { sponsorUid: admin.firestore.FieldValue.delete(), alias: admin.firestore.FieldValue.delete() });
    });
    res.json({ success: true });
  } catch (error) { next(error); }
});

const allowedAlerts = new Set([
  "OTP_THEFT", "PASSWORD_REQUEST", "URGENCY_MANIPULATION", "FAKE_IDENTITY",
  "PHISHING_LINK", "MALWARE_APP", "SOCIAL_ENGINEERING", "FRAUD_CALL", "MONEY_REQUEST", "RECEIPT_FRAUD"
]);
app.post("/send-alert", authenticate, async (req, res, next) => {
  try {
    const { threatType } = req.body;
    if (!allowedAlerts.has(threatType)) throw new RequestError(400, "Tipo de alerta no permitido");
    const firestore = getDb();
    const protectedSnap = await firestore.collection("users").doc(req.uid).get();
    const sponsorUid = protectedSnap.get("sponsorUid");
    if (!protectedSnap.exists || protectedSnap.get("planTier") !== "FREE" || !sponsorUid)
      throw new RequestError(403, "Dispositivo no vinculado");
    const sponsorSnap = await firestore.collection("users").doc(sponsorUid).get();
    if (!sponsorSnap.exists || !linkedIds(sponsorSnap.data()).includes(req.uid))
      throw new RequestError(403, "Vínculo inválido");
    const token = sponsorSnap.get("fcmToken");
    if (!token) throw new RequestError(404, "Protector sin token de notificaciones");
    const alias = protectedSnap.get("alias") || "Tu familiar";
    const message = {
      token,
      notification: {
        title: `⚠️ ${alias} detectó una amenaza`,
        body: `Se detectó: ${threatType}. Revisá la protección de tu familiar.`
      },
      data: { type: "fraud_alert", alias, threatType, timestamp: Date.now().toString() },
      android: { priority: "high", notification: { channelId: "fraud_alerts", priority: "max" } }
    };
    const messageId = await admin.messaging().send(message);
    console.log(`FCM enviado OK: ${messageId}`);
    res.json({ success: true, messageId });
  } catch (error) { next(error); }
});

app.use((error, req, res, next) => {
  if (!(error instanceof RequestError)) console.error("Backend Atrox:", error);
  res.status(error.status || 500).json({ error: error instanceof RequestError ? error.message : "Error interno del servidor" });
});

if (require.main === module) {
  app.listen(process.env.PORT || 3000, () => console.log("Atrox FCM Backend listo"));
}

module.exports = { app, linkedIds };
