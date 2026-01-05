// firebase-config.js — FINAL VERSION (Railway + Firebase Admin)
const admin = require("firebase-admin");

// WAJIB: Railway hanya pakai ENV, tidak ada file JSON
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  throw new Error("FIREBASE_SERVICE_ACCOUNT environment variable is not set");
}

// Decode Base64 service account
let serviceAccount;
try {
  serviceAccount = JSON.parse(
    Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT, "base64").toString("utf8")
  );
} catch (err) {
  throw new Error("Failed to parse FIREBASE_SERVICE_ACCOUNT Base64 JSON");
}

// Init Firebase Admin (hindari double init)
if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();
const auth = admin.auth();

db.settings({
  ignoreUndefinedProperties: true,
});

module.exports = {
  admin,
  db,
  auth,
};
