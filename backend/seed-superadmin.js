/**
 * Seed Superadmin Account
 * Run once: node seed-superadmin.js
 */

require("dotenv").config();
const bcrypt = require("bcryptjs");
const admin = require("firebase-admin");

/* =========================
   FIREBASE INIT
========================= */
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const BASE_PATH = "artifacts/digital-backend-prod/public/data";

/* =========================
   CONFIG SUPERADMIN
========================= */
const SUPERADMIN_USERNAME = "Superadmin";
const SUPERADMIN_PASSWORD = "Digital@super2026";

/* =========================
   SEED FUNCTION
========================= */
(async () => {
  try {
    const existing = await db
      .collection(`${BASE_PATH}/admin_user`)
      .where("username", "==", SUPERADMIN_USERNAME)
      .limit(1)
      .get();

    if (!existing.empty) {
      console.log("⚠️ Superadmin already exists. Abort.");
      process.exit(0);
    }

    const hashedPassword = await bcrypt.hash(SUPERADMIN_PASSWORD, 10);

    await db.collection(`${BASE_PATH}/admin_user`).add({
      username: SUPERADMIN_USERNAME,
      password: hashedPassword,
      role: "superadmin",
      isActive: true,
      permissions: ["view", "edit", "delete"],
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: "system",
      lastLogin: null,
    });

    console.log("✅ Superadmin created successfully.");
    process.exit(0);
  } catch (err) {
    console.error("❌ Failed to seed Superadmin:", err);
    process.exit(1);
  }
})();
