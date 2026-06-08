/**
 * Firebase Admin SDK — Shared initialization module.
 *
 * Initializes Firebase from the FIREBASE_SERVICE_ACCOUNT environment variable
 * (expects the full JSON service-account key as a string).
 * Exports the Firestore database reference used by all API functions.
 */

const admin = require("firebase-admin");

// Singleton guard — Vercel may reuse the module across invocations
if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();

module.exports = { db, admin };
