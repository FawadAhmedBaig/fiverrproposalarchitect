/**
 * Firebase Admin SDK — Shared initialization module.
 *
 * Initializes Firebase from the FIREBASE_SERVICE_ACCOUNT environment variable
 * (expects the full JSON service-account key as a string).
 * Exports the Firestore database reference used by all API functions.
 */

const admin = require("firebase-admin");

if (!admin.apps.length) {
  // 1. Parse your environment variable string as JSON
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

  // 2. Fix the string-escaping issue for the PEM key format
  if (serviceAccount.private_key) {
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();
module.exports = { db, admin };
