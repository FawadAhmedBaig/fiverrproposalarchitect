/**
 * User Status Endpoint
 * GET /api/user-status?userId=<email>
 *
 * Called by the Chrome extension's background service worker to check
 * whether a user has an active premium subscription.
 *
 * Returns:
 *   { isPremium: boolean, subscriptionId: string|null, status: string }
 */

const { db } = require("../lib/firebase");

module.exports = async function handler(req, res) {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // Only accept GET
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const userId = req.query.userId;

    if (!userId || typeof userId !== "string" || userId.length < 3) {
      return res.status(400).json({ error: "Missing or invalid userId parameter" });
    }

    // Sanitize: use the userId as a Firestore document ID
    // Firestore doc IDs can't contain '/' so we use the email directly
    const docRef = db.collection("users").doc(userId);
    const doc = await docRef.get();

    if (!doc.exists) {
      // User not found — they haven't purchased
      return res.status(200).json({
        isPremium: false,
        subscriptionId: null,
        status: "none",
      });
    }

    const data = doc.data();

    return res.status(200).json({
      isPremium: data.isPremium === true,
      subscriptionId: data.subscriptionId || null,
      status: data.subscriptionStatus || "unknown",
    });
  } catch (err) {
    console.error("[user-status] Error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};
