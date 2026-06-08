/**
 * Paddle v2 Webhook Receiver
 * POST /api/paddle-webhook
 *
 * Verifies the HMAC-SHA256 signature from Paddle, then routes
 * subscription lifecycle events to update the user's premium status
 * in Firebase Firestore.
 *
 * Handled events:
 *   - subscription.activated  → isPremium = true
 *   - subscription.updated    → isPremium based on status
 *   - subscription.canceled   → isPremium = false
 */

const crypto = require("crypto");
const { db } = require("../lib/firebase");

/* ─────────────────────────────────────────────
   Signature Verification
   ───────────────────────────────────────────── */

/**
 * Verify the Paddle-Signature header using HMAC-SHA256.
 * @param {string} rawBody  — The raw, unparsed request body string.
 * @param {string} signature — The Paddle-Signature header value.
 * @param {string} secret   — Your PADDLE_WEBHOOK_SECRET.
 * @returns {boolean}
 */
function verifyPaddleSignature(rawBody, signature, secret) {
  if (!signature || !secret) return false;

  try {
    // Header format: ts=<timestamp>;h1=<hash>
    const parts = signature.split(";");
    const tsPart = parts.find((p) => p.startsWith("ts="));
    const h1Part = parts.find((p) => p.startsWith("h1="));

    if (!tsPart || !h1Part) return false;

    const ts = tsPart.split("=")[1];
    const h1 = h1Part.split("=")[1];

    if (!ts || !h1) return false;

    // Replay attack prevention — reject events older than 5 minutes
    const eventAge = Math.floor(Date.now() / 1000) - parseInt(ts, 10);
    if (isNaN(eventAge) || eventAge > 300) {
      console.warn("[paddle-webhook] Rejected: timestamp too old", { eventAge });
      return false;
    }

    // Compute HMAC-SHA256
    const signedPayload = `${ts}:${rawBody}`;
    const computed = crypto
      .createHmac("sha256", secret)
      .update(signedPayload)
      .digest("hex");

    // Timing-safe comparison
    if (computed.length !== h1.length) return false;
    return crypto.timingSafeEqual(
      Buffer.from(computed, "hex"),
      Buffer.from(h1, "hex")
    );
  } catch (err) {
    console.error("[paddle-webhook] Signature verification error:", err.message);
    return false;
  }
}

/* ─────────────────────────────────────────────
   Firestore Helpers
   ───────────────────────────────────────────── */

/**
 * Upsert the user's subscription state in Firestore.
 * Uses set-with-merge so we never lose data on out-of-order events.
 */
async function updateUserSubscription(userId, data) {
  if (!userId) {
    console.error("[paddle-webhook] No userId in customData — cannot update");
    return;
  }

  const docRef = db.collection("users").doc(userId);
  await docRef.set(
    {
      ...data,
      updatedAt: new Date().toISOString(),
    },
    { merge: true }
  );

  console.log(`[paddle-webhook] Updated user ${userId}:`, data);
}

/* ─────────────────────────────────────────────
   Request Handler
   ───────────────────────────────────────────── */

module.exports = async function handler(req, res) {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // Only accept POST
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    // 1. Get the raw body for signature verification
    //    Vercel provides req.body as parsed JSON by default.
    //    We need the raw body string for HMAC computation.
    const rawBody =
      typeof req.body === "string" ? req.body : JSON.stringify(req.body);

    // 2. Verify Paddle signature
    const signature = req.headers["paddle-signature"];
    const secret = process.env.PADDLE_WEBHOOK_SECRET;

    if (!verifyPaddleSignature(rawBody, signature, secret)) {
      console.warn("[paddle-webhook] Invalid signature — rejecting");
      return res.status(403).json({ error: "Invalid signature" });
    }

    // 3. Parse the event
    const event = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
    const eventType = event.event_type;
    const eventId = event.event_id;
    const data = event.data || {};

    console.log(`[paddle-webhook] Received: ${eventType} (${eventId})`);

    // 4. Extract userId from customData
    const customData = data.custom_data || {};
    const userId = customData.userId || customData.user_id || null;

    if (!userId) {
      console.warn("[paddle-webhook] No userId in custom_data:", customData);
      // Still return 200 to Paddle to avoid retries
      return res.status(200).json({ received: true, warning: "no userId" });
    }

    // 5. Route by event type
    switch (eventType) {
      case "subscription.activated":
      case "subscription.resumed":
        await updateUserSubscription(userId, {
          isPremium: true,
          subscriptionId: data.id || null,
          subscriptionStatus: data.status || "active",
          customerId: data.customer_id || null,
          paddleEventId: eventId,
        });
        break;

      case "subscription.updated":
        // Check the new status — "active", "trialing", "past_due", "paused", "canceled"
        const isActive = ["active", "trialing"].includes(data.status);
        await updateUserSubscription(userId, {
          isPremium: isActive,
          subscriptionId: data.id || null,
          subscriptionStatus: data.status || "unknown",
          paddleEventId: eventId,
        });
        break;

      case "subscription.canceled":
      case "subscription.past_due":
      case "subscription.paused":
        await updateUserSubscription(userId, {
          isPremium: false,
          subscriptionStatus: data.status || "canceled",
          paddleEventId: eventId,
        });
        break;

      default:
        console.log(`[paddle-webhook] Unhandled event type: ${eventType}`);
    }

    // 6. Always return 200 to Paddle
    return res.status(200).json({ received: true, eventType });
  } catch (err) {
    console.error("[paddle-webhook] Handler error:", err);
    // Return 200 even on errors to prevent Paddle retry storms
    return res.status(200).json({ received: true, error: "internal" });
  }
};
