/**
 * Paddle v2 Webhook Receiver
 * POST /api/paddle-webhook
 *
 * Verifies the HMAC-SHA256 signature from Paddle, then routes
 * subscription lifecycle events to update the user's premium status
 * in Firebase Firestore.
 */

const crypto = require("crypto");
const { db } = require("../lib/firebase");

/* ─────────────────────────────────────────────
    Vercel Serverless Configuration
   ───────────────────────────────────────────── */

// CRITICAL: Tells Vercel to bypass automatic body parsing so we can get the true byte-perfect stream
export const config = {
  api: {
    bodyParser: false,
  },
};

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
    if (isNaN(eventAge) || Math.abs(eventAge) > 300) {
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

/**
 * Reads the raw unparsed network request bytes straight from the buffer stream.
 */
async function getRawBody(req) {
  if (typeof req.body === "string" && !req.readable) {
    return req.body; // Fallback if parsed elsewhere
  }

  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

/* ─────────────────────────────────────────────
    Firestore Helpers
   ───────────────────────────────────────────── */

/**
 * Upsert the user's subscription state in Firestore.
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
    const requestId = req.headers["x-vercel-id"] || "unknown";

    // 1. Get the raw unparsed network body stream
    const rawBody = await getRawBody(req);

    // 2. Verify Paddle signature
    const signature = req.headers["paddle-signature"];
    const secret = process.env.PADDLE_WEBHOOK_SECRET;

    if (!secret) {
      console.error("[paddle-webhook] Missing PADDLE_WEBHOOK_SECRET", { requestId });
      return res.status(500).json({ error: "Webhook secret not configured" });
    }

    if (!rawBody) {
      console.warn("[paddle-webhook] Empty body received", { requestId });
      return res.status(400).json({ error: "Empty request body" });
    }

    console.log("[paddle-webhook] Incoming request", {
      requestId,
      hasSignature: Boolean(signature),
      bodyLength: rawBody.length,
    });

    if (!verifyPaddleSignature(rawBody, signature, secret)) {
      console.warn("[paddle-webhook] Invalid signature — rejecting", { requestId });
      return res.status(403).json({ error: "Invalid signature" });
    }

    // 3. SECURE CHANGE: Parse rawBody since Vercel's automatic parsing is now disabled
    const event = JSON.parse(rawBody);
    const eventType = event.event_type;
    const eventId = event.event_id;
    const data = event.data || {};

    console.log(`[paddle-webhook] Received verified event: ${eventType} (${eventId})`);

    // 4. Extract userId from customData
    const customData = data.custom_data || {};
    const userId = customData.userId || customData.user_id || null;

    if (!userId) {
      console.warn("[paddle-webhook] No userId in custom_data", {
        requestId,
        eventType,
        eventId,
        customData,
      });
      return res.status(200).json({ received: true, warning: "no userId" });
    }

    console.log("[paddle-webhook] Firestore write start", {
      requestId,
      eventType,
      eventId,
      userId,
    });

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

      case "subscription.updated": {
        const isActive = ["active", "trialing"].includes(data.status);
        await updateUserSubscription(userId, {
          isPremium: isActive,
          subscriptionId: data.id || null,
          subscriptionStatus: data.status || "unknown",
          paddleEventId: eventId,
        });
        break;
      }

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

    console.log("[paddle-webhook] Firestore write done", {
      requestId,
      eventType,
      eventId,
      userId,
    });

    return res.status(200).json({ received: true, eventType });
  } catch (err) {
    console.error("[paddle-webhook] Handler error:", err);
    return res.status(200).json({ received: true, error: "internal" });
  }
};