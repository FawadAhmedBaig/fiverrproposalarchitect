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
 * Best-effort raw body extraction for signature verification.
 * Paddle signatures are computed over the exact raw payload bytes.
 */
async function getRawBody(req) {
  if (typeof req.body === "string") {
    return req.body;
  }

  if (Buffer.isBuffer(req.body)) {
    return req.body.toString("utf8");
  }

  if (Buffer.isBuffer(req.rawBody)) {
    return req.rawBody.toString("utf8");
  }

  if (typeof req.rawBody === "string") {
    return req.rawBody;
  }

  // Fallback only; this may not always match original byte-for-byte payload.
  if (req.body && typeof req.body === "object") {
    return JSON.stringify(req.body);
  }

  if (!req.readable) {
    return "";
  }

  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return Buffer.concat(chunks).toString("utf8");
}

function parseEventFromRawBody(rawBody) {
  if (!rawBody) {
    return null;
  }

  if (typeof rawBody === "object") {
    return rawBody;
  }

  if (typeof rawBody === "string") {
    return JSON.parse(rawBody);
  }

  return null;
}

function summarizeSignature(signature) {
  if (!signature) {
    return null;
  }

  const summary = {};
  signature.split(";").forEach(function (part) {
    const index = part.indexOf("=");
    if (index > 0) {
      summary[part.slice(0, index)] = part.slice(index + 1).slice(0, 12);
    }
  });

  return summary;
}

function getWebhookSecretCandidates() {
  const environmentHint = String(process.env.PADDLE_ENVIRONMENT || process.env.VERCEL_ENV || "").toLowerCase();

  const candidates = [];
  if (environmentHint === "sandbox") {
    candidates.push(["PADDLE_WEBHOOK_SECRET_SANDBOX", process.env.PADDLE_WEBHOOK_SECRET_SANDBOX]);
  }
  if (environmentHint === "production") {
    candidates.push(["PADDLE_WEBHOOK_SECRET_LIVE", process.env.PADDLE_WEBHOOK_SECRET_LIVE]);
    candidates.push(["PADDLE_WEBHOOK_SECRET_PRODUCTION", process.env.PADDLE_WEBHOOK_SECRET_PRODUCTION]);
  }

  candidates.push(["PADDLE_WEBHOOK_SECRET", process.env.PADDLE_WEBHOOK_SECRET]);
  candidates.push(["PADDLE_WEBHOOK_SECRET_SANDBOX", process.env.PADDLE_WEBHOOK_SECRET_SANDBOX]);
  candidates.push(["PADDLE_WEBHOOK_SECRET_LIVE", process.env.PADDLE_WEBHOOK_SECRET_LIVE]);
  candidates.push(["PADDLE_WEBHOOK_SECRET_PRODUCTION", process.env.PADDLE_WEBHOOK_SECRET_PRODUCTION]);

  const seen = new Set();
  const uniqueCandidates = candidates
    .map(function ([name, value]) {
      return [name, typeof value === "string" ? value.trim() : value];
    })
    .filter(function ([name, value]) {
      if (!value) {
        return false;
      }

      const key = name + "::" + value;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });

  return {
    candidates: uniqueCandidates,
    environmentHint: environmentHint || null,
  };
}

function verifyPaddleSignatureWithCandidates(rawBody, signature, candidates) {
  if (!signature || !Array.isArray(candidates) || candidates.length === 0) {
    return { ok: false, secretName: null };
  }

  for (const [secretName, secretValue] of candidates) {
    if (verifyPaddleSignature(rawBody, signature, secretValue)) {
      return { ok: true, secretName: secretName };
    }
  }

  return { ok: false, secretName: null };
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
    const requestId = req.headers["x-vercel-id"] || "unknown";

    // 1. Get the raw body for signature verification
    const rawBody = await getRawBody(req);

    // 2. Verify Paddle signature
    const signature = req.headers["paddle-signature"];
    const secretSelection = getWebhookSecretCandidates();

    if (!secretSelection.candidates.length) {
      console.error("[paddle-webhook] Missing Paddle webhook secret", {
        requestId,
        environmentHint: secretSelection.environmentHint,
      });
      return res.status(500).json({ error: "Webhook secret not configured" });
    }

    if (!rawBody) {
      console.warn("[paddle-webhook] Empty body received", { requestId });
      return res.status(400).json({ error: "Empty request body" });
    }

    console.log("[paddle-webhook] Incoming request", {
      requestId,
      hasSignature: Boolean(signature),
      signatureSummary: summarizeSignature(signature),
      bodyLength: rawBody.length,
      secretSources: secretSelection.candidates.map(function ([name]) { return name; }),
      environmentHint: secretSelection.environmentHint,
    });

    const verificationResult = verifyPaddleSignatureWithCandidates(
      rawBody,
      signature,
      secretSelection.candidates
    );

    if (!verificationResult.ok) {
      console.warn("[paddle-webhook] Invalid signature — rejecting", {
        requestId,
        signaturePrefix: signature ? signature.slice(0, 24) : null,
        bodyPreview: rawBody.slice(0, 120),
        secretConfigured: secretSelection.candidates.length > 0,
        secretSources: secretSelection.candidates.map(function ([name]) { return name; }),
      });
      return res.status(403).json({ error: "Invalid signature" });
    }

    console.log("[paddle-webhook] Signature verified", {
      requestId,
      secretSource: verificationResult.secretName,
    });

    // 3. Parse the event
    const event = parseEventFromRawBody(rawBody);
    if (!event) {
      console.error("[paddle-webhook] Could not parse webhook body", { requestId });
      return res.status(400).json({ error: "Invalid JSON body" });
    }
    const eventType = event.event_type;
    const eventId = event.event_id;
    const data = event.data || {};

    console.log(`[paddle-webhook] Received: ${eventType} (${eventId})`);

    // 4. Extract userId from customData
    const customData = data.custom_data || {};
    const userId = customData.userId || customData.user_id || null;

    console.log("[paddle-webhook] Parsed event payload", {
      requestId,
      eventType,
      eventId,
      dataId: data.id || null,
      subscriptionStatus: data.status || null,
      hasCustomData: Object.keys(customData).length > 0,
      userId,
    });

    if (!userId) {
      console.warn("[paddle-webhook] No userId in custom_data", {
        requestId,
        eventType,
        eventId,
        customData,
      });
      // Still return 200 to Paddle to avoid retries
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
      case "subscription.created":
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

      case "transaction.completed":
        await updateUserSubscription(userId, {
          isPremium: true,
          transactionId: data.id || null,
          transactionStatus: data.status || "completed",
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

    // 6. Always return 200 to Paddle
    return res.status(200).json({ received: true, eventType });
  } catch (err) {
    console.error("[paddle-webhook] Handler error:", err);
    // Return 200 even on errors to prevent Paddle retry storms
    return res.status(200).json({ received: true, error: "internal" });
  }
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};
