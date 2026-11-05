/**
 * eBay Marketplace Account Deletion/Closure notification endpoint.
 *
 * WHY THIS FILE EXISTS
 *
 * eBay refuses to activate a production keyset until the application either subscribes to these
 * notifications or formally opts out. The "Your keyset is currently disabled" message is that gate,
 * not a fault: it applies to every new production keyset.
 *
 * Opting out is only permitted for applications that do not persist eBay user data. This business
 * does — a dropship order carries the buyer's delivery details, and order records are kept for tax
 * purposes — so opting out would mean declaring something untrue to eBay, whose own documentation
 * warns that incorrect information may result in penalties or account closure. Subscribing is the
 * honest route, and it is about thirty lines of arithmetic.
 *
 * THE TWO HALVES OF THE CONTRACT, ON ONE URL:
 *
 *   GET  ?challenge_code=...  -> 200 {"challengeResponse":"<sha256 hex>"}
 *   POST <notification body>  -> 200 once the notification is verified, 412 if it is not
 *
 * The hash is SHA-256 over the concatenation, in this exact order:
 *
 *   challengeCode + verificationToken + endpoint
 *
 * No separators, no reordering, and the endpoint must be character-for-character the URL registered
 * in the developer portal — a trailing slash or a different host produces a hash eBay rejects, and
 * the error it gives says nothing about which of the three parts was wrong.
 */

const crypto = require("crypto");

// Read from the environment so neither the token nor the URL is in the repository. The endpoint URL
// is not a secret, but it must match the portal exactly, and keeping it in one place means the two
// cannot drift.
const VERIFICATION_TOKEN = process.env.EBAY_VERIFICATION_TOKEN || "";
const ENDPOINT_URL = process.env.EBAY_ENDPOINT_URL || "";
const CLIENT_ID = process.env.EBAY_CLIENT_ID || "";
const CLIENT_SECRET = process.env.EBAY_CLIENT_SECRET || "";
const API_BASE = process.env.EBAY_API_BASE_URL || "https://api.ebay.com";

// eBay recommends caching the public key for about an hour; fetching it per notification would burn
// the API call limit the moment a batch of deletions arrives.
const KEY_CACHE_MS = 55 * 60 * 1000;
let keyCache = { kid: null, key: null, at: 0 };
let tokenCache = { token: null, at: 0 };

function challengeResponse(challengeCode) {
  return crypto
    .createHash("sha256")
    .update(challengeCode + VERIFICATION_TOKEN + ENDPOINT_URL)
    .digest("hex");
}

function send(res, status, payload) {
  const body = JSON.stringify(payload);
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Length", Buffer.byteLength(body));
  res.setHeader("Cache-Control", "no-store");
  res.end(body);
}

async function readRawBody(req) {
  // The signature is over the exact bytes eBay sent, so the body must be taken raw. Re-serialising a
  // parsed object would change whitespace and key order, and the signature would fail for a reason
  // that looks like an eBay problem rather than an ours problem.
  if (Buffer.isBuffer(req.body)) return req.body;
  const chunks = [];
  try {
    for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  } catch (err) {
    if (typeof req.body === "string") return Buffer.from(req.body, "utf8");
    throw err;
  }
  if (chunks.length) return Buffer.concat(chunks);
  if (typeof req.body === "string") return Buffer.from(req.body, "utf8");
  if (req.body && typeof req.body === "object") return Buffer.from(JSON.stringify(req.body), "utf8");
  return Buffer.alloc(0);
}

async function appAccessToken() {
  if (tokenCache.token && Date.now() - tokenCache.at < KEY_CACHE_MS) return tokenCache.token;
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
  const response = await fetch(`${API_BASE}/identity/v1/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basic}`,
    },
    body: "grant_type=client_credentials&scope=https%3A%2F%2Fapi.ebay.com%2Foauth%2Fapi_scope",
  });
  if (!response.ok) throw new Error(`token request failed: HTTP ${response.status}`);
  const data = await response.json();
  tokenCache = { token: data.access_token, at: Date.now() };
  return data.access_token;
}

async function publicKey(kid) {
  if (keyCache.kid === kid && Date.now() - keyCache.at < KEY_CACHE_MS) return keyCache.key;
  const token = await appAccessToken();
  const response = await fetch(`${API_BASE}/commerce/notification/v1/public_key/${kid}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error(`getPublicKey failed: HTTP ${response.status}`);
  const data = await response.json();
  let key = data.key || "";
  // eBay returns the key body without PEM markers. Node's verifier needs them.
  if (key && !key.includes("BEGIN")) {
    const lines = key.match(/.{1,64}/g) || [key];
    key = `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
  }
  keyCache = { kid, key, at: Date.now() };
  return key;
}

async function verifySignature(req, raw) {
  const header = req.headers["x-ebay-signature"];
  if (!header) return { ok: false, reason: "no x-ebay-signature header" };
  if (!CLIENT_ID || !CLIENT_SECRET) {
    // Without credentials the key cannot be fetched, so authenticity cannot be established. Said
    // plainly rather than treated as verified: an unverified payload must never look like a good one.
    return { ok: false, reason: "no eBay credentials configured, so the signature cannot be checked" };
  }
  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
  } catch (err) {
    return { ok: false, reason: `signature header is not base64 JSON: ${err.message}` };
  }
  const { kid, signature } = decoded;
  if (!kid || !signature) return { ok: false, reason: "signature header lacks kid or signature" };
  try {
    const key = await publicKey(kid);
    const ok = crypto
      .createVerify("SHA1")
      .update(raw)
      .verify(key, Buffer.from(signature, "base64"));
    return { ok, reason: ok ? "verified" : "signature does not match the payload" };
  } catch (err) {
    return { ok: false, reason: `verification error: ${err.message}` };
  }
}

module.exports = async (req, res) => {
  // eBay's endpoint validation: a GET carrying a one-off challenge code, issued the moment the URL
  // and token are saved in the developer portal.
  if (req.method === "GET") {
    const url = new URL(req.url, `https://${req.headers.host || "localhost"}`);
    const challengeCode = url.searchParams.get("challenge_code");
    if (!challengeCode) {
      return send(res, 400, {
        error: "expected a challenge_code query parameter",
        hint: "this endpoint is for eBay's account-deletion notifications and answers GET only with ?challenge_code=",
      });
    }
    if (!VERIFICATION_TOKEN || !ENDPOINT_URL) {
      // Answered with a clear reason rather than a hash computed from empty strings, which would
      // look like a correct response and fail eBay's check with no clue as to why.
      return send(res, 500, {
        error: "EBAY_VERIFICATION_TOKEN and EBAY_ENDPOINT_URL must both be set",
      });
    }
    return send(res, 200, { challengeResponse: challengeResponse(challengeCode) });
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return send(res, 405, { error: `${req.method} is not supported` });
  }

  let raw;
  try {
    raw = await readRawBody(req);
  } catch (err) {
    return send(res, 400, { error: `could not read the body: ${err.message}` });
  }

  const verdict = await verifySignature(req, raw);
  if (!verdict.ok) {
    // 412 as eBay specifies, so it retries rather than treating a rejected payload as delivered. The
    // payload is NOT acted on: an unauthenticated request must never be able to delete a record.
    return send(res, 412, { error: "signature verification failed", reason: verdict.reason });
  }

  let payload = {};
  try {
    payload = JSON.parse(raw.toString("utf8"));
  } catch (err) {
    return send(res, 400, { error: `body is not JSON: ${err.message}` });
  }

  const data = (payload.notification && payload.notification.data) || {};
  const username = data.username || "";
  const userId = data.userId || "";
  const notificationId = (payload.notification && payload.notification.notificationId) || "";

  // What has to happen here, and what deliberately does not.
  //
  // The request is to delete the eBay user's data. This business holds exactly one kind of eBay user
  // data: the buyer details on a dropship order. Those records are also the accounting record of a
  // sale, and UK tax law requires them to be kept — so the right response is not to erase the order
  // but to remove the personal identifiers from it and keep the financial facts.
  //
  // That deletion is NOT performed here. This function runs on stateless hosting with no access to
  // the order database, and a deletion that silently does nothing is worse than one that is visibly
  // queued. It acknowledges, records the identity to be erased, and leaves the erasure to the engine
  // that owns the data — so the request is durable rather than lost, and can be audited afterwards.
  console.log(
    JSON.stringify({
      event: "ebay_marketplace_account_deletion",
      receivedAt: new Date().toISOString(),
      notificationId,
      username,
      userId,
      // Recorded so the engine can match it against orders.buyer_reference and strip the personal
      // fields while keeping the totals, dates and SKUs the accounts depend on.
      action: "queued_for_erasure_by_the_commerce_engine",
      retained: "order totals, dates and SKUs (accounting records); buyer identifiers to be removed",
    })
  );

  return send(res, 200, { acknowledged: true, notificationId });
};
