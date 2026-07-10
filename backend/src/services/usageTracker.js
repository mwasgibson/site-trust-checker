/**
 * usageTracker.js
 *
 * Tracks LLM token usage per user so a subscription/paywall can be
 * added later without reworking the check modules. Right now NOTHING
 * is blocked — everyone is effectively unlimited — but usage is
 * recorded so you have real numbers when you decide on a free-tier
 * limit.
 *
 * Admin identification: set ADMIN_USER_IDS in .env as a comma-separated
 * list of userIds (the extension generates and persists one per
 * install — see extension/background.js). Admins are flagged in the
 * response and will always be exempt from limits once limits exist.
 *
 * Swap the in-memory Map for a real database (Postgres/Redis) before
 * running this in production — usage data is lost on server restart
 * otherwise.
 */

const adminIds = new Set(
  (process.env.ADMIN_USER_IDS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
);

// FREE_TOKEN_LIMIT: null/undefined = unlimited (current default).
// Once you introduce a subscription tier, set this to e.g. 100000
// (tokens/month) and start enforcing it in hasExceededLimit().
const FREE_TOKEN_LIMIT = process.env.FREE_TOKEN_LIMIT
  ? parseInt(process.env.FREE_TOKEN_LIMIT, 10)
  : null;

// userId -> { totalTokens, requests, firstSeen, lastSeen }
const usage = new Map();

function isAdmin(userId) {
  return !!userId && adminIds.has(userId);
}

function recordUsage(userId, { inputTokens = 0, outputTokens = 0 } = {}) {
  const id = userId || 'anonymous';
  const total = inputTokens + outputTokens;
  const existing = usage.get(id) || {
    totalTokens: 0,
    requests: 0,
    firstSeen: new Date().toISOString(),
  };

  existing.totalTokens += total;
  existing.requests += 1;
  existing.lastSeen = new Date().toISOString();
  usage.set(id, existing);

  return existing;
}

/**
 * hasExceededLimit — currently always false (free for everyone).
 * When you're ready to enforce a free-tier cap:
 *
 *   if (isAdmin(userId)) return false;
 *   if (FREE_TOKEN_LIMIT === null) return false;
 *   const record = usage.get(userId);
 *   return !!record && record.totalTokens >= FREE_TOKEN_LIMIT;
 */
function hasExceededLimit(userId) {
  if (isAdmin(userId)) return false;
  if (FREE_TOKEN_LIMIT === null) return false;
  const record = usage.get(userId);
  return !!record && record.totalTokens >= FREE_TOKEN_LIMIT;
}

function getUsage(userId) {
  return usage.get(userId) || { totalTokens: 0, requests: 0 };
}

module.exports = { isAdmin, recordUsage, hasExceededLimit, getUsage, FREE_TOKEN_LIMIT };
