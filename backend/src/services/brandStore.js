/**
 * brandStore.js
 *
 * Persists which domains share a "brand token" — the core name of a
 * domain with the TLD stripped off. If simbacoach.com and
 * simbacoach.online both get scanned, they share the token "simbacoach"
 * despite being entirely different domains. That's exactly the pattern
 * used in brand-impersonation/typosquat scams: same recognizable name,
 * different (often newer, less scrutinized) TLD.
 *
 * IMPORTANT CAVEAT: a match does NOT mean the newer domain is fake — a
 * real company might legitimately run simbacoach.com AND simbacoach.co.ke.
 * This check can only tell you "these domains share a name," never which
 * one (if any) is the impersonator. It's a prompt for the user to verify,
 * not a verdict — worded that way in scoring.js.
 *
 * Storage: flat JSON file. Swap for a real database before real-scale use.
 */

const fs = require('fs');
const path = require('path');

const STORE_PATH = path.join(__dirname, '..', '..', 'data', 'brand-tokens.json');

// A short list of common two-label ccTLDs so "simbacoach.co.ke" correctly
// strips to "simbacoach" rather than "simbacoach.co". Not exhaustive —
// for full correctness you'd want the public suffix list
// (https://publicsuffix.org), but this covers the common cases.
const TWO_LABEL_TLDS = new Set([
  'co.ke', 'co.uk', 'co.za', 'co.in', 'co.jp', 'co.nz', 'co.id',
  'com.au', 'com.br', 'com.mx', 'com.sg', 'com.ng', 'com.tr',
  'org.uk', 'net.au', 'ac.uk', 'gov.uk',
]);

function extractBrandToken(hostname) {
  const clean = hostname.toLowerCase().replace(/^www\./, '');
  const parts = clean.split('.');
  if (parts.length < 2) return clean.replace(/[^a-z0-9]/g, '');

  const lastTwo = parts.slice(-2).join('.');
  const brandLabel = TWO_LABEL_TLDS.has(lastTwo)
    ? parts[parts.length - 3] // e.g. simbacoach . co . ke -> index -3
    : parts[parts.length - 2]; // e.g. simbacoach . online -> index -2

  return (brandLabel || '').replace(/[^a-z0-9]/g, ''); // normalize away hyphens etc.
}

function loadStore() {
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return {}; // brandToken -> [{ domain, firstSeen }]
  }
}

function saveStore(store) {
  try {
    fs.mkdirSync(path.dirname(STORE_PATH), { recursive: true });
    fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
  } catch (err) {
    console.error('brandStore: failed to persist store', err.message);
  }
}

let store = loadStore();

/**
 * recordAndCheck(domain)
 * Returns other domains already recorded that share this domain's brand
 * token, then records the current domain.
 */
function recordAndCheck(domain) {
  const token = extractBrandToken(domain);
  if (!token || token.length < 3) return { token, matches: [] }; // too short to be meaningful

  const entry = store[token] || [];
  const matches = entry.map((e) => e.domain).filter((d) => d !== domain);

  const alreadyRecorded = entry.some((e) => e.domain === domain);
  if (!alreadyRecorded) {
    entry.push({ domain, firstSeen: new Date().toISOString() });
    store[token] = entry;
    saveStore(store);
  }

  return { token, matches };
}

function _resetForTests() {
  store = {};
  saveStore(store);
}

module.exports = { recordAndCheck, extractBrandToken, _resetForTests };
