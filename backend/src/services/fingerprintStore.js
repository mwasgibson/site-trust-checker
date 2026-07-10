/**
 * fingerprintStore.js
 *
 * Persists which domains share an identical page-structure fingerprint.
 * Scam/phishing "site farms" frequently reuse the exact same template
 * across dozens of throwaway domains with only the product/brand text
 * swapped out — so if domain B has the identical structural fingerprint
 * as domain A, that's a strong signal, especially once 3+ domains share
 * one fingerprint.
 *
 * Storage: a flat JSON file for simplicity. Swap for a real database
 * (Postgres/Redis) before running this at any real scale — a single
 * JSON file does not handle concurrent writes safely.
 */

const fs = require('fs');
const path = require('path');

const STORE_PATH = path.join(__dirname, '..', '..', 'data', 'fingerprints.json');

function loadStore() {
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return {}; // hash -> { domains: [{domain, firstSeen}] }
  }
}

function saveStore(store) {
  try {
    fs.mkdirSync(path.dirname(STORE_PATH), { recursive: true });
    fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
  } catch (err) {
    console.error('fingerprintStore: failed to persist store', err.message);
  }
}

let store = loadStore();

/**
 * recordAndCheck(hash, domain)
 * Returns the list of OTHER domains already associated with this hash
 * (before recording the current one), then records the current domain.
 */
function recordAndCheck(hash, domain) {
  const entry = store[hash] || { domains: [] };
  const otherDomains = entry.domains
    .map((d) => d.domain)
    .filter((d) => d !== domain);

  const alreadyRecorded = entry.domains.some((d) => d.domain === domain);
  if (!alreadyRecorded) {
    entry.domains.push({ domain, firstSeen: new Date().toISOString() });
    store[hash] = entry;
    saveStore(store);
  }

  return otherDomains;
}

function _resetForTests() {
  store = {};
  saveStore(store);
}

module.exports = { recordAndCheck, _resetForTests };
