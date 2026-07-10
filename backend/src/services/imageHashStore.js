/**
 * imageHashStore.js
 *
 * Persists which domains use a given perceptual image hash. Mirrors
 * fingerprintStore.js but for images (logos, hero photos, "team" photos)
 * instead of page structure — the same exact stock/AI-generated image
 * showing up on multiple unrelated domains is a strong reuse signal.
 *
 * Storage: flat JSON file. Swap for a real database before real-scale use.
 */

const fs = require('fs');
const path = require('path');

const STORE_PATH = path.join(__dirname, '..', '..', 'data', 'image-hashes.json');

function loadStore() {
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return {}; // hash -> [{ domain, imageUrl, firstSeen }]
  }
}

function saveStore(store) {
  try {
    fs.mkdirSync(path.dirname(STORE_PATH), { recursive: true });
    fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
  } catch (err) {
    console.error('imageHashStore: failed to persist store', err.message);
  }
}

let store = loadStore();

function hammingDistance(hashA, hashB) {
  if (hashA.length !== hashB.length) return Infinity;
  let distance = 0;
  for (let i = 0; i < hashA.length; i++) {
    const bitsA = parseInt(hashA[i], 16);
    const bitsB = parseInt(hashB[i], 16);
    let xor = bitsA ^ bitsB;
    while (xor) {
      distance += xor & 1;
      xor >>= 1;
    }
  }
  return distance;
}

const SIMILARITY_THRESHOLD = 5; // out of 64 bits — small tolerance for recompression

/**
 * findSimilarAndRecord(hash, domain, imageUrl)
 * Returns other domains whose stored hash is within the similarity
 * threshold of this one, then records the current hash/domain.
 */
function findSimilarAndRecord(hash, domain, imageUrl) {
  const matches = [];

  for (const [storedHash, entries] of Object.entries(store)) {
    const distance = hammingDistance(hash, storedHash);
    if (distance <= SIMILARITY_THRESHOLD) {
      for (const entry of entries) {
        if (entry.domain !== domain) {
          matches.push({ domain: entry.domain, imageUrl: entry.imageUrl, distance });
        }
      }
    }
  }

  const entry = store[hash] || [];
  const alreadyRecorded = entry.some((e) => e.domain === domain && e.imageUrl === imageUrl);
  if (!alreadyRecorded) {
    entry.push({ domain, imageUrl, firstSeen: new Date().toISOString() });
    store[hash] = entry;
    saveStore(store);
  }

  return matches;
}

function _resetForTests() {
  store = {};
  saveStore(store);
}

module.exports = { findSimilarAndRecord, hammingDistance, _resetForTests };
