/**
 * checkImageReuse(url, { renderedImages })
 *
 * Computes a perceptual "average hash" (aHash) for key images on the page
 * (logo, hero image, etc.) and checks whether a visually-identical image
 * has already been seen on other domains. The same stock photo or scam
 * template's exact logo showing up across unrelated domains is a strong
 * reuse signal — similar in spirit to templateFingerprint.js, but for
 * images instead of DOM structure.
 *
 * This is NOT a reverse-image-search against the wider web (that needs a
 * paid API like TinEye/Google Vision) — it only catches reuse across
 * domains that this specific installation has scanned before. Still
 * useful, and free, and it grows more useful the more you scan.
 *
 * Prefers `renderedImages` (an array of absolute image URLs) supplied by
 * the extension's content script. Falls back to none if not provided —
 * there's no reliable static-HTML equivalent since logo/hero detection
 * benefits from seeing the rendered layout.
 */

const { Jimp } = require('jimp');
const { findSimilarAndRecord } = require('../services/imageHashStore');

const MAX_IMAGES_TO_CHECK = 5;
const HASH_SIZE = 8; // 8x8 = 64-bit hash
const FETCH_TIMEOUT_MS = 8000;

function extractHostname(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
}

async function computeAverageHash(imageUrl) {
  const res = await fetch(imageUrl, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Image fetch returned ${res.status}`);

  const buf = Buffer.from(await res.arrayBuffer());
  const img = await Jimp.read(buf);
  img.resize({ w: HASH_SIZE, h: HASH_SIZE }).greyscale();

  const pixels = [];
  let sum = 0;
  for (let y = 0; y < HASH_SIZE; y++) {
    for (let x = 0; x < HASH_SIZE; x++) {
      const idx = img.getPixelIndex(x, y);
      const grey = img.bitmap.data[idx];
      pixels.push(grey);
      sum += grey;
    }
  }
  const mean = sum / pixels.length;

  // Build a 64-bit hash (1 if pixel >= mean, else 0), packed as hex nibbles
  let bits = '';
  for (const p of pixels) {
    bits += p >= mean ? '1' : '0';
  }
  let hex = '';
  for (let i = 0; i < bits.length; i += 4) {
    hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  }
  return hex;
}

async function checkImageReuse(url, { renderedImages } = {}) {
  const domain = extractHostname(url);

  if (!renderedImages || renderedImages.length === 0) {
    return {
      ok: false,
      skipped: true,
      reason: 'No image URLs supplied (extension content script required for this check)',
    };
  }

  const imagesToCheck = renderedImages.slice(0, MAX_IMAGES_TO_CHECK);
  const results = [];

  for (const imageUrl of imagesToCheck) {
    try {
      const hash = await computeAverageHash(imageUrl);
      const matches = findSimilarAndRecord(hash, domain, imageUrl);
      if (matches.length > 0) {
        results.push({ imageUrl, hash, matchedDomains: matches.map((m) => m.domain) });
      }
    } catch (err) {
      // Skip images that fail to fetch/decode (broken image, unsupported
      // format, CORS-irrelevant server-side fetch failure, etc.) — one
      // bad image shouldn't fail the whole check.
      continue;
    }
  }

  const allMatchedDomains = new Set();
  for (const r of results) {
    for (const d of r.matchedDomains) allMatchedDomains.add(d);
  }

  let tier = null;
  if (allMatchedDomains.size >= 3) tier = 'medium';
  else if (allMatchedDomains.size >= 1) tier = 'weak';

  return {
    ok: true,
    imagesChecked: imagesToCheck.length,
    reusedImages: results,
    tier,
  };
}

module.exports = { checkImageReuse };
