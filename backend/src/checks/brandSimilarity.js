/**
 * checkBrandSimilarity(url)
 *
 * Flags when a domain's core name (brand token) matches another domain
 * this installation has scanned before, on a different TLD/address —
 * e.g. simbacoach.online vs. a previously-seen simbacoach.com. This is
 * the exact pattern that surfaced a real gap: a well-known brand name
 * on an unexpected TLD scored "likely legitimate" because nothing in
 * the pipeline compared it against anything else.
 *
 * No external API required — purely local, grows with usage, same
 * architecture as templateFingerprint.js and imageReuse.js.
 *
 * LIMITATION: this can only tell you two domains share a name, never
 * which one (if either) is the impersonator, and it only knows about
 * domains this specific installation has personally scanned. A real
 * brand-protection product would cross-reference a curated database of
 * known official brand domains — out of scope for a local-only tool.
 */

const { recordAndCheck } = require('../services/brandStore');

function extractHostname(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
}

async function checkBrandSimilarity(url) {
  const domain = extractHostname(url);
  const { token, matches } = recordAndCheck(domain);

  if (!token || token.length < 3) {
    return { ok: false, skipped: true, reason: 'Domain name too short to fingerprint meaningfully' };
  }

  const tier = matches.length > 0 ? 'medium' : null;

  return {
    ok: true,
    brandToken: token,
    matchedDomains: matches,
    tier,
  };
}

module.exports = { checkBrandSimilarity };
