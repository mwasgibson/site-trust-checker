/**
 * checkBlocklist(url)
 * Queries Google Safe Browsing's Lookup API for known phishing/malware
 * listings. This is one of the strongest signals available since it's
 * backed by Google's crawling + user-report data, not heuristics.
 *
 * Requires a free API key: https://developers.google.com/safe-browsing/v4/get-started
 * Set GOOGLE_SAFE_BROWSING_API_KEY in your environment (.env file).
 *
 * If no key is configured, this check is skipped (ok: false, skipped: true)
 * rather than throwing — so the rest of the report still works.
 */

const SAFE_BROWSING_ENDPOINT =
  'https://safebrowsing.googleapis.com/v4/threatMatches:find';

async function checkBlocklist(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey) {
    return {
      ok: false,
      skipped: true,
      reason: 'GOOGLE_SAFE_BROWSING_API_KEY not set',
    };
  }

  const body = {
    client: {
      clientId: 'site-trust-checker',
      clientVersion: '0.1.0',
    },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }],
    },
  };

  try {
    const res = await fetch(`${SAFE_BROWSING_ENDPOINT}?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) {
      return { ok: false, error: `Safe Browsing API returned ${res.status}` };
    }

    const data = await res.json();
    const matches = data.matches || [];

    return {
      ok: true,
      flagged: matches.length > 0,
      tier: matches.length > 0 ? 'strong' : null,
      threatTypes: matches.map((m) => m.threatType),
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = { checkBlocklist };
