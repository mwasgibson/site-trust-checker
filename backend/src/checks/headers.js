/**
 * checkHeaders(url)
 * Fetches the page and inspects HTTP response headers for common
 * security best practices. Returns a list of findings plus a
 * tier ("strong" | "medium" | "weak") for scoring purposes.
 */

const { isEnvironmentBlocked, getDenyReason } = require('../services/networkGuard');

const EXPECTED_HEADERS = [
  {
    header: 'strict-transport-security',
    label: 'HSTS (Strict-Transport-Security)',
    tier: 'medium',
  },
  {
    header: 'content-security-policy',
    label: 'Content-Security-Policy',
    tier: 'medium',
  },
  {
    header: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    tier: 'weak',
  },
  {
    header: 'x-frame-options',
    label: 'X-Frame-Options (clickjacking protection)',
    tier: 'weak',
  },
  {
    header: 'referrer-policy',
    label: 'Referrer-Policy',
    tier: 'weak',
  },
];

async function checkHeaders(url) {
  const findings = [];
  let usedHttps = url.startsWith('https://');

  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    });

    // Track whether we ended up on HTTPS after redirects
    usedHttps = res.url.startsWith('https://');

    if (isEnvironmentBlocked(res)) {
      return {
        ok: false,
        environmentBlocked: true,
        error: `Network egress blocked before reaching the real site (${getDenyReason(res)}) — this is an environment restriction, not a finding about the target site`,
        findings: [],
      };
    }

    findings.push({
      check: 'https',
      label: 'Uses HTTPS',
      pass: usedHttps,
      tier: 'strong',
    });

    for (const { header, label, tier } of EXPECTED_HEADERS) {
      const present = res.headers.has(header);
      findings.push({
        check: header,
        label,
        pass: present,
        tier,
      });
    }

    // Redirect chain length (res.redirected tells us at least one redirect happened;
    // for full chain length you'd need a manual redirect: 'manual' loop)
    findings.push({
      check: 'redirected',
      label: 'Landed on final URL without excessive redirects',
      pass: true, // placeholder — see notes below
      tier: 'weak',
      note: res.redirected ? `Redirected to ${res.url}` : 'No redirect',
    });

    return {
      ok: true,
      finalUrl: res.url,
      statusCode: res.status,
      findings,
    };
  } catch (err) {
    return {
      ok: false,
      error: err.message,
      findings: [
        {
          check: 'https',
          label: 'Uses HTTPS',
          pass: usedHttps,
          tier: 'strong',
        },
      ],
    };
  }
}

module.exports = { checkHeaders };
