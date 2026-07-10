/**
 * checkWhois(url)
 * Looks up domain registration data and flags very young domains,
 * which correlate strongly with scam/phishing sites.
 *
 * Uses RDAP (Registration Data Access Protocol) as the primary method —
 * it's the modern, HTTPS-based replacement for raw WHOIS, returns
 * structured JSON, and works through standard HTTPS egress rules that
 * many restrictive networks (corporate firewalls, serverless platforms,
 * some sandboxes) apply, unlike raw WHOIS which needs TCP port 43.
 *
 * Falls back to raw WHOIS (whois-json) if RDAP fails for a given domain
 * (not all TLDs have RDAP servers yet, though most major ones do).
 */

const whois = require('whois-json');

const YOUNG_DOMAIN_DAYS = 30;
const RECENT_DOMAIN_DAYS = 180;
const RDAP_BOOTSTRAP = 'https://rdap.org/domain';

function extractHostname(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return null;
  }
}

function daysSince(dateStr) {
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return null;
  return Math.floor((Date.now() - date.getTime()) / (1000 * 60 * 60 * 24));
}

function classifyAge(ageDays) {
  if (ageDays === null) return { tier: null, flag: null };
  if (ageDays < YOUNG_DOMAIN_DAYS) {
    return { tier: 'strong', flag: `Domain registered only ${ageDays} day(s) ago` };
  }
  if (ageDays < RECENT_DOMAIN_DAYS) {
    return { tier: 'medium', flag: `Domain registered ${ageDays} days ago (relatively new)` };
  }
  return { tier: null, flag: null };
}

async function tryRdap(hostname) {
  const res = await fetch(`${RDAP_BOOTSTRAP}/${hostname}`, {
    signal: AbortSignal.timeout(8000),
    headers: { Accept: 'application/rdap+json' },
  });

  if (!res.ok) {
    throw new Error(`RDAP returned ${res.status}`);
  }

  const data = await res.json();
  const events = data.events || [];
  const registrationEvent = events.find(
    (e) => e.eventAction === 'registration' || e.eventAction === 'registered'
  );
  const creationDateRaw = registrationEvent?.eventDate || null;
  const ageDays = creationDateRaw ? daysSince(creationDateRaw) : null;

  const registrarEntity = (data.entities || []).find((e) =>
    (e.roles || []).includes('registrar')
  );
  const registrar = registrarEntity?.vcardArray?.[1]?.find((f) => f[0] === 'fn')?.[3] || null;

  const { tier, flag } = classifyAge(ageDays);

  return {
    ok: true,
    method: 'rdap',
    hostname,
    creationDate: creationDateRaw,
    registrar,
    ageDays,
    privacyProtected: JSON.stringify(data).match(/redacted|privacy/i) !== null,
    flag,
    tier,
  };
}

async function tryRawWhois(hostname) {
  const data = await whois(hostname, { timeout: 8000 });

  const creationDateRaw =
    data.creationDate || data.createdDate || data.registeredDate || null;
  const ageDays = creationDateRaw ? daysSince(creationDateRaw) : null;
  const { tier, flag } = classifyAge(ageDays);

  return {
    ok: true,
    method: 'raw-whois',
    hostname,
    creationDate: creationDateRaw,
    registrar: data.registrar || null,
    ageDays,
    privacyProtected: /privacy|redacted|whoisguard/i.test(JSON.stringify(data)),
    flag,
    tier,
  };
}

async function checkWhois(url) {
  const hostname = extractHostname(url);
  if (!hostname) {
    return { ok: false, error: 'Could not parse hostname from URL' };
  }

  try {
    return await tryRdap(hostname);
  } catch (rdapErr) {
    try {
      return await tryRawWhois(hostname);
    } catch (whoisErr) {
      return {
        ok: false,
        hostname,
        error: `RDAP failed (${rdapErr.message}), raw WHOIS also failed (${whoisErr.message})`,
        note: 'RDAP needs HTTPS egress to rdap.org; raw WHOIS needs TCP port 43 — check network/firewall config if this fails consistently.',
      };
    }
  }
}

module.exports = { checkWhois };
