/**
 * checkBrokenLinks(url)
 * Scrapes the homepage, extracts internal + footer links, and checks
 * each one to find dead links. Limits concurrency and total link count
 * to keep this fast and polite.
 *
 * Status-code checking alone misses "soft 404s" — pages that return
 * HTTP 200 but actually show a "page not found" message (common on
 * many CMSes/frameworks). For key trust pages specifically (About,
 * Privacy, Terms, Contact) we do a full GET and scan the body for
 * common not-found phrasing, since those pages matter most for
 * legitimacy signals and are worth the extra request cost.
 */

const cheerio = require('cheerio');
const { isEnvironmentBlocked, getDenyReason } = require('../services/networkGuard');

const MAX_LINKS_TO_CHECK = 50;
const CONCURRENCY = 8;
const TIMEOUT_MS = 6000;
const KEY_PAGE_PATTERNS = [/about/i, /privacy/i, /terms/i, /contact/i];
const KEY_NAV_TEXT_PATTERNS = [/^home$/i, /about/i, /contact/i, /services/i, /products/i];
const SOFT_404_PATTERNS = [
  /page not found/i,
  /404[\s\-]?(error|not found)/i,
  /(this page|content) (could not|couldn'?t) be found/i,
  /oops.{0,20}(doesn'?t|does not) exist/i,
  /we can'?t seem to find/i,
];

function resolveUrl(href, base) {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

function isKeyPage(link) {
  return KEY_PAGE_PATTERNS.some((p) => p.test(link));
}

async function checkLink(link) {
  const keyPage = isKeyPage(link);

  try {
    if (keyPage) {
      // Full GET + body check for soft-404s on pages that matter most
      const res = await fetch(link, {
        method: 'GET',
        redirect: 'follow',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) return { link, status: res.status, ok: false, keyPage };

      const body = await res.text();
      const looksLikeSoft404 = SOFT_404_PATTERNS.some((p) => p.test(body));
      return { link, status: res.status, ok: !looksLikeSoft404, keyPage, soft404: looksLikeSoft404 };
    }

    let res = await fetch(link, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    // Some servers don't support HEAD properly (405/403) — fall back to GET
    if (res.status === 405 || res.status === 403) {
      res = await fetch(link, {
        method: 'GET',
        redirect: 'follow',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    }
    return { link, status: res.status, ok: res.ok, keyPage };
  } catch (err) {
    return { link, status: null, ok: false, keyPage, error: err.message };
  }
}

async function runWithConcurrency(items, limit, worker) {
  const results = [];
  let i = 0;
  async function next() {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await worker(items[idx]);
    }
  }
  const runners = Array.from({ length: Math.min(limit, items.length) }, next);
  await Promise.all(runners);
  return results;
}

async function checkBrokenLinks(url, { renderedLinks, renderedDeadEndLinks } = {}) {
  let hrefs;
  let source;

  if (renderedLinks !== undefined) {
    hrefs = new Set(renderedLinks);
    source = 'rendered-dom';
  } else {
    try {
      const res = await fetch(url, {
        redirect: 'follow',
        signal: AbortSignal.timeout(10000),
      });
      if (isEnvironmentBlocked(res)) {
        return {
          ok: false,
          environmentBlocked: true,
          error: `Network egress blocked before reaching the real site (${getDenyReason(res)})`,
        };
      }
      const html = await res.text();
      const $ = cheerio.load(html);
      const base = res.url;

      hrefs = new Set();
      $('a[href]').each((_, el) => {
        const href = $(el).attr('href');
        if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) {
          return;
        }
        const resolved = resolveUrl(href, base);
        if (resolved) hrefs.add(resolved);
      });
      source = 'static-html';
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  try {
    const linksToCheck = Array.from(hrefs).slice(0, MAX_LINKS_TO_CHECK);
    const results = await runWithConcurrency(linksToCheck, CONCURRENCY, checkLink);

    const broken = results.filter((r) => !r.ok);
    const softBroken = results.filter((r) => r.soft404);
    const keyPagesFound = linksToCheck.filter(isKeyPage);
    const keyPagesBroken = results.filter((r) => r.keyPage && !r.ok);

    // Dead-end "fake navigation" links (href="#", javascript:void(0), or
    // a hash pointing nowhere) — supplied by the extension's content
    // script, since detecting these requires seeing the actual rendered
    // DOM and attribute values, not just fetching URLs. A link with no
    // real destination isn't a broken link in the HTTP sense (there's no
    // URL to fetch), but it's arguably a stronger red flag: it means the
    // "page" doesn't exist even as a concept, just decoration meant to
    // make the site look more complete than it is.
    const deadEndLinks = renderedDeadEndLinks || [];
    const deadEndKeyNavLinks = deadEndLinks.filter((d) =>
      KEY_NAV_TEXT_PATTERNS.some((p) => p.test(d.text))
    );

    let deadEndTier = null;
    if (deadEndKeyNavLinks.length >= 2) deadEndTier = 'strong';
    else if (deadEndKeyNavLinks.length >= 1 || deadEndLinks.length >= 3) deadEndTier = 'medium';
    else if (deadEndLinks.length >= 1) deadEndTier = 'weak';

    return {
      ok: true,
      linkSource: source,
      totalLinksFound: hrefs.size,
      totalLinksChecked: linksToCheck.length,
      brokenCount: broken.length,
      brokenLinks: broken.map((b) => ({ link: b.link, status: b.status, soft404: !!b.soft404 })),
      softBrokenCount: softBroken.length,
      hasAboutOrPrivacyOrTerms: keyPagesFound.length > 0 && keyPagesBroken.length < keyPagesFound.length,
      keyPagesFound,
      keyPagesBroken: keyPagesBroken.map((b) => b.link),
      deadEndLinks,
      deadEndKeyNavLinks,
      deadEndTier,
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = { checkBrokenLinks };