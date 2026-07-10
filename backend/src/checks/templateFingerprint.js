/**
 * checkTemplateFingerprint(url, { renderedStructure })
 *
 * Computes a structural fingerprint of the page — the sequence of HTML
 * tag names in document order, ignoring text/attributes/styling — and
 * checks whether that exact structure has been seen on other domains
 * before. Identical structure across otherwise-unrelated domains is a
 * strong indicator of a templated scam/phishing "site farm."
 *
 * Prefers `renderedStructure` (a comma-joined tag list) supplied by the
 * extension's content script, which sees the fully rendered DOM. Falls
 * back to parsing static HTML server-side for direct API/curl testing —
 * note the fallback will diverge from the rendered version on JS-heavy
 * sites, same caveat as the other checks.
 */

const cheerio = require('cheerio');
const crypto = require('crypto');
const { recordAndCheck } = require('../services/fingerprintStore');
const { isEnvironmentBlocked, getDenyReason } = require('../services/networkGuard');

const MAX_NODES = 300;
const IGNORED_TAGS = new Set(['script', 'style', 'noscript', 'svg', 'path']);

function extractHostname(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
}

function computeStructureFromHtml(html) {
  const $ = cheerio.load(html);
  const tags = [];

  function walk(el) {
    if (tags.length >= MAX_NODES) return;
    const tagName = el.tagName || el.name;
    if (!tagName) return;
    const tag = tagName.toLowerCase();
    if (IGNORED_TAGS.has(tag)) return;
    tags.push(tag);
    const children = el.children || [];
    for (const child of children) {
      if (tags.length >= MAX_NODES) break;
      if (child.type === 'tag') walk(child);
    }
  }

  const root = $('body').get(0);
  if (root) walk(root);
  return tags.join(',');
}

function hashStructure(structureStr) {
  return crypto.createHash('sha256').update(structureStr).digest('hex').slice(0, 16);
}

async function checkTemplateFingerprint(url, { renderedStructure } = {}) {
  const domain = extractHostname(url);
  let structure = renderedStructure && renderedStructure.length > 0 ? renderedStructure : null;
  let source = structure ? 'rendered-dom' : null;

  if (!structure) {
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
      structure = computeStructureFromHtml(html);
      source = 'static-html';
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  if (!structure || structure.length < 20) {
    return { ok: false, skipped: true, reason: 'Not enough structural data to fingerprint' };
  }

  const hash = hashStructure(structure);
  const sharedWithDomains = recordAndCheck(hash, domain);

  let tier = null;
  if (sharedWithDomains.length >= 3) tier = 'strong';
  else if (sharedWithDomains.length >= 1) tier = 'medium';

  return {
    ok: true,
    fingerprint: hash,
    textSource: source,
    sharedWithDomains,
    tier,
  };
}

module.exports = { checkTemplateFingerprint };
