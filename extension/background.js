// Background service worker (Manifest V3)
// Handles requests from the popup to analyze the active tab's URL,
// and caches results per-tab so re-opening the popup doesn't
// re-trigger a full analysis.

const BACKEND_URL = 'https://site-trust-checker.onrender.com/analyze';
const LOCAL_URL = 'http://localhost:3100/analyze'

// In-memory cache keyed by URL, cleared when the service worker
// is unloaded (Chrome may do this after ~30s idle — that's fine,
// the backend itself also caches).
const resultCache = new Map();

// Persistent anonymous ID, generated once per install and stored in
// chrome.storage.local. Sent with every request so the backend can
// track per-user token usage (see backend/src/services/usageTracker.js).
// To get unlimited access as an admin, add this ID to ADMIN_USER_IDS
// in the backend's .env file — check chrome://extensions > service
// worker console, or the popup, to find your generated ID.
async function getUserId() {
  const stored = await chrome.storage.local.get('userId');
  if (stored.userId) return stored.userId;

  const newId = crypto.randomUUID();
  await chrome.storage.local.set({ userId: newId });
  console.log('Site Trust Checker: generated userId', newId);
  return newId;
}

// Runs inside the target page. Kept as a plain function (not an arrow
// function referencing outer scope) because chrome.scripting.executeScript
// serializes it and runs it in an isolated world with no closure access.
function extractRenderedPageData() {
  const MAX_TEXT_CHARS = 4000;
  const MAX_STRUCTURE_NODES = 300;
  const IGNORED_TAGS = new Set(['script', 'style', 'noscript', 'svg', 'path']);

  const text = document.body
    ? document.body.innerText.replace(/\s+/g, ' ').trim().slice(0, MAX_TEXT_CHARS)
    : '';

  const links = Array.from(document.querySelectorAll('a[href]'))
    .map((a) => a.href)
    .filter((href) => href && href.startsWith('http'));

  // Dead-end "fake navigation" links: <a> tags that LOOK like real nav
  // items (visible text like "About Us", "Contact") but go nowhere —
  // href="#", empty href, javascript:void(0), or a "#section" hash with
  // no matching element on the page. These were previously silently
  // dropped entirely (they don't start with "http"), which meant a page
  // full of decorative, non-functional nav links scored as if it had no
  // navigation problems at all — the opposite of the truth.
  const deadEndLinks = [];
  const anchorTags = document.querySelectorAll('a');
  for (const a of anchorTags) {
    const rawHref = a.getAttribute('href');
    const text = (a.textContent || '').trim().replace(/\s+/g, ' ');
    if (!text || text.length > 40) continue; // skip non-nav-looking / paragraph-like links

    let isDeadEnd = false;
    if (!rawHref || rawHref.trim() === '' || rawHref.trim() === '#') {
      isDeadEnd = true;
    } else if (rawHref.trim().toLowerCase().startsWith('javascript:')) {
      isDeadEnd = true;
    } else if (rawHref.startsWith('#') && rawHref.length > 1) {
      const targetId = rawHref.slice(1);
      if (!document.getElementById(targetId) && !document.getElementsByName(targetId).length) {
        isDeadEnd = true; // anchor link points to a section that doesn't exist
      }
    }

    if (isDeadEnd) {
      deadEndLinks.push({ text, href: rawHref || '(none)' });
    }
  }

  // Structural fingerprint: sequence of tag names in document order,
  // ignoring text/attributes/styling — used to detect identical
  // templates reused across unrelated "scam farm" domains.
  const structureTags = [];
  function walk(el) {
    if (structureTags.length >= MAX_STRUCTURE_NODES || !el) return;
    const tag = el.tagName ? el.tagName.toLowerCase() : null;
    if (!tag || IGNORED_TAGS.has(tag)) return;
    structureTags.push(tag);
    for (const child of el.children) {
      if (structureTags.length >= MAX_STRUCTURE_NODES) break;
      walk(child);
    }
  }
  if (document.body) walk(document.body);

  // Candidate images for reuse detection (logo, hero image, etc.) —
  // just grab visible <img> tags in document order, dedupe, cap count.
  // No size/position filtering for now; the backend caps how many it
  // actually fetches and hashes.
  const images = Array.from(document.querySelectorAll('img[src]'))
    .map((img) => img.src)
    .filter((src) => src && src.startsWith('http'));

  return {
    text,
    links: Array.from(new Set(links)),
    deadEndLinks: deadEndLinks.slice(0, 30),
    structure: structureTags.join(','),
    images: Array.from(new Set(images)).slice(0, 10),
  };
}

async function extractFromTab(tabId) {
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId },
      func: extractRenderedPageData,
    });
    return result || { text: '', links: [], deadEndLinks: [], structure: '', images: [] };
  } catch (err) {
    // Injection can fail on chrome:// pages, the Chrome Web Store, or
    // before the page has finished loading — fall back gracefully and
    // let the backend do its own server-side fetch instead.
    console.warn('Site Trust Checker: could not extract rendered page data', err.message);
    return { text: '', links: [], deadEndLinks: [], structure: '', images: [] };
  }
}

async function analyzeUrl(url, tabId) {
  if (resultCache.has(url)) {
    return resultCache.get(url);
  }

  const userId = await getUserId();
  const {
    text: renderedText,
    links: renderedLinks,
    deadEndLinks: renderedDeadEndLinks,
    structure: renderedStructure,
    images: renderedImages,
  } = tabId
    ? await extractFromTab(tabId)
    : { text: '', links: [], deadEndLinks: [], structure: '', images: [] };

  const payload = {
      url,
      userId,
      renderedText,
      renderedLinks,
      renderedDeadEndLinks,
      renderedStructure,
      renderedImages,
    }

  let res;
  try{
    res = await fetch(BACKEND_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: payload,
  });
  } catch(err){
    console.warn('Render server unreachable', err.message);

    res = await fetch(LOCAL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payload,
  
    });
  }
  if (!res.ok) {
    throw new Error(`Backend returned ${res.status}`);
  }

  const data = await res.json();
  resultCache.set(url, data);
  return data;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_URL') {
    analyzeUrl(message.url, message.tabId)
      .then((data) => sendResponse({ ok: true, data }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true; // keep the message channel open for async sendResponse
  }

  if (message.type === 'GET_USER_ID') {
    getUserId()
      .then((userId) => sendResponse({ ok: true, userId }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});