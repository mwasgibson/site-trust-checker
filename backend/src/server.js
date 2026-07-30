require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { checkHeaders } = require('./checks/headers');
const { checkBrokenLinks } = require('./checks/brokenLinks');
const { checkWhois } = require('./checks/whois');
const { checkBlocklist } = require('./checks/blocklist');
const { checkAiContent } = require('./checks/aiContent');
const { checkTemplateFingerprint } = require('./checks/templateFingerprint');
const { checkImageReuse } = require('./checks/imageReuse');
const { checkBrandSimilarity } = require('./checks/brandSimilarity');
const { scoreReport } = require('./scoring');
const { isAdmin, getUsage } = require('./services/usageTracker');

const app = express();
const PORT = process.env.PORT || 3100;

app.use(cors());
app.use(express.json());

// --- Extremely simple in-memory cache (swap for Redis in production) ---
const cache = new Map();
const CACHE_TTL_MS = 1000 * 60 * 60 * 3; // 3 hours

function getCached(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  return entry.value;
}

function setCached(key, value) {
  cache.set(key, { value, timestamp: Date.now() });
}

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/analyze', async (req, res) => {
  const { url, userId, renderedText, renderedLinks, renderedDeadEndLinks, renderedStructure, renderedImages } = req.body || {};

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Missing "url" in request body' });
  }

  let normalizedUrl;
  try {
    normalizedUrl = new URL(url).toString();
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  // Cache key includes userId so an admin's aiContent result (which may
  // differ in future once limits exist) never overwrites another user's.
  // Rendered-DOM data isn't part of the key — a cache hit just means we
  // skip re-running checks for a few hours, which is fine either way.
  const cacheKey = `${normalizedUrl}::${userId || 'anonymous'}`;
  const cached = getCached(cacheKey);
  if (cached) {
    return res.json({ ...cached, cached: true });
  }

  try {
    const [headers, brokenLinks, whois, blocklist, aiContent, templateFingerprint, imageReuse, brandSimilarity] = await Promise.all([
      checkHeaders(normalizedUrl),
      checkBrokenLinks(normalizedUrl, { renderedLinks, renderedDeadEndLinks }),
      checkWhois(normalizedUrl),
      checkBlocklist(normalizedUrl),
      checkAiContent(normalizedUrl, { userId, renderedText }),
      checkTemplateFingerprint(normalizedUrl, { renderedStructure }),
      checkImageReuse(normalizedUrl, { renderedImages }),
      checkBrandSimilarity(normalizedUrl),
    ]);

    const { score, verdict, reasons } = scoreReport({
      headers,
      brokenLinks,
      whois,
      blocklist,
      aiContent,
      templateFingerprint,
      imageReuse,
      brandSimilarity,
    });

    const report = {
      url: normalizedUrl,
      score,
      verdict,
      reasons,
      details: { headers, brokenLinks, whois, blocklist, aiContent, templateFingerprint, imageReuse, brandSimilarity },
      isAdmin: isAdmin(userId),
      usage: getUsage(userId),
      generatedAt: new Date().toISOString(),
    };

    setCached(cacheKey, report);
    res.json({ ...report, cached: false });
  } catch (err) {
    res.status(500).json({ error: 'Analysis failed', detail: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Site Trust Checker backend running on port: ${PORT}`);
});