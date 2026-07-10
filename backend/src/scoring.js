/**
 * scoreReport(checks)
 * Combines results from all checks into a single 0-100 trust score
 * plus a human-readable list of reasons. Weighting reflects the
 * tiers discussed: strong signals dominate, weak signals only matter
 * when several stack up together.
 */

const TIER_WEIGHTS = {
  strong: 35,
  medium: 12,
  weak: 4,
};

function scoreReport({ headers, brokenLinks, whois, blocklist, aiContent, templateFingerprint, imageReuse, brandSimilarity }) {
  let score = 100;
  const reasons = [];

  // --- Blocklist (strongest possible signal) ---
  if (blocklist?.ok && blocklist.flagged) {
    score -= TIER_WEIGHTS.strong;
    reasons.push({
      severity: 'high',
      message: `Flagged by Google Safe Browsing (${blocklist.threatTypes.join(', ')})`,
    });
  }

  // --- HTTPS / headers ---
  if (headers?.ok) {
    for (const f of headers.findings) {
      if (!f.pass) {
        score -= TIER_WEIGHTS[f.tier] || 0;
        reasons.push({
          severity: f.tier === 'strong' ? 'high' : f.tier === 'medium' ? 'medium' : 'low',
          message: `Missing or failing: ${f.label}`,
        });
      }
    }
  } else if (headers && !headers.ok) {
    score -= TIER_WEIGHTS.medium;
    reasons.push({ severity: 'medium', message: `Could not fetch site to inspect headers (${headers.error})` });
  }

  // --- WHOIS domain age ---
  if (whois?.ok && whois.flag) {
    score -= TIER_WEIGHTS[whois.tier] || 0;
    reasons.push({
      severity: whois.tier === 'strong' ? 'high' : 'medium',
      message: whois.flag,
    });
  }
  if (whois?.ok && whois.privacyProtected) {
    score -= TIER_WEIGHTS.weak;
    reasons.push({ severity: 'low', message: 'WHOIS registration uses privacy protection' });
  }

  // --- Broken links ---
  if (brokenLinks?.ok) {
    if (brokenLinks.brokenCount > 0) {
      const tier = brokenLinks.brokenCount >= 3 ? 'medium' : 'weak';
      score -= TIER_WEIGHTS[tier];
      reasons.push({
        severity: tier === 'medium' ? 'medium' : 'low',
        message: `${brokenLinks.brokenCount} broken link(s) found out of ${brokenLinks.totalLinksChecked} checked`,
      });
    }
    if (brokenLinks.softBrokenCount > 0) {
      score -= TIER_WEIGHTS.medium;
      reasons.push({
        severity: 'medium',
        message: `${brokenLinks.softBrokenCount} page(s) return "not found" content despite a 200 OK status (soft 404s)`,
      });
    }
    if (brokenLinks.keyPagesBroken && brokenLinks.keyPagesBroken.length > 0) {
      score -= TIER_WEIGHTS.medium;
      reasons.push({
        severity: 'medium',
        message: `Key trust page(s) broken or missing content: ${brokenLinks.keyPagesBroken.join(', ')}`,
      });
    }
    if (!brokenLinks.hasAboutOrPrivacyOrTerms) {
      score -= TIER_WEIGHTS.weak;
      reasons.push({ severity: 'low', message: 'No working About/Privacy/Terms/Contact page found' });
    }
    if (brokenLinks.deadEndTier) {
      score -= TIER_WEIGHTS[brokenLinks.deadEndTier] || 0;
      const navNames = brokenLinks.deadEndKeyNavLinks.map((d) => `"${d.text}"`).join(', ');
      const message = brokenLinks.deadEndKeyNavLinks.length > 0
        ? `Navigation link(s) that look real but go nowhere when clicked: ${navNames} — the page doesn't actually exist, just decorative text`
        : `${brokenLinks.deadEndLinks.length} link(s) found that go nowhere when clicked (href="#" or similar with no real destination)`;
      reasons.push({
        severity: brokenLinks.deadEndTier === 'strong' ? 'high' : brokenLinks.deadEndTier === 'medium' ? 'medium' : 'low',
        message,
      });
    }
  }

  // --- AI-generated / generic template content (LLM-based, weaker confidence) ---
  if (aiContent?.ok && aiContent.tier) {
    score -= TIER_WEIGHTS[aiContent.tier] || 0;
    reasons.push({
      severity: aiContent.tier === 'medium' ? 'medium' : 'low',
      message: `Content reads as likely AI-generated/templated (${aiContent.aiGeneratedLikelihood}% confidence): ${aiContent.reasoning}`,
    });
  }

  // --- Template fingerprint reuse (identical structure on other domains) ---
  if (templateFingerprint?.ok && templateFingerprint.tier) {
    score -= TIER_WEIGHTS[templateFingerprint.tier] || 0;
    const count = templateFingerprint.sharedWithDomains.length;
    reasons.push({
      severity: templateFingerprint.tier === 'strong' ? 'high' : 'medium',
      message: `Identical page structure found on ${count} other domain(s): ${templateFingerprint.sharedWithDomains.slice(0, 5).join(', ')}`,
    });
  }

  // --- Image reuse (identical logo/hero image found on other domains) ---
  if (imageReuse?.ok && imageReuse.tier) {
    score -= TIER_WEIGHTS[imageReuse.tier] || 0;
    const domains = new Set();
    for (const r of imageReuse.reusedImages) {
      for (const d of r.matchedDomains) domains.add(d);
    }
    reasons.push({
      severity: imageReuse.tier === 'medium' ? 'medium' : 'low',
      message: `Identical image(s) found reused on other domain(s): ${Array.from(domains).slice(0, 5).join(', ')}`,
    });
  }

  // --- Brand-name / typosquat similarity (same brand name, different TLD/domain) ---
  if (brandSimilarity?.ok && brandSimilarity.tier) {
    score -= TIER_WEIGHTS[brandSimilarity.tier] || 0;
    reasons.push({
      severity: 'medium',
      message: `Domain name closely matches other previously-scanned domain(s) using a different address: ${brandSimilarity.matchedDomains.slice(0, 5).join(', ')}. Verify this is the site you intend to visit — brand-name/TLD mismatches are a common impersonation pattern.`,
    });
  }

  // --- Confidence gating ---
  // Blocklist, WHOIS, and Broken links are the three checks with real
  // discriminating power (a "clean" result from headers/links alone just
  // means nothing was checked, not that the site was vetted). If most of
  // these didn't actually run — missing API keys, network restrictions,
  // etc. — cap the score so a thin scan can never claim "likely
  // legitimate." This directly addresses a real false-positive: a scan
  // where only headers+links ran still scored 80 ("likely legitimate")
  // on a site that turned out to be a probable brand impersonation.
  const deepChecks = [blocklist, whois, brokenLinks];
  const deepChecksRan = deepChecks.filter((c) => c && c.ok).length;
  const deepChecksTotal = deepChecks.length;

  if (deepChecksRan < 2) {
    const cap = 75; // below the 80-point "likely legitimate" threshold
    if (score > cap) {
      score = cap;
    }
    reasons.push({
      severity: 'medium',
      message: `Limited data: only ${deepChecksRan} of ${deepChecksTotal} deeper checks (blocklist, domain age, broken links) completed. Score reflects surface-level checks only — treat with caution.`,
    });
  }

  score = Math.max(0, Math.min(100, score));

  let verdict;
  if (score >= 80) verdict = 'Likely legitimate';
  else if (score >= 55) verdict = 'Some concerns — proceed with caution';
  else if (score >= 30) verdict = 'High risk';
  else verdict = 'Very high risk — strong indicators of a fake/malicious site';

  return { score, verdict, reasons };
}

module.exports = { scoreReport };