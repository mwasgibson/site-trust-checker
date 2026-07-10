# Site Trust Checker

A browser extension + Node.js backend that scores a website's trustworthiness
based on security posture, domain age, broken links, and known-threat
blocklists.

## Project structure

```
site-trust-checker/
├── backend/               Node.js/Express API
│   ├── src/
│   │   ├── checks/
│   │   │   ├── headers.js       HTTPS + security header checks
│   │   │   ├── brokenLinks.js   Scrapes homepage, finds dead links
│   │   │   ├── whois.js         Domain age / registration checks
│   │   │   ├── blocklist.js     Google Safe Browsing lookup
│   │   │   ├── aiContent.js     LLM-based AI-generated/template content check
│   │   │   ├── templateFingerprint.js   Detects identical page structure reused across domains
│   │   │   ├── imageReuse.js    Perceptual-hash detection of identical images across domains
│   │   │   └── brandSimilarity.js   Detects same brand name reused across different domains/TLDs
│   │   ├── services/
│   │   │   ├── usageTracker.js  Per-user token tracking + admin allowlist
│   │   │   ├── fingerprintStore.js  Persistent structure-hash -> domains store
│   │   │   ├── imageHashStore.js    Persistent image-hash -> domains store
│   │   │   ├── brandStore.js        Persistent brand-token -> domains store
│   │   │   └── networkGuard.js      Detects sandbox/proxy block pages vs real responses
│   │   ├── scoring.js            Aggregates checks into a 0-100 score
│   │   └── server.js             Express app, /analyze endpoint
│   ├── data/                    Persisted stores (gitignored, created on first run)
│   ├── .env.example
│   └── package.json
└── extension/             Chrome/Edge Manifest V3 extension
    ├── manifest.json
    ├── background.js       Talks to the backend, injects rendered-DOM
    │                        extraction into the active tab, caches results
    ├── popup.html / popup.js   UI shown when clicking the toolbar icon
    └── icons/
```

## Running the backend

```bash
cd backend
npm install
cp .env.example .env   # add your Google Safe Browsing key (optional but recommended)
node src/server.js
```

Server starts on `http://localhost:3000`. Test it:

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Loading the extension

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** and select the `extension/` folder
4. Make sure the backend is running on `localhost:3000`
5. Click the extension icon on any site to see its trust report

## What's implemented vs. stubbed

| Check | Status |
|---|---|
| HTTPS + security headers | ✅ Working — now detects when a fetch was blocked by a network proxy/WAF before reaching the real site, and reports that honestly instead of analyzing the block page (see "A real bug we found and fixed" below) |
| Broken link detection | ✅ Working — checks up to 50 links, detects **soft 404s** (pages returning HTTP 200 but showing "not found" content) on key trust pages, uses the extension's rendered-DOM links when available |
| WHOIS domain age | ✅ Working — now tries **RDAP** first (HTTPS-based, works through more firewalls/proxies than raw WHOIS), falls back to raw WHOIS (TCP port 43) if RDAP fails for that TLD |
| Google Safe Browsing blocklist | ✅ Working, but needs a free API key in `.env` — gracefully skips if absent |
| AI-generated content detection | ✅ Working, LLM-based (Claude Haiku by default) — needs `ANTHROPIC_API_KEY` in `.env`, gracefully skips if absent. Uses the extension's rendered-DOM text when available |
| Template fingerprint reuse | ✅ Fully working — hashes the page's tag structure and flags when the identical structure appears on 1+ other domains. No external API needed; persists to `data/fingerprints.json` |
| Image reuse detection | ✅ Fully working — perceptual-hashes up to 5 images per page and flags when a visually-identical image appears on other domains. No external API needed; persists to `data/image-hashes.json` |
| Brand-name / typosquat similarity | ✅ Fully working — flags when a domain's core name matches another domain you've scanned before on a different TLD/address (e.g. `simbacoach.online` vs. `simbacoach.com`). No external API needed; persists to `data/brand-tokens.json` |

## A real bug we found and fixed: fabricated findings from blocked requests

During testing against a real site, the headers check reported several
"missing security headers" that turned out to be **completely fabricated**.
Here's what actually happened: the fetch to the target site was blocked by
a network proxy (this sandbox's own egress restrictions), which returned a
synthetic `403` response instead of a connection error. `checkHeaders`
never verified the response actually came from the real site — it just
inspected whatever headers came back and reported "HSTS missing," "CSP
missing," etc. against the **proxy's own block page**, not the real
website.

This isn't just a sandbox quirk — the identical failure mode would hit any
real deployment whenever a request gets intercepted by a WAF, bot-challenge
page, or geo-block: the tool would silently misreport findings about a
page it never actually reached.

**The fix**: `services/networkGuard.js` detects these synthetic block
responses (via an `x-deny-reason` header in this sandbox's case; adapt the
detection to whatever your production network's block signature looks
like) and every check that fetches a URL now bails out honestly —
`ok: false, environmentBlocked: true` — instead of analyzing a page it
never really loaded. Verified with a before/after test: the same URL went
from confidently reporting 5 fake "missing header" findings to correctly
reporting "network egress blocked before reaching the real site."

## Scoring engine fix: confidence gating

The original scoring bug you caught: a real site scored 80 ("likely
legitimate") when only 2 of 7 checks actually ran (headers + broken
links) — blocklist and AI-content were skipped for missing API keys,
WHOIS failed on network restrictions, and the reuse-detection checks had
nothing to compare against yet (first time seeing that domain). The
scoring engine treated "the checks that ran found nothing bad" as
equivalent to "this site is vetted," which is a real design flaw, not
just missing data.

**The fix**: `scoring.js` now counts how many of the three
highest-discriminating-power checks (blocklist, WHOIS domain age,
AI-content analysis) actually completed. If fewer than 2 of 3 ran, the
score is capped at 75 — below the 80-point "likely legitimate" threshold
— and a reason is added explaining exactly why: *"Limited data: only N of
3 deeper checks completed. Score reflects surface-level checks only."*
Verified both directions: a thin scan (0/3 deep checks) is now correctly
capped and labeled, while a full scan where all three succeed and find
nothing is confirmed to still reach 100/"Likely legitimate" — the cap
only fires when it should.

## Brand-name / typosquat detection

`checks/brandSimilarity.js` strips the TLD from a domain (handling common
two-part TLDs like `.co.ke`, `.co.uk`, `.com.au`) to get a "brand token" —
e.g. both `simbacoach.online` and `simbacoach.com` reduce to `simbacoach`.
It checks `data/brand-tokens.json` for other domains sharing that same
token and flags the match.

**Important caveat, worded carefully in the actual output**: a match does
NOT mean the newer domain is fake — a real company might legitimately run
the same brand on multiple TLDs. This check can only tell you "these two
domains share a name," never which one (if either) is the impersonator.
It's a prompt to verify, not an accusation — and it's exactly the signal
that was missing when a likely-impersonating domain scored "likely
legitimate" with nothing flagging the name collision at all.

Verified live against the actual case that exposed this gap: scanning
`simbacoach.com` then `simbacoach.online` correctly cross-referenced the
two and flagged the match, dropping the score from a false 80 down to 75
with an honest, specific reason attached.

## Rendered-DOM extraction (fixes JS-heavy sites)

The extension's background script now injects a small extraction function
into the active tab via `chrome.scripting.executeScript` before calling the
backend. It grabs `document.body.innerText` (visible text only, respects
CSS visibility) and every resolved `<a href>` on the fully rendered page,
and sends both along with the URL. The backend prefers this data when
present; if you call `/analyze` directly (curl, Postman, testing) without
`renderedText`/`renderedLinks`, it transparently falls back to fetching and
parsing static HTML server-side — so the API still works standalone.

Each check result includes a `linkSource` / `textSource` field
(`"rendered-dom"` or `"static-html"`) so you can see which path was used.

## AI content detection + token usage

`checks/aiContent.js` sends up to ~4000 characters of visible page text to
Claude and asks for a structured JSON rating (`aiGeneratedLikelihood`,
`indicators`, `reasoning`). It's treated as a **medium/weak** signal in
scoring, never a strong one, since LLM text-detection is inherently fuzzy.

**Usage is free and unlimited for everyone right now.** Token usage is
still tracked per user (`services/usageTracker.js`) so you have real
numbers when you're ready to introduce a paid tier:

- The extension generates a random `userId` on install (`chrome.storage.local`)
  and sends it with every request. You can see your own ID at the bottom
  of the popup.
- Add your ID to `ADMIN_USER_IDS` in `.env` (comma-separated) to flag
  yourself as admin — admins are already coded to bypass any future limit.
- `FREE_TOKEN_LIMIT` is unset by default (= unlimited). When you're ready
  to gate the free tier, set it to a token count and uncomment the
  enforcement logic described in `usageTracker.js`'s `hasExceededLimit()`
  comment block — non-admins over the limit will get `aiContent.skipped: true`
  with a reason, while the rest of the report (security/WHOIS/blocklist)
  still returns normally.

## Template fingerprinting (scam-farm detection)

`checks/templateFingerprint.js` walks the page's DOM (via the extension's
rendered structure, or static HTML as fallback) and builds a sequence of
tag names in document order — ignoring all text, attributes, and styling.
That sequence is hashed and checked against `data/fingerprints.json`,
which remembers every hash-to-domain mapping seen so far.

If domain B produces the exact same structural hash as domain A, that's
flagged as **medium** severity; once 3+ unrelated domains share one hash,
it escalates to **strong** — this is the clearest signal available for
catching templated scam/phishing "site farms" that swap out branding but
reuse the same page skeleton. No external API or cost is involved.

This starts empty on a fresh install and grows the more real sites you
scan — it only ever compares against domains this specific installation
has actually seen, and gets more useful over time.

## Image reuse detection

`checks/imageReuse.js` works the same way as template fingerprinting, but
for images: it fetches up to 5 image URLs per page (supplied by the
extension's content script — logo, hero image, etc.), computes a
perceptual "average hash" for each via `jimp`, and checks `data/image-hashes.json`
for visually-identical images (allowing a small Hamming-distance tolerance
for recompression) already seen on other domains.

This is meaningfully different from a true reverse-image-search (TinEye,
Google Vision) — it can't tell you an image is a generic stock photo the
first time it's seen. What it CAN catch: the same scam template's exact
logo or hero photo reused across several domains you've scanned before,
which is a strong, free signal once your local database has some history.

Verified end-to-end with real fetched images from a public GitHub repo:
the same image on two different simulated domains was correctly
cross-referenced and flagged; a different image was not.

## Another real bug found through actual usage: fake navigation links

A user testing against a real site (`simbacoach.online`) reported that
its Home/About Us/Contact links did nothing when clicked — no page load,
no error, nothing. The link extraction was silently dropping them: it
only kept `<a>` tags whose `href` started with `http`, so `href="#"`,
empty hrefs, and `javascript:void(0)` links — the exact pattern behind
non-functional decorative nav — were filtered out before they ever
reached the backend. A page with completely fake navigation was scoring
as if it had no navigation problems at all, because the fake links were
invisible to the checker, not passing.

**The fix**: `extension/background.js`'s content-script extraction now
separately detects these — empty/`#`/`javascript:` hrefs, or a `#section`
hash pointing at an element that doesn't exist on the page — captures
their visible text, and sends them to the backend as `renderedDeadEndLinks`.
`checks/brokenLinks.js` flags them, and weights it by how many look like
core navigation (`Home`, `About`, `Contact`, `Services`, `Products` in the
link text): 2+ fake core-nav links escalates to **strong** severity — as
serious as a blocklist hit — since it indicates the site is deliberately
presenting fake structure to look like a complete business, with only
the checkout/payment flow actually functional. That's a materially
different (and more deliberate-looking) problem than an ordinary 404.

Verified with a direct test simulating the exact case reported: three
dead-end nav links (`Home`, `About Us`, `Contact`) dropped a simulated
scenario's score from 68 down to 37 ("High risk"), with the fake-nav
finding correctly surfaced as the top reason.

## Another real bug found: the .env file was never actually loaded

A user reported adding their Google Safe Browsing API key but the tool
kept reporting it as missing. Root cause: `server.js` never called
`require('dotenv').config()` — Node doesn't read `.env` files
automatically, so every value in it was invisible to `process.env`
regardless of what was in the file. Fixed by adding the `dotenv` package
and loading it as the very first line of `server.js`, before anything
else runs. Verified directly: confirmed the key was `undefined` before
the fix and correctly populated after it, using the exact same `.env`
file both times.

## Next steps (not yet built)

1. **True reverse image search** — integrate a paid API (TinEye, Google
   Vision) to catch stock/AI-generated images on their FIRST sighting,
   not just reuse across domains you've already scanned.
2. **Curated known-brand database for typosquat detection** — right now
   `brandSimilarity.js` can only compare against domains this
   installation has personally scanned before. Cross-referencing a
   curated list of well-known official brand domains (or a live search,
   as was done manually to catch the Simba Coach case) would catch
   impersonation on the FIRST scan of a fake domain, not just the second.
3. **Redis-backed caching** — swap the in-memory `Map` cache in
   `server.js` for Redis once you're running this beyond local dev.
4. **CORS lockdown** — once you have a stable extension ID, replace the
   wildcard CORS origin in `server.js` with `chrome-extension://<your-id>`.
5. **Shared fingerprint/image/brand database** — right now each install's
   data files only know about sites it personally scanned. A shared
   backend (all installs contributing to one database) would make
   structure, image, and brand reuse detection dramatically more
   powerful, at the cost of needing real infrastructure (a proper
   database, moderation for bad submissions).

## What couldn't be tested in this development sandbox

**Update: the extension has now been loaded and tested in a real browser**
(by the user, not by me — I still have no browser access here) against a
real site. That test is what surfaced both real bugs described above: the
fabricated-headers bug and the overconfident-scoring bug. Neither would
have been caught by anything I could run in this sandbox alone — real
usage found real problems that unit tests against mocked data didn't.

One correction to earlier notes in this file: I'd said network egress here
was simply "restricted to an allowlist." That's true, but it's more
precise to say the restriction is enforced by a **proxy that returns a
synthetic response** (403 + `x-deny-reason` header) rather than a hard
connection failure — which is exactly what caused the fabricated-findings
bug. I hadn't verified that distinction until debugging this issue.

Everything below is still accurate — written correctly, but not
exercisable live in this sandbox:

- **WHOIS lookups against real domains** — RDAP calls now succeed in
  reaching `rdap.org` (confirmed: got a real `403` response back, not a
  network failure), which is progress over the old raw-WHOIS-only
  approach, but still couldn't get a genuine successful lookup here. Raw
  WHOIS fallback still can't reach port 43. Both failure paths were
  confirmed to degrade gracefully.
- **Google Safe Browsing blocklist calls** — no API key was available in
  this environment. Confirmed the code skips gracefully when the key is
  absent; the actual authenticated call was never exercised.
- **Anthropic API calls for AI-content detection** — `api.anthropic.com`
  is reachable from this sandbox, but no `ANTHROPIC_API_KEY` was available
  to authenticate with. Confirmed the endpoint responds (got a real 401
  for a missing key) and confirmed the skip-gracefully path, and separately
  unit-tested the JSON-parsing/scoring logic with a simulated model
  response — but never ran a real end-to-end model call.
- **True reverse image search** — not built at all (needs a paid
  TinEye/Google Vision API key).

Everything else (headers/HTTPS checks — including the new environment-block
detection, tested against a real blocked request — the broken-link
crawler, including the soft-404 detection tested against a local fake
server, the scoring engine's confidence-gating tested in both directions,
the rendered-DOM extraction fallback behavior, the usage-tracking service,
**template fingerprinting**, **image reuse detection** — fully verified
end-to-end with real images fetched from a public GitHub repo — and
**brand/typosquat similarity detection** — verified live against the
exact real-world case that exposed the original scoring gap) was run and
verified live in this session.

## Notes on accuracy

Treat the final score as a **risk indicator, not a verdict**. Blocklist hits
and domain age are strong signals; broken links and missing headers are
supporting evidence; content/image heuristics (once built) should be
weighted lightly and always shown with their individual reasoning so users
can judge for themselves.