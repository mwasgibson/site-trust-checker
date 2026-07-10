/**
 * checkAiContent(url, { userId })
 *
 * Scrapes visible text from the page and asks Claude to rate how
 * likely it is to be AI-generated / generic scam-template boilerplate,
 * with structured reasoning. This is a WEAK/MEDIUM confidence signal
 * on its own — LLM text-detection is inherently fuzzy — so it's
 * weighted accordingly in scoring.js and always shown with its
 * reasoning so the user can judge for themselves.
 *
 * Requires ANTHROPIC_API_KEY in your environment.
 *
 * Note: this fetches raw HTML server-side, so it will miss content
 * that's rendered client-side via JS. If you find that's a problem
 * for the sites you're checking, move the text extraction into the
 * extension's content script instead (it sees the fully rendered DOM)
 * and pass the text to this module rather than the URL.
 */

const cheerio = require('cheerio');
const { recordUsage, hasExceededLimit, isAdmin } = require('../services/usageTracker');
const { isEnvironmentBlocked, getDenyReason } = require('../services/networkGuard');

const ANTHROPIC_ENDPOINT = 'https://api.anthropic.com/v1/messages';
const MODEL = process.env.AI_CONTENT_MODEL || 'claude-haiku-4-5-20251001';
const MAX_TEXT_CHARS = 4000; // keep token cost predictable

const SYSTEM_PROMPT = `You analyze website text to assess whether it reads as AI-generated or generic scam/template boilerplate, as opposed to genuine, specific, human-written business content.

Respond with ONLY a JSON object, no markdown fences, no preamble, in exactly this shape:
{
  "aiGeneratedLikelihood": <integer 0-100>,
  "isGenericTemplate": <boolean>,
  "indicators": [<short strings, max 5, each under 12 words>],
  "reasoning": "<1-2 sentence summary>"
}

Guidance:
- High likelihood: vague mission statements, no specific names/dates/numbers, repetitive filler phrasing, generic superlatives ("best-in-class", "cutting-edge") with no substantiation, copy that could apply to literally any business in the category.
- Low likelihood: specific, verifiable details (real names, dates, numbers, concrete claims), distinctive voice, content that would be hard to reuse verbatim on an unrelated site.
- Be conservative — small businesses with simple, plain writing are NOT automatically high likelihood. Reserve high scores for text that is clearly templated or vacuous.`;

function extractVisibleText(html) {
  const $ = cheerio.load(html);
  $('script, style, noscript, svg').remove();
  const text = $('body').text().replace(/\s+/g, ' ').trim();
  return text.slice(0, MAX_TEXT_CHARS);
}

async function checkAiContent(url, { userId, renderedText } = {}) {
  const apiKey = process.env.ANTHROPIC_API_KEY;

  if (!apiKey) {
    return { ok: false, skipped: true, reason: 'ANTHROPIC_API_KEY not set' };
  }

  if (hasExceededLimit(userId)) {
    return {
      ok: false,
      skipped: true,
      reason: 'Free token limit reached for this user',
      isAdmin: isAdmin(userId),
    };
  }

  let text = renderedText && renderedText.trim().length >= 50 ? renderedText.trim() : null;
  let source = text ? 'rendered-dom' : null;

  if (!text) {
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
      text = extractVisibleText(html);
      source = 'static-html';
    } catch (err) {
      return { ok: false, error: `Could not fetch page text: ${err.message}` };
    }
  }

  if (!text || text.length < 50) {
    return {
      ok: false,
      skipped: true,
      reason: 'Not enough visible text to analyze (likely JS-rendered page, and no rendered text was supplied by the extension)',
    };
  }

  try {
    const res = await fetch(ANTHROPIC_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 400,
        system: SYSTEM_PROMPT,
        messages: [
          {
            role: 'user',
            content: `Page URL: ${url}\n\nVisible page text:\n"""\n${text}\n"""`,
          },
        ],
      }),
      signal: AbortSignal.timeout(20000),
    });

    if (!res.ok) {
      const errText = await res.text();
      return { ok: false, error: `Anthropic API returned ${res.status}: ${errText}` };
    }

    const data = await res.json();

    // Track token usage for future subscription gating
    const usageRecord = recordUsage(userId, {
      inputTokens: data.usage?.input_tokens || 0,
      outputTokens: data.usage?.output_tokens || 0,
    });

    const textBlock = data.content?.find((c) => c.type === 'text');
    if (!textBlock) {
      return { ok: false, error: 'No text response from model' };
    }

    let parsed;
    try {
      const cleaned = textBlock.text.replace(/```json|```/g, '').trim();
      parsed = JSON.parse(cleaned);
    } catch {
      return { ok: false, error: 'Could not parse model response as JSON', raw: textBlock.text };
    }

    let tier = null;
    if (parsed.aiGeneratedLikelihood >= 70) tier = 'medium';
    else if (parsed.aiGeneratedLikelihood >= 40) tier = 'weak';

    return {
      ok: true,
      aiGeneratedLikelihood: parsed.aiGeneratedLikelihood,
      isGenericTemplate: parsed.isGenericTemplate,
      indicators: parsed.indicators || [],
      reasoning: parsed.reasoning,
      tier,
      textSource: source,
      usage: {
        inputTokens: data.usage?.input_tokens || 0,
        outputTokens: data.usage?.output_tokens || 0,
        userTotalTokens: usageRecord.totalTokens,
        isAdmin: isAdmin(userId),
      },
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = { checkAiContent };
