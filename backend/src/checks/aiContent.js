/**
 * checkAiContent(url, { userId, renderedText })
 *
 * Scrapes visible text from the page and asks an LLM (via OpenRouter)
 * to rate how likely it is to be AI-generated / generic scam-template
 * boilerplate, with structured reasoning. This is a WEAK/MEDIUM
 * confidence signal on its own — LLM text-detection is inherently fuzzy
 * — so it's weighted accordingly in scoring.js and always shown with
 * its reasoning so the user can judge for themselves.
 *
 * Requires OPENROUTER_API_KEY in your environment.
 * Get a key at https://openrouter.ai/keys
 *
 * Model is configurable via AI_CONTENT_MODEL (OpenRouter model id,
 * e.g. anthropic/claude-haiku-4.5, google/gemini-2.0-flash-lite-001,
 * openai/gpt-4o-mini, or any free model).
 *
 * Note: this fetches raw HTML server-side when the extension does not
 * supply renderedText, so it will miss content that's rendered
 * client-side via JS. Prefer the extension path for JS-heavy sites.
 */

const cheerio = require('cheerio');
const { recordUsage, hasExceededLimit, isAdmin } = require('../services/usageTracker');
const { isEnvironmentBlocked, getDenyReason } = require('../services/networkGuard');

const OPENROUTER_ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions';
const MODEL = process.env.AI_CONTENT_MODEL || 'anthropic/claude-haiku-4.5';
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
  const apiKey = process.env.OPENROUTER_API_KEY;

  if (!apiKey) {
    return { ok: false, skipped: true, reason: 'OPENROUTER_API_KEY not set' };
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
    const res = await fetch(OPENROUTER_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
        // Optional but recommended by OpenRouter for rankings / attribution
        'HTTP-Referer': process.env.OPENROUTER_HTTP_REFERER || 'https://github.com/mwasgibson/site-trust-checker',
        'X-Title': process.env.OPENROUTER_APP_TITLE || 'Site Trust Checker',
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 400,
        temperature: 0.2,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          {
            role: 'user',
            content: `Page URL: ${url}\n\nVisible page text:\n"""\n${text}\n"""`,
          },
        ],
      }),
      signal: AbortSignal.timeout(30000),
    });

    if (!res.ok) {
      const errText = await res.text();
      return { ok: false, error: `OpenRouter API returned ${res.status}: ${errText}` };
    }

    const data = await res.json();

    // OpenAI-compatible usage fields (OpenRouter normalizes these)
    const inputTokens = data.usage?.prompt_tokens || 0;
    const outputTokens = data.usage?.completion_tokens || 0;

    const usageRecord = recordUsage(userId, {
      inputTokens,
      outputTokens,
    });

    const content = data.choices?.[0]?.message?.content;
    if (!content) {
      return { ok: false, error: 'No text response from model', raw: data };
    }

    let parsed;
    try {
      const cleaned = content.replace(/```json|```/g, '').trim();
      parsed = JSON.parse(cleaned);
    } catch {
      return { ok: false, error: 'Could not parse model response as JSON', raw: content };
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
      model: MODEL,
      textSource: source,
      usage: {
        inputTokens,
        outputTokens,
        userTotalTokens: usageRecord.totalTokens,
        isAdmin: isAdmin(userId),
      },
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = { checkAiContent };
