/**
 * networkGuard.js
 *
 * Some restrictive network environments (this sandbox included) use an
 * egress proxy that returns a synthetic HTTP response — often a 403 with
 * an `x-deny-reason` header — instead of actually blocking the TCP
 * connection. A naive fetch() treats that as a normal successful
 * response, and any check that inspects headers/body without verifying
 * it actually reached the real site will silently analyze the proxy's
 * OWN block page and report fabricated findings about the target site.
 *
 * This happened for real during development: a headers check against a
 * blocked domain reported "missing security headers" that were actually
 * just the properties of the sandbox's denial page, not the real site.
 *
 * Any check module that fetches a URL and inspects the response should
 * call isEnvironmentBlocked(res) first and bail out honestly rather than
 * evaluating a page that was never actually reached.
 */

function isEnvironmentBlocked(res) {
  return res.headers.has('x-deny-reason');
}

function getDenyReason(res) {
  return res.headers.get('x-deny-reason') || 'unknown';
}

module.exports = { isEnvironmentBlocked, getDenyReason };
