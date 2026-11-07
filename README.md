# Headerscope

An HTTP security header analyzer. Paste a URL, and it fetches the live response headers
server-side and checks them against the controls that defend against clickjacking, XSS,
cookie theft, MIME-sniffing, and protocol downgrade attacks — the same checks a web
security review starts with.

Unlike a simple presence check, Headerscope looks at whether each header is actually
doing its job: a CSP full of wildcards and `unsafe-inline`, or an HSTS header with
`preload` but missing `includeSubDomains`, won't quietly pass.

**[Live demo →](https://headerscope-owenrxxt.netlify.app)**

## What it checks

- **Strict-Transport-Security** — presence, `max-age`, and real preload-list eligibility
- **Content-Security-Policy** — presence, plus `unsafe-inline` / `unsafe-eval` / wildcard
  sources and missing `object-src`, `base-uri`, or `frame-ancestors`
- **X-Frame-Options** and clickjacking coverage via CSP `frame-ancestors`
- **X-Content-Type-Options, Referrer-Policy, Permissions-Policy**
- **Cookie flags** — Secure, HttpOnly, and SameSite checked independently, across every
  `Set-Cookie` header observed (not just the first one)
- **HTTPS enforcement** and **Server header** version disclosure

## How it works

- `index.html` — static frontend, no build step
- `netlify/functions/check-headers.js` — a Netlify serverless function that performs the
  actual HTTP `GET` to the target site server-side (avoiding the CORS restriction that
  stops a browser from reading cross-origin headers directly), then scores the response

## Security design

**SSRF protection.** Only `http`/`https` are allowed. The hostname is resolved via
`dns.lookup` and checked against loopback, private (RFC1918), link-local (including
the `169.254.169.254` cloud metadata address), CGNAT, and IPv6 equivalents *before*
connecting. Node's `URL` parser already normalizes decimal/hex/short IPv4 literals
(`http://2130706433/` → `127.0.0.1`) to dotted form, so that check catches those for
free. Redirects are followed manually (`redirect: "manual"`), capped at 3 hops, and
**every hop is re-validated** the same way — a public URL that 302s to
`http://127.0.0.1` is blocked on the second hop, not just the first. Requests time out
after 5s, and the response body is never read (headers only), so there's no way to use
this as a bulk-download proxy.

Tested against: `localhost`, `127.0.0.1`, `::1`, `10.0.0.1`, `192.168.1.1`,
`169.254.169.254` (cloud metadata), decimal/hex-encoded loopback, `localtest.me`
(public DNS name that resolves to `127.0.0.1` — confirms the check validates the
*resolved* IP, not just the hostname string), `file://`/`ftp://` schemes, and an
open redirect to an internal address.

**Rate limiting.** A lightweight in-memory counter (10 req/min) throttles abuse within
a single warm function instance. This is **not** a substitute for a real distributed
rate limiter — Netlify Functions can run as multiple concurrent instances with no
shared state, so a determined abuser spread across instances isn't meaningfully
slowed. A production deployment would put this behind Netlify's own rate limiting or
an edge WAF.

## Scoring

Each check is weighted by impact: **high** (3 pts) — HSTS, CSP, HTTPS enforcement;
**medium** (2 pts) — X-Frame-Options, cookie Secure/HttpOnly; **low** (1 pt) —
X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie SameSite, Server
header disclosure. Score = (points earned / points available) × 100. A header that's
present but structurally weak (e.g. a CSP full of wildcards and `unsafe-inline`) earns
half credit, not full credit — presence alone doesn't pass a check.

## Local development

```bash
npm install -g netlify-cli
netlify dev
```

## Privacy

The function performs read-only `GET` requests only. Scanned URLs are not stored,
logged, or forwarded anywhere.

## Possible extensions

- TLS certificate/cipher inspection (via an external TLS API, since Node's `fetch`
  doesn't expose certificate details)
- Historical scan comparison
- A real distributed rate limiter

## Built by

[OwenRoot](https://github.com/OwenRoot)
