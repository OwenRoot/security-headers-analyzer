# Headerscope — Security Header Analyzer

Enter any URL and it fetches the live HTTP response headers server-side, then checks them
against the controls that defend against clickjacking, XSS, cookie theft, MIME-sniffing,
and protocol downgrade attacks — the same checks a web security review starts with.

**Live tool is the proof** — no lab, no screenshots needed. Anyone (recruiters included)
can paste a URL and watch it work.

## How it works

- `index.html` — static frontend, dark terminal-style UI, no build step
- `netlify/functions/check-headers.js` — a Netlify serverless function that does the
  actual HTTP GET to the target site (server-side, so there's no browser CORS problem
  reading cross-origin headers), then scores the response against 9 checks:
  HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, HTTPS enforcement, cookie flags, and server header disclosure.

Weighted score (high/medium/low impact per check) renders as a ring + per-check pass/fail
breakdown with the actual header value or what's missing.

## Deploy — no local machine needed

**Option A: GitHub + Netlify (recommended)**
1. Create a new GitHub repo from your phone/browser (github.com → New repository).
2. Use GitHub's web upload (drag files into the repo page, or "Add file → Upload files")
   to upload all files in this folder, keeping the `netlify/functions/` structure intact.
3. Go to [app.netlify.com](https://app.netlify.com) → "Add new site" → "Import an existing
   project" → connect GitHub → pick the repo. Netlify auto-detects `netlify.toml`.
4. Deploy. No build command needed — it's static + functions.

**Option B: Netlify Drop (fastest, but no function support)**
[app.netlify.com/drop](https://app.netlify.com/drop) only works for static files dragged
in — it won't run the serverless function, so header fetching won't work. Use Option A if
you want the functional version.

## Local dev (optional, once you have a machine)

```bash
npm install -g netlify-cli
netlify dev
```

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
an edge WAF. Documented here rather than overclaimed.

## Scoring weights

Each check is weighted by impact: **high** (3 pts) — HSTS, CSP, HTTPS enforcement;
**medium** (2 pts) — X-Frame-Options, cookie Secure/HttpOnly; **low** (1 pt) —
X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie SameSite, Server
header disclosure. Score = (points earned / points available) × 100. A header that's
present but structurally weak (e.g. a CSP full of wildcards and `unsafe-inline`) earns
**half credit**, not full credit — presence alone no longer passes a check.

## Demo targets

Scanning a well-configured site (e.g. a modern SaaS homepage) and a poorly-configured
one side by side shows the score actually move — if every target scores the same,
the checks aren't discriminating. Worth including both in a demo/writeup rather than
just one high-scoring example.

## CV line

> Headerscope: HTTP security header analyzer. Netlify serverless function fetches
> headers server-side (read-only GET) and scores 9 checks including HSTS, CSP, cookie
> flags and clickjacking protections. Live demo + GitHub.

## Notes for your portfolio writeup

- This mirrors what tools like securityheaders.com check, built from scratch to
  demonstrate understanding of *why* each header matters and how it can be bypassed,
  not just whether it's present.
- The function only performs read-only GET requests and does not store, log, or forward
  scanned URLs anywhere.
- Possible extensions: TLS certificate/cipher inspection (via an external TLS API, since
  Node's fetch doesn't expose cert details), historical scan comparison, a real
  distributed rate limiter.
