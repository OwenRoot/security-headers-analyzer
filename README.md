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

## Notes for your portfolio writeup

- This mirrors what tools like securityheaders.com check, built from scratch to
  demonstrate understanding of *why* each header matters, not just that it exists.
- The function only performs read-only GET requests and does not store, log, or forward
  scanned URLs anywhere.
- Possible extensions: TLS certificate/cipher inspection (via an external TLS API, since
  Node's fetch doesn't expose cert details), historical scan comparison, CSP policy
  linting (flagging `unsafe-inline`/`unsafe-eval`).
