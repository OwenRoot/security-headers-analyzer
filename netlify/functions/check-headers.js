// Netlify Function: fetches a target URL's response headers server-side
// (avoids browser CORS restrictions on reading cross-origin headers)
// and runs a security header / cookie / CSP posture analysis.
//
// SSRF protections: only http/https, hostname resolved and checked against
// private/loopback/link-local ranges before connecting, every redirect hop
// re-validated the same way (redirect: "manual", max 3 hops), 5s timeout,
// response body never consumed (headers only).
//
// Rate limiting: a lightweight per-instance counter. Netlify Functions are
// stateless across cold starts and can run as multiple concurrent instances,
// so this is NOT a substitute for a real rate limiter (e.g. Netlify Rate
// Limiting / an edge-level WAF) in a production deployment — it only
// throttles a single warm instance under light, non-distributed abuse.
// Documented here rather than hidden, since presenting it as more than that
// would itself be a credibility problem for a "security tool."

const dns = require("dns").promises;
const net = require("net");

const MAX_REDIRECTS = 3;
const TIMEOUT_MS = 5000;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 10;

// Reset per cold start; shared only within one warm instance.
const rateBuckets = new Map();

exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const clientIp =
    (event.headers && (event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"])) ||
    "unknown";

  const rateCheck = checkRateLimit(clientIp);
  if (!rateCheck.allowed) {
    return {
      statusCode: 429,
      headers: { ...headers, "Retry-After": String(rateCheck.retryAfterSeconds) },
      body: JSON.stringify({
        error: `Rate limit exceeded (${RATE_LIMIT_MAX} requests/min per instance). Try again in ${rateCheck.retryAfterSeconds}s.`,
      }),
    };
  }

  const target = event.queryStringParameters && event.queryStringParameters.url;
  if (!target) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing url parameter" }) };
  }

  let url;
  try {
    url = new URL(target.startsWith("http") ? target : `https://${target}`);
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Invalid URL" }) };
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: "Only http and https URLs are allowed (no file:, ftp:, etc.)" }),
    };
  }

  try {
    const result = await safeFetchHeaders(url);
    const checks = analyzeHeaders(result.headers, result.finalUrl);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        url: url.toString(),
        finalUrl: result.finalUrl.toString(),
        status: result.status,
        redirectHops: result.hops,
        headers: result.headers,
        checks,
        score: scoreChecks(checks),
      }),
    };
  } catch (err) {
    if (err.code === "SSRF_BLOCKED") {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: `Blocked: target resolves to a private or reserved address (${err.detail}).` }),
      };
    }
    if (err.code === "TIMEOUT") {
      return { statusCode: 504, headers, body: JSON.stringify({ error: "Request timed out after 5s." }) };
    }
    if (err.code === "TOO_MANY_REDIRECTS") {
      return { statusCode: 400, headers, body: JSON.stringify({ error: "Too many redirects (max 3)." }) };
    }
    return {
      statusCode: 502,
      headers,
      body: JSON.stringify({ error: `Could not reach target: ${err.message}` }),
    };
  }
};

function checkRateLimit(clientIp) {
  const now = Date.now();
  const bucket = rateBuckets.get(clientIp) || [];
  const recent = bucket.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);

  if (recent.length >= RATE_LIMIT_MAX) {
    const oldest = Math.min(...recent);
    return { allowed: false, retryAfterSeconds: Math.ceil((RATE_LIMIT_WINDOW_MS - (now - oldest)) / 1000) };
  }

  recent.push(now);
  rateBuckets.set(clientIp, recent);
  return { allowed: true };
}

// --- SSRF-safe fetch -------------------------------------------------

async function safeFetchHeaders(initialUrl) {
  let currentUrl = initialUrl;
  let hops = 0;

  while (true) {
    await assertPublicHost(currentUrl.hostname);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    let res;
    try {
      res = await fetch(currentUrl.toString(), {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": "Headerscope/1.1 (+security-review-tool)" },
      });
    } catch (err) {
      if (err.name === "AbortError") {
        const e = new Error("Timed out");
        e.code = "TIMEOUT";
        throw e;
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }

    // Never read the response body — we only need headers, and this avoids
    // downloading arbitrary amounts of data from the target.
    if (res.body && typeof res.body.cancel === "function") {
      res.body.cancel().catch(() => {});
    }

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      hops += 1;
      if (hops > MAX_REDIRECTS) {
        const e = new Error("Too many redirects");
        e.code = "TOO_MANY_REDIRECTS";
        throw e;
      }
      const location = res.headers.get("location");
      if (!location) break; // redirect with no Location — treat current response as final
      currentUrl = new URL(location, currentUrl);
      if (!["http:", "https:"].includes(currentUrl.protocol)) {
        const e = new Error(`Redirect to disallowed protocol ${currentUrl.protocol}`);
        e.code = "SSRF_BLOCKED";
        e.detail = currentUrl.protocol;
        throw e;
      }
      continue; // loop re-validates the new host before connecting
    }

    const responseHeaders = {};
    // getSetCookie() preserves multiple Set-Cookie headers separately;
    // headers.forEach() would otherwise collapse them into one comma-joined
    // string and hide all but the first cookie.
    const setCookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    res.headers.forEach((value, key) => {
      if (key.toLowerCase() === "set-cookie") return;
      responseHeaders[key.toLowerCase()] = value;
    });
    if (setCookies.length) responseHeaders["set-cookie"] = setCookies;

    return { headers: responseHeaders, finalUrl: currentUrl, status: res.status, hops };
  }
}

async function assertPublicHost(hostname) {
  // Strip IPv6 brackets if present (new URL() includes them in .hostname for literals)
  const bare = hostname.replace(/^\[/, "").replace(/\]$/, "");

  if (net.isIP(bare)) {
    if (isPrivateOrReservedIp(bare)) {
      const e = new Error("private IP literal");
      e.code = "SSRF_BLOCKED";
      e.detail = bare;
      throw e;
    }
    return;
  }

  if (bare.toLowerCase() === "localhost") {
    const e = new Error("localhost");
    e.code = "SSRF_BLOCKED";
    e.detail = "localhost";
    throw e;
  }

  let addresses;
  try {
    addresses = await dns.lookup(bare, { all: true, verbatim: true });
  } catch (err) {
    const e = new Error(`DNS resolution failed: ${err.message}`);
    e.code = "DNS_FAIL";
    throw e;
  }

  for (const { address } of addresses) {
    if (isPrivateOrReservedIp(address)) {
      const e = new Error("resolved to private address");
      e.code = "SSRF_BLOCKED";
      e.detail = `${bare} -> ${address}`;
      throw e;
    }
  }
}

function isPrivateOrReservedIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;
    if (a === 127) return true; // loopback
    if (a === 10) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 169 && b === 254) return true; // link-local, incl. cloud metadata (169.254.169.254)
    if (a === 0) return true; // "this network"
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
    return false;
  }
  if (version === 6) {
    const norm = ip.toLowerCase();
    if (norm === "::1") return true; // loopback
    if (norm === "::") return true; // unspecified
    if (norm.startsWith("fe80:") || norm.startsWith("fe8") || norm.startsWith("fe9") || norm.startsWith("fea") || norm.startsWith("feb")) return true; // link-local
    if (norm.startsWith("fc") || norm.startsWith("fd")) return true; // unique local (private)
    if (norm.startsWith("::ffff:")) {
      // IPv4-mapped IPv6 — check the embedded IPv4 address too
      const mapped = norm.split(":").pop();
      if (net.isIP(mapped) === 4) return isPrivateOrReservedIp(mapped);
    }
    return false;
  }
  return true; // unparseable — fail closed
}

// --- Header analysis ---------------------------------------------------

function analyzeHeaders(h, url) {
  const checks = [];

  checks.push(checkHSTS(h));
  checks.push(checkCSP(h));

  checks.push({
    id: "xfo",
    label: "X-Frame-Options",
    pass: !!h["x-frame-options"] || (h["content-security-policy"] || "").includes("frame-ancestors"),
    detail: h["x-frame-options"] || "Not set — page may be vulnerable to clickjacking (unless CSP frame-ancestors is set).",
    severity: "medium",
  });

  checks.push({
    id: "xcto",
    label: "X-Content-Type-Options",
    pass: h["x-content-type-options"] === "nosniff",
    detail: h["x-content-type-options"] || "Not set — browsers may MIME-sniff responses, enabling some content-type attacks.",
    severity: "low",
  });

  checks.push({
    id: "referrer",
    label: "Referrer-Policy",
    pass: !!h["referrer-policy"],
    detail: h["referrer-policy"]
      ? h["referrer-policy"]
      : "Not set explicitly. Modern browsers now default to strict-origin-when-cross-origin, which is a reasonable floor — but setting it explicitly removes ambiguity across older clients.",
    severity: "low",
  });

  checks.push({
    id: "permissions",
    label: "Permissions-Policy",
    pass: !!h["permissions-policy"],
    detail: h["permissions-policy"] ? truncate(h["permissions-policy"], 160) : "Not set — no restriction on camera/mic/geolocation API access by embedded content.",
    severity: "low",
  });

  checks.push({
    id: "https",
    label: "HTTPS enforced",
    pass: url.protocol === "https:",
    detail: url.protocol === "https:" ? "Site served over HTTPS." : "Site is not served over HTTPS.",
    severity: "high",
  });

  checks.push(...checkCookies(h["set-cookie"]));

  checks.push({
    id: "server",
    label: "Server header disclosure",
    pass: !h["server"] || !/\d/.test(h["server"]),
    detail: h["server"]
      ? `Server header reveals: "${h["server"]}" — version numbers help attackers target known CVEs.`
      : "No Server header disclosed.",
    severity: "low",
  });

  return checks;
}

function checkHSTS(h) {
  const raw = h["strict-transport-security"];
  if (!raw) {
    return {
      id: "hsts",
      label: "Strict-Transport-Security",
      pass: false,
      detail: "Not set — site does not force HTTPS on return visits.",
      severity: "high",
    };
  }

  const maxAgeMatch = raw.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const hasIncludeSub = /includesubdomains/i.test(raw);
  const hasPreload = /preload/i.test(raw);

  if (hasPreload && (!hasIncludeSub || maxAge < 31536000)) {
    return {
      id: "hsts",
      label: "Strict-Transport-Security",
      pass: true,
      detail: `${raw} — preload is set but the directive doesn't meet the preload-list requirements (needs includeSubDomains and max-age >= 31536000). As written, it won't qualify for preload submission.`,
      severity: "high",
    };
  }

  return { id: "hsts", label: "Strict-Transport-Security", pass: true, detail: raw, severity: "high" };
}

function checkCSP(h) {
  const raw = h["content-security-policy"];
  if (!raw) {
    return {
      id: "csp",
      label: "Content-Security-Policy",
      pass: false,
      detail: "Not set — no restriction on script/style/resource sources, raises XSS impact.",
      severity: "high",
    };
  }

  const issues = [];
  if (/unsafe-inline/i.test(raw)) issues.push("allows 'unsafe-inline'");
  if (/unsafe-eval/i.test(raw)) issues.push("allows 'unsafe-eval'");
  if (/(^|[\s;])\*(?=[\s;]|$)/.test(raw) || /src\s+\*/i.test(raw)) issues.push("uses a bare '*' source somewhere");
  if (!/object-src/i.test(raw)) issues.push("no object-src directive");
  if (!/base-uri/i.test(raw)) issues.push("no base-uri directive");
  if (!/frame-ancestors/i.test(raw)) issues.push("no frame-ancestors directive");

  if (issues.length) {
    return {
      id: "csp",
      label: "Content-Security-Policy",
      pass: true,
      detail: `Present, but weak: ${issues.join(", ")}. ${truncate(raw, 120)}`,
      severity: "high",
      weak: true,
    };
  }

  return { id: "csp", label: "Content-Security-Policy", pass: true, detail: truncate(raw, 160), severity: "high" };
}

function checkCookies(setCookieHeader) {
  const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : setCookieHeader ? [setCookieHeader] : [];

  if (!cookies.length) {
    return [
      {
        id: "cookies",
        label: "Cookie flags (Secure/HttpOnly)",
        pass: true,
        detail: "No Set-Cookie header observed on this request.",
        severity: "medium",
      },
    ];
  }

  const missingSecureOrHttpOnly = cookies.filter((c) => !/secure/i.test(c) || !/httponly/i.test(c));
  const missingSameSite = cookies.filter((c) => !/samesite/i.test(c));

  return [
    {
      id: "cookies",
      label: "Cookie flags (Secure/HttpOnly)",
      pass: missingSecureOrHttpOnly.length === 0,
      detail:
        missingSecureOrHttpOnly.length === 0
          ? `${cookies.length} cookie(s) observed, all set Secure and HttpOnly.`
          : `${missingSecureOrHttpOnly.length} of ${cookies.length} cookie(s) missing Secure and/or HttpOnly. Example: ${truncate(missingSecureOrHttpOnly[0], 120)}`,
      severity: "medium",
    },
    {
      id: "cookie-samesite",
      label: "Cookie SameSite attribute",
      pass: missingSameSite.length === 0,
      detail:
        missingSameSite.length === 0
          ? `All ${cookies.length} cookie(s) set SameSite.`
          : `${missingSameSite.length} of ${cookies.length} cookie(s) have no SameSite attribute. Browsers increasingly default missing SameSite to Lax, but setting it explicitly is safer. Example: ${truncate(missingSameSite[0], 120)}`,
      severity: "low",
    },
  ];
}

function scoreChecks(checks) {
  const weight = { high: 3, medium: 2, low: 1 };
  const total = checks.reduce((sum, c) => sum + weight[c.severity], 0);
  // A "weak" pass (e.g. CSP present but full of holes) earns half credit
  // instead of full credit, so a wildcard CSP doesn't score the same as a
  // tight one.
  const earned = checks.reduce((sum, c) => {
    if (!c.pass) return sum;
    return sum + (c.weak ? weight[c.severity] * 0.5 : weight[c.severity]);
  }, 0);
  return Math.round((earned / total) * 100);
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n) + "…" : str;
}
