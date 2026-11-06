// Netlify Function: fetches a target URL's response headers server-side
// (avoids browser CORS restrictions on reading cross-origin headers)
// and runs a basic security header / TLS posture analysis.

exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

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
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Only http/https URLs are supported" }) };
  }

  try {
    const res = await fetch(url.toString(), {
      method: "GET",
      redirect: "follow",
      headers: { "User-Agent": "SecurityHeadersAnalyzer/1.0 (+portfolio-project)" },
    });

    const responseHeaders = {};
    res.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });

    const checks = analyzeHeaders(responseHeaders, url);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        url: url.toString(),
        finalUrl: res.url,
        status: res.status,
        headers: responseHeaders,
        checks,
        score: scoreChecks(checks),
      }),
    };
  } catch (err) {
    return {
      statusCode: 502,
      headers,
      body: JSON.stringify({ error: `Could not reach target: ${err.message}` }),
    };
  }
};

function analyzeHeaders(h, url) {
  const checks = [];

  checks.push({
    id: "hsts",
    label: "Strict-Transport-Security",
    pass: !!h["strict-transport-security"],
    detail: h["strict-transport-security"] || "Not set — site does not force HTTPS on return visits.",
    severity: "high",
  });

  checks.push({
    id: "csp",
    label: "Content-Security-Policy",
    pass: !!h["content-security-policy"],
    detail: h["content-security-policy"]
      ? truncate(h["content-security-policy"], 160)
      : "Not set — no restriction on script/style/resource sources, raises XSS impact.",
    severity: "high",
  });

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
    detail: h["referrer-policy"] || "Not set — full referrer URL (including paths/query strings) may leak to third parties.",
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

  const setCookie = h["set-cookie"] || "";
  checks.push({
    id: "cookies",
    label: "Cookie flags (Secure/HttpOnly/SameSite)",
    pass: !setCookie || (/secure/i.test(setCookie) && /httponly/i.test(setCookie)),
    detail: setCookie
      ? truncate(setCookie, 160)
      : "No Set-Cookie header observed on this request.",
    severity: "medium",
  });

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

function scoreChecks(checks) {
  const weight = { high: 3, medium: 2, low: 1 };
  const total = checks.reduce((sum, c) => sum + weight[c.severity], 0);
  const earned = checks.reduce((sum, c) => sum + (c.pass ? weight[c.severity] : 0), 0);
  return Math.round((earned / total) * 100);
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n) + "…" : str;
      }
