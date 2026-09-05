// Pure cookie helpers: no chrome.* usage so these are unit-testable in Node.
// SECURITY: none of these functions may ever log or serialize cookie values
// anywhere except into the outbound sink payload itself.

const SAMESITE_MAP = {
  no_restriction: "None",
  lax: "Lax",
  strict: "Strict",
  // "unspecified" intentionally omitted -> CDP default applies
};

/**
 * Map a chrome.cookies.Cookie to a CDP CookieParam (Storage.setCookies /
 * Network.setCookie shape). Returns null when the cookie violates
 * __Host-/__Secure- prefix rules; callers count those as "skipped" instead of
 * failing the whole sync.
 */
export function toCdpCookie(c) {
  if (!c || typeof c.name !== "string" || typeof c.value !== "string") return null;

  if (c.name.startsWith("__Host-")) {
    // __Host- requires Secure, Path=/ and a host-only domain (no leading dot).
    if (!c.secure || c.path !== "/" || !c.domain || c.domain.startsWith(".")) return null;
    const out = {
      name: c.name,
      value: c.value,
      url: `https://${c.domain}/`,
      path: "/",
      secure: true,
      httpOnly: !!c.httpOnly,
    };
    applySameSite(out, c);
    applyExpiry(out, c);
    return out;
  }

  if (c.name.startsWith("__Secure-") && !c.secure) return null;
  if (!c.domain) return null;

  const out = {
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path || "/",
    secure: !!c.secure,
    httpOnly: !!c.httpOnly,
  };
  applySameSite(out, c);
  applyExpiry(out, c);
  return out;
}

function applySameSite(out, c) {
  const mapped = SAMESITE_MAP[c.sameSite];
  if (mapped) out.sameSite = mapped;
}

function applyExpiry(out, c) {
  // Session cookies (c.session === true or no expirationDate) omit `expires`.
  if (!c.session && typeof c.expirationDate === "number" && Number.isFinite(c.expirationDate)) {
    out.expires = Math.floor(c.expirationDate);
  }
}

/**
 * Filter cookies by a domain allowlist. An empty/absent allowlist passes
 * everything through. Allowlist entries match the domain itself and any
 * subdomain ("example.com" matches "example.com", ".example.com",
 * "a.example.com" but not "notexample.com").
 */
export function filterByAllowlist(cookies, allowlist) {
  if (!Array.isArray(allowlist) || allowlist.length === 0) return cookies;
  const entries = allowlist
    .map((d) => String(d).trim().toLowerCase().replace(/^\./, ""))
    .filter(Boolean);
  if (entries.length === 0) return cookies;
  return cookies.filter((c) => {
    const domain = String(c.domain || "").toLowerCase().replace(/^\./, "");
    return entries.some((e) => domain === e || domain.endsWith("." + e));
  });
}

/** Map an array of chrome cookies; returns {cookies, skipped}. */
export function mapCookies(chromeCookies) {
  const cookies = [];
  let skipped = 0;
  for (const c of chromeCookies) {
    const mapped = toCdpCookie(c);
    if (mapped) cookies.push(mapped);
    else skipped++;
  }
  return { cookies, skipped };
}
