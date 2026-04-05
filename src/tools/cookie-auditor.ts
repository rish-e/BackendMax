// =============================================================================
// backend-max — Cookie Security Auditor
//
// Fetches a URL and inspects all Set-Cookie response headers for security
// best practices: Secure, HttpOnly, SameSite, Path/Domain scope, and
// session cookie identification.
// =============================================================================

import type { Issue, IssueCategory, Severity } from "../types.js";
import { generateIssueId } from "../utils/helpers.js";

const CATEGORY: IssueCategory = "cookies";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CookieAuditResult {
  url: string;
  issues: Issue[];
  summary: {
    totalCookies: number;
    secureCookies: number;
    httpOnlyCookies: number;
    sameSiteCookies: number;
    sessionCookiesFound: string[];
    score: number; // 0-100
  };
}

// ---------------------------------------------------------------------------
// Cookie parsing
// ---------------------------------------------------------------------------

/** Patterns that indicate a cookie is likely a session/auth token. */
const SESSION_PATTERNS = [
  /^sess/i,
  /session/i,
  /^sid$/i,
  /^s_id$/i,
  /token/i,
  /^jwt/i,
  /^auth/i,
  /^access[-_]?token/i,
  /^refresh[-_]?token/i,
  /^id[-_]?token/i,
  /^csrf/i,
  /^xsrf/i,
  /^connect\.sid$/i,
  /^__session/i,
  /^__host-/i,
  /^__secure-/i,
];

interface ParsedCookie {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null; // "strict" | "lax" | "none" | null
  path: string | null;
  domain: string | null;
  maxAge: number | null;
  expires: string | null;
  isSessionLike: boolean;
}

/**
 * Parses a single Set-Cookie header string into a structured object.
 */
function parseCookie(raw: string): ParsedCookie {
  const parts = raw.split(";").map((p) => p.trim());
  const [nameValue, ...attrs] = parts;

  // Extract name=value
  const eqIdx = nameValue.indexOf("=");
  const name = eqIdx > 0 ? nameValue.slice(0, eqIdx).trim() : nameValue.trim();
  const value = eqIdx > 0 ? nameValue.slice(eqIdx + 1).trim() : "";

  let secure = false;
  let httpOnly = false;
  let sameSite: string | null = null;
  let path: string | null = null;
  let domain: string | null = null;
  let maxAge: number | null = null;
  let expires: string | null = null;

  for (const attr of attrs) {
    const lowerAttr = attr.toLowerCase();

    if (lowerAttr === "secure") {
      secure = true;
    } else if (lowerAttr === "httponly") {
      httpOnly = true;
    } else if (lowerAttr.startsWith("samesite=")) {
      sameSite = attr.split("=")[1]?.trim().toLowerCase() ?? null;
    } else if (lowerAttr.startsWith("path=")) {
      path = attr.split("=")[1]?.trim() ?? null;
    } else if (lowerAttr.startsWith("domain=")) {
      domain = attr.split("=")[1]?.trim() ?? null;
    } else if (lowerAttr.startsWith("max-age=")) {
      const parsed = parseInt(attr.split("=")[1] ?? "", 10);
      maxAge = isNaN(parsed) ? null : parsed;
    } else if (lowerAttr.startsWith("expires=")) {
      expires = attr.slice(attr.indexOf("=") + 1).trim();
    }
  }

  const isSessionLike = SESSION_PATTERNS.some((p) => p.test(name));

  return { name, value, secure, httpOnly, sameSite, path, domain, maxAge, expires, isSessionLike };
}

/**
 * Extracts all Set-Cookie headers from a fetch Response.
 * The standard Headers API merges Set-Cookie — we use the raw method
 * `getSetCookie()` when available, falling back to `get("set-cookie")`.
 */
function extractSetCookies(response: Response): string[] {
  // Node.js 20+ and modern runtimes support getSetCookie()
  if (typeof response.headers.getSetCookie === "function") {
    return response.headers.getSetCookie();
  }

  // Fallback: the headers may be comma-joined (lossy but best effort)
  const raw = response.headers.get("set-cookie");
  if (!raw) return [];

  // Naive split on ", " that doesn't fall inside Expires dates.
  // Cookies with Expires contain a comma in the date (e.g., "Thu, 01 Jan 2025").
  // We split on boundaries where a new cookie name starts after ", ".
  const cookies: string[] = [];
  let current = "";
  for (const part of raw.split(", ")) {
    // If the part starts with what looks like a cookie name=value,
    // it is likely a new cookie.
    if (current && /^[^=]+=[^;]/.test(part) && !/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)/i.test(part)) {
      cookies.push(current.trim());
      current = part;
    } else {
      current += (current ? ", " : "") + part;
    }
  }
  if (current) cookies.push(current.trim());
  return cookies;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const USER_AGENT = "BackendMax-Auditor/2.4.0";

export async function auditCookies(url: string): Promise<CookieAuditResult> {
  const issues: Issue[] = [];
  let score = 100;

  let totalCookies = 0;
  let secureCookies = 0;
  let httpOnlyCookies = 0;
  let sameSiteCookies = 0;
  const sessionCookiesFound: string[] = [];

  try {
    // Normalize URL
    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http")) targetUrl = `https://${targetUrl}`;

    const isHttps = targetUrl.startsWith("https://");

    // Fetch the target URL
    const response = await fetch(targetUrl, {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(15_000),
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "text/html,application/json,*/*",
      },
    });

    // Extract and parse all cookies
    const rawCookies = extractSetCookies(response);
    const cookies = rawCookies.map(parseCookie);
    totalCookies = cookies.length;

    if (totalCookies === 0) {
      // No cookies at all — perfect score, nothing to audit
      return {
        url: targetUrl,
        issues,
        summary: {
          totalCookies: 0,
          secureCookies: 0,
          httpOnlyCookies: 0,
          sameSiteCookies: 0,
          sessionCookiesFound: [],
          score: 100,
        },
      };
    }

    // --- Analyze each cookie ---
    for (const cookie of cookies) {
      if (cookie.secure) secureCookies++;
      if (cookie.httpOnly) httpOnlyCookies++;
      if (cookie.sameSite) sameSiteCookies++;
      if (cookie.isSessionLike) sessionCookiesFound.push(cookie.name);

      // ---------------------------------------------------------------
      // Check: HTTPS site without Secure flag
      // ---------------------------------------------------------------
      if (isHttps && !cookie.secure) {
        const penalty = cookie.isSessionLike ? 10 : 5;
        score -= penalty;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, `no-secure-${cookie.name}`),
          category: CATEGORY,
          severity: cookie.isSessionLike ? "critical" : "warning",
          title: `Cookie '${cookie.name}' missing Secure flag`,
          description:
            `Cookie '${cookie.name}' is set on an HTTPS site without the Secure flag. ` +
            "The browser may transmit it over insecure HTTP connections. " +
            "Add the Secure attribute to prevent cookie theft via network sniffing.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      // ---------------------------------------------------------------
      // Check: Session-like cookie without HttpOnly
      // ---------------------------------------------------------------
      if (cookie.isSessionLike && !cookie.httpOnly) {
        score -= 10;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, `no-httponly-${cookie.name}`),
          category: CATEGORY,
          severity: "critical",
          title: `Session cookie '${cookie.name}' missing HttpOnly flag`,
          description:
            `Cookie '${cookie.name}' looks like a session/auth token but lacks the HttpOnly flag. ` +
            "JavaScript can read this cookie via document.cookie, enabling XSS-based session theft. " +
            "Add the HttpOnly attribute to session cookies.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      // ---------------------------------------------------------------
      // Check: SameSite=None without Secure
      // ---------------------------------------------------------------
      if (cookie.sameSite === "none" && !cookie.secure) {
        score -= 8;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, `samesite-none-no-secure-${cookie.name}`),
          category: CATEGORY,
          severity: "warning",
          title: `Cookie '${cookie.name}' has SameSite=None without Secure`,
          description:
            `Cookie '${cookie.name}' sets SameSite=None but lacks the Secure flag. ` +
            "Modern browsers reject SameSite=None cookies without Secure. " +
            "Either add the Secure flag or change SameSite to Lax or Strict.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      // ---------------------------------------------------------------
      // Check: Missing SameSite attribute
      // ---------------------------------------------------------------
      if (!cookie.sameSite) {
        const penalty = cookie.isSessionLike ? 5 : 2;
        score -= penalty;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, `no-samesite-${cookie.name}`),
          category: CATEGORY,
          severity: cookie.isSessionLike ? "warning" : "info",
          title: `Cookie '${cookie.name}' missing SameSite attribute`,
          description:
            `Cookie '${cookie.name}' does not set a SameSite attribute. ` +
            "While modern browsers default to Lax, older browsers default to None, " +
            "making the cookie vulnerable to CSRF. Explicitly set SameSite=Lax or SameSite=Strict.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      // ---------------------------------------------------------------
      // Check: Overly broad Path scope for session cookies
      // ---------------------------------------------------------------
      if (cookie.isSessionLike && cookie.path === "/") {
        // Path=/ is extremely common and often intentional for session cookies,
        // but worth noting for APIs that could scope more tightly
        score -= 1;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, `broad-path-${cookie.name}`),
          category: CATEGORY,
          severity: "info",
          title: `Session cookie '${cookie.name}' has broad Path=/`,
          description:
            `Cookie '${cookie.name}' uses Path=/, making it available to all paths on the domain. ` +
            "For APIs with distinct sections, consider scoping session cookies to specific paths " +
            "(e.g., Path=/api) to limit exposure.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      // ---------------------------------------------------------------
      // Check: Overly broad Domain scope
      // ---------------------------------------------------------------
      if (cookie.domain) {
        // A domain starting with "." is standard for including subdomains.
        // Flag if the domain is a bare TLD or very short (likely overly broad).
        const domainParts = cookie.domain.replace(/^\./, "").split(".");
        if (domainParts.length <= 2 && cookie.isSessionLike) {
          score -= 3;
          issues.push({
            id: generateIssueId(CATEGORY, targetUrl, `broad-domain-${cookie.name}`),
            category: CATEGORY,
            severity: "info",
            title: `Session cookie '${cookie.name}' has broad domain scope`,
            description:
              `Cookie '${cookie.name}' is scoped to domain '${cookie.domain}', ` +
              "which includes all subdomains. If any subdomain is compromised, the session cookie " +
              "can be stolen. Consider omitting the Domain attribute to restrict to the exact host.",
            file: targetUrl,
            line: null,
            status: "open",
            firstSeen: new Date().toISOString(),
            fixedAt: null,
          });
        }
      }
    }

    // --- Overall cookie hygiene checks ---

    // Check if any non-HttpOnly cookies exist (general hygiene)
    const nonHttpOnly = cookies.filter((c) => !c.httpOnly && !c.isSessionLike);
    if (nonHttpOnly.length > 0 && nonHttpOnly.length === cookies.length) {
      score -= 2;
      issues.push({
        id: generateIssueId(CATEGORY, targetUrl, "no-httponly-cookies"),
        category: CATEGORY,
        severity: "info",
        title: "No cookies use HttpOnly flag",
        description:
          `None of the ${totalCookies} cookie(s) have the HttpOnly flag set. ` +
          "While not all cookies need HttpOnly, any cookie containing sensitive data " +
          "should be marked HttpOnly to prevent JavaScript access.",
        file: targetUrl,
        line: null,
        status: "open",
        firstSeen: new Date().toISOString(),
        fixedAt: null,
      });
    }

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    return {
      url: targetUrl,
      issues,
      summary: {
        totalCookies,
        secureCookies,
        httpOnlyCookies,
        sameSiteCookies,
        sessionCookiesFound,
        score,
      },
    };
  } catch (error) {
    return {
      url,
      issues: [
        {
          id: generateIssueId(CATEGORY, url, "fetch-failed"),
          category: CATEGORY,
          severity: "warning",
          title: "Cookie audit failed — could not reach URL",
          description: `Failed to fetch ${url}: ${error instanceof Error ? error.message : String(error)}`,
          file: url,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        },
      ],
      summary: {
        totalCookies: 0,
        secureCookies: 0,
        httpOnlyCookies: 0,
        sameSiteCookies: 0,
        sessionCookiesFound: [],
        score: 0,
      },
    };
  }
}
