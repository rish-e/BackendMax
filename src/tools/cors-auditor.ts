// =============================================================================
// backend-max — CORS Misconfiguration Auditor
//
// Detects Cross-Origin Resource Sharing misconfigurations by sending
// preflight OPTIONS requests with various test origins and inspecting
// the Access-Control-* response headers.
// =============================================================================

import type { Issue, IssueCategory, Severity } from "../types.js";
import { generateIssueId } from "../utils/helpers.js";

const CATEGORY: IssueCategory = "cors";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CorsAuditResult {
  url: string;
  issues: Issue[];
  summary: {
    corsEnabled: boolean;
    allowedOrigins: string | null;
    allowedMethods: string | null;
    allowCredentials: boolean;
    reflectsOrigin: boolean;
    wildcardWithCredentials: boolean;
    maxAge: number | null;
    score: number; // 0-100
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const USER_AGENT = "BackendMax-Auditor/2.4.0";
const EVIL_ORIGIN = "https://evil.com";

/**
 * Sends a fetch request and collects response headers, ignoring failures.
 */
async function safeFetch(
  url: string,
  options: RequestInit,
): Promise<{ status: number; headers: Record<string, string> } | null> {
  try {
    const resp = await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(10_000),
    });
    const headers: Record<string, string> = {};
    resp.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    return { status: resp.status, headers };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Overly permissive methods check
// ---------------------------------------------------------------------------

const SENSITIVE_METHODS = ["DELETE", "PUT", "PATCH"];

// ---------------------------------------------------------------------------
// Sensitive headers that should not be exposed
// ---------------------------------------------------------------------------

const SENSITIVE_EXPOSED_HEADERS = [
  "authorization",
  "set-cookie",
  "x-api-key",
  "x-csrf-token",
  "x-auth-token",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function auditCors(url: string): Promise<CorsAuditResult> {
  const issues: Issue[] = [];
  let score = 100;

  // Summary fields
  let corsEnabled = false;
  let allowedOrigins: string | null = null;
  let allowedMethods: string | null = null;
  let allowCredentials = false;
  let reflectsOrigin = false;
  let wildcardWithCredentials = false;
  let maxAge: number | null = null;

  try {
    // Normalize URL
    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http")) targetUrl = `https://${targetUrl}`;

    // ------------------------------------------------------------------
    // Test 1: Does the server reflect an arbitrary origin?
    // ------------------------------------------------------------------
    const evilPreflight = await safeFetch(targetUrl, {
      method: "OPTIONS",
      headers: {
        "User-Agent": USER_AGENT,
        Origin: EVIL_ORIGIN,
        "Access-Control-Request-Method": "GET",
      },
    });

    if (evilPreflight) {
      const acao = evilPreflight.headers["access-control-allow-origin"];
      if (acao) {
        corsEnabled = true;
        allowedOrigins = acao;

        if (acao === EVIL_ORIGIN || acao === "*") {
          reflectsOrigin = acao === EVIL_ORIGIN;
        }
      }

      const acac = evilPreflight.headers["access-control-allow-credentials"];
      if (acac?.toLowerCase() === "true") {
        allowCredentials = true;
      }

      const acam = evilPreflight.headers["access-control-allow-methods"];
      if (acam) {
        allowedMethods = acam;
      }

      const acma = evilPreflight.headers["access-control-max-age"];
      if (acma) {
        maxAge = parseInt(acma, 10) || null;
      }
    }

    // Also do a regular GET with Origin to check reflection (some servers
    // only respond to non-preflight CORS)
    const evilGet = await safeFetch(targetUrl, {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        Origin: EVIL_ORIGIN,
        Accept: "*/*",
      },
    });

    if (evilGet) {
      const acao = evilGet.headers["access-control-allow-origin"];
      if (acao) {
        corsEnabled = true;
        if (!allowedOrigins) allowedOrigins = acao;

        if (acao === EVIL_ORIGIN) {
          reflectsOrigin = true;
        }

        const acac = evilGet.headers["access-control-allow-credentials"];
        if (acac?.toLowerCase() === "true") {
          allowCredentials = true;
        }
      }
    }

    // ------------------------------------------------------------------
    // Issue: Origin reflection
    // ------------------------------------------------------------------
    if (reflectsOrigin) {
      score -= 25;
      issues.push({
        id: generateIssueId(CATEGORY, targetUrl, "reflects-origin"),
        category: CATEGORY,
        severity: "critical",
        title: "CORS reflects arbitrary Origin header",
        description:
          `The server reflects the Origin '${EVIL_ORIGIN}' back in Access-Control-Allow-Origin. ` +
          "This effectively disables the same-origin policy for any attacker-controlled domain. " +
          "Only allow explicitly trusted origins.",
        file: targetUrl,
        line: null,
        status: "open",
        firstSeen: new Date().toISOString(),
        fixedAt: null,
      });
    }

    // ------------------------------------------------------------------
    // Test 2: Wildcard + credentials (the most dangerous combo)
    // ------------------------------------------------------------------
    const credPreflight = await safeFetch(targetUrl, {
      method: "OPTIONS",
      headers: {
        "User-Agent": USER_AGENT,
        Origin: EVIL_ORIGIN,
        "Access-Control-Request-Method": "POST",
      },
    });

    if (credPreflight) {
      const acao = credPreflight.headers["access-control-allow-origin"];
      const acac = credPreflight.headers["access-control-allow-credentials"];

      if (acac?.toLowerCase() === "true") {
        allowCredentials = true;
      }

      // Wildcard with credentials is technically invalid per spec but
      // some servers misconfigure this
      if (acao === "*" && allowCredentials) {
        wildcardWithCredentials = true;
        score -= 30;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "wildcard-credentials"),
          category: CATEGORY,
          severity: "critical",
          title: "CORS wildcard (*) with credentials enabled",
          description:
            "The server sends Access-Control-Allow-Origin: * alongside " +
            "Access-Control-Allow-Credentials: true. While browsers block this combination, " +
            "the misconfiguration indicates a broken CORS policy that may reflect origins " +
            "under different request conditions. Audit your CORS middleware thoroughly.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      // Reflected origin + credentials is very dangerous
      if (reflectsOrigin && allowCredentials) {
        score -= 20;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "reflect-with-credentials"),
          category: CATEGORY,
          severity: "critical",
          title: "CORS reflects origin with credentials enabled",
          description:
            "The server reflects arbitrary origins AND allows credentials. " +
            "An attacker can make authenticated cross-origin requests from any domain. " +
            "This is one of the most dangerous CORS misconfigurations. " +
            "Restrict allowed origins to a strict allowlist.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }
    }

    // ------------------------------------------------------------------
    // Test 3: Wildcard origin (less severe but flaggable)
    // ------------------------------------------------------------------
    if (allowedOrigins === "*" && !wildcardWithCredentials) {
      score -= 10;
      issues.push({
        id: generateIssueId(CATEGORY, targetUrl, "wildcard-origin"),
        category: CATEGORY,
        severity: "warning",
        title: "CORS uses wildcard Access-Control-Allow-Origin: *",
        description:
          "The server allows any origin to read responses. While this is appropriate for " +
          "truly public APIs, it is a security risk for APIs that serve user-specific data. " +
          "Consider restricting to specific trusted origins if the API is not fully public.",
        file: targetUrl,
        line: null,
        status: "open",
        firstSeen: new Date().toISOString(),
        fixedAt: null,
      });
    }

    // ------------------------------------------------------------------
    // Test 4: Overly permissive methods
    // ------------------------------------------------------------------
    if (allowedMethods) {
      const methods = allowedMethods.split(",").map((m) => m.trim().toUpperCase());
      const dangerousMethods = methods.filter((m) => SENSITIVE_METHODS.includes(m));

      if (dangerousMethods.length > 0) {
        score -= 5;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "permissive-methods"),
          category: CATEGORY,
          severity: "info",
          title: "CORS allows potentially dangerous HTTP methods",
          description:
            `Access-Control-Allow-Methods includes: ${dangerousMethods.join(", ")}. ` +
            "Ensure these methods are intentionally exposed. Only allow the HTTP methods " +
            "that your API actually needs for cross-origin access.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }
    }

    // ------------------------------------------------------------------
    // Test 5: Missing Access-Control-Max-Age
    // ------------------------------------------------------------------
    if (corsEnabled && maxAge === null) {
      score -= 5;
      issues.push({
        id: generateIssueId(CATEGORY, targetUrl, "no-max-age"),
        category: CATEGORY,
        severity: "info",
        title: "CORS missing Access-Control-Max-Age",
        description:
          "No Access-Control-Max-Age header is set. Browsers will send a preflight OPTIONS " +
          "request before every cross-origin request, adding latency. " +
          "Set Access-Control-Max-Age: 86400 (24 hours) to cache preflight results.",
        file: targetUrl,
        line: null,
        status: "open",
        firstSeen: new Date().toISOString(),
        fixedAt: null,
      });
    }

    // ------------------------------------------------------------------
    // Test 6: Sensitive headers exposed
    // ------------------------------------------------------------------
    if (evilPreflight || evilGet) {
      const exposeHeaders =
        evilPreflight?.headers["access-control-expose-headers"] ??
        evilGet?.headers["access-control-expose-headers"] ??
        null;

      if (exposeHeaders) {
        const exposed = exposeHeaders.split(",").map((h) => h.trim().toLowerCase());
        const sensitiveExposed = exposed.filter((h) => SENSITIVE_EXPOSED_HEADERS.includes(h));

        if (sensitiveExposed.length > 0) {
          score -= 10;
          issues.push({
            id: generateIssueId(CATEGORY, targetUrl, "sensitive-expose-headers"),
            category: CATEGORY,
            severity: "warning",
            title: "CORS exposes sensitive response headers",
            description:
              `Access-Control-Expose-Headers includes sensitive headers: ${sensitiveExposed.join(", ")}. ` +
              "These headers can be read by cross-origin JavaScript. " +
              "Only expose headers that the client legitimately needs.",
            file: targetUrl,
            line: null,
            status: "open",
            firstSeen: new Date().toISOString(),
            fixedAt: null,
          });
        }
      }
    }

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    return {
      url: targetUrl,
      issues,
      summary: {
        corsEnabled,
        allowedOrigins,
        allowedMethods,
        allowCredentials,
        reflectsOrigin,
        wildcardWithCredentials,
        maxAge,
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
          title: "CORS audit failed — could not reach URL",
          description: `Failed to fetch ${url}: ${error instanceof Error ? error.message : String(error)}`,
          file: url,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        },
      ],
      summary: {
        corsEnabled: false,
        allowedOrigins: null,
        allowedMethods: null,
        allowCredentials: false,
        reflectsOrigin: false,
        wildcardWithCredentials: false,
        maxAge: null,
        score: 0,
      },
    };
  }
}
