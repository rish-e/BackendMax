// =============================================================================
// backend-max — HTTP Security Header Auditor
//
// Deep analysis of HTTP security headers with A-F letter grading.
// Evaluates CSP, HSTS, X-Frame-Options, Permissions-Policy, and all
// Cross-Origin headers — no source code access required.
// =============================================================================

import type { Issue, IssueCategory, Severity } from "../types.js";
import { generateIssueId } from "../utils/helpers.js";

const CATEGORY: IssueCategory = "headers";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HeaderAuditResult {
  url: string;
  issues: Issue[];
  headers: Record<string, string>;
  summary: {
    grade: string; // A+, A, B, C, D, F
    score: number; // 0-100
    headersPresent: string[];
    headersMissing: string[];
    cspAnalysis: {
      hasUnsafeInline: boolean;
      hasUnsafeEval: boolean;
      hasWildcard: boolean;
    } | null;
    hstsAnalysis: {
      maxAge: number;
      includeSubDomains: boolean;
      preload: boolean;
    } | null;
  };
}

// ---------------------------------------------------------------------------
// Header definitions with scoring weights
// ---------------------------------------------------------------------------

interface HeaderSpec {
  header: string;
  weight: number; // points deducted if missing
  severity: Severity;
  title: string;
  description: string;
}

const SECURITY_HEADERS: HeaderSpec[] = [
  {
    header: "content-security-policy",
    weight: 15,
    severity: "critical",
    title: "Missing Content-Security-Policy (CSP)",
    description:
      "No CSP header detected. This leaves the site vulnerable to XSS and data injection attacks. " +
      "Add a Content-Security-Policy header with restrictive directives.",
  },
  {
    header: "strict-transport-security",
    weight: 15,
    severity: "critical",
    title: "Missing Strict-Transport-Security (HSTS)",
    description:
      "No HSTS header — browsers may allow HTTP downgrade attacks. " +
      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
  },
  {
    header: "x-frame-options",
    weight: 10,
    severity: "warning",
    title: "Missing X-Frame-Options",
    description:
      "No X-Frame-Options header — the site can be embedded in iframes, enabling clickjacking. " +
      "Add: X-Frame-Options: DENY or SAMEORIGIN.",
  },
  {
    header: "x-content-type-options",
    weight: 8,
    severity: "warning",
    title: "Missing X-Content-Type-Options",
    description:
      "No X-Content-Type-Options header — browsers may MIME-sniff responses into executable types. " +
      "Add: X-Content-Type-Options: nosniff",
  },
  {
    header: "referrer-policy",
    weight: 5,
    severity: "info",
    title: "Missing Referrer-Policy",
    description:
      "No Referrer-Policy header — full URLs (including query strings) may leak to third-party sites. " +
      "Add: Referrer-Policy: strict-origin-when-cross-origin",
  },
  {
    header: "permissions-policy",
    weight: 5,
    severity: "info",
    title: "Missing Permissions-Policy",
    description:
      "No Permissions-Policy header — browser features (camera, microphone, geolocation) are not restricted. " +
      "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
  },
  {
    header: "cross-origin-opener-policy",
    weight: 5,
    severity: "info",
    title: "Missing Cross-Origin-Opener-Policy (COOP)",
    description:
      "No COOP header — the page can be referenced by cross-origin windows. " +
      "Add: Cross-Origin-Opener-Policy: same-origin",
  },
  {
    header: "cross-origin-resource-policy",
    weight: 5,
    severity: "info",
    title: "Missing Cross-Origin-Resource-Policy (CORP)",
    description:
      "No CORP header — resources can be loaded by any origin. " +
      "Add: Cross-Origin-Resource-Policy: same-origin or same-site",
  },
  {
    header: "cross-origin-embedder-policy",
    weight: 5,
    severity: "info",
    title: "Missing Cross-Origin-Embedder-Policy (COEP)",
    description:
      "No COEP header — cross-origin resources are loaded without explicit opt-in. " +
      "Add: Cross-Origin-Embedder-Policy: require-corp",
  },
];

// Total possible deductions
const MAX_DEDUCTIONS = SECURITY_HEADERS.reduce((sum, h) => sum + h.weight, 0);

// ---------------------------------------------------------------------------
// CSP analysis helpers
// ---------------------------------------------------------------------------

interface CspAnalysis {
  hasUnsafeInline: boolean;
  hasUnsafeEval: boolean;
  hasWildcard: boolean;
  directives: Record<string, string>;
}

function analyzeCSP(cspValue: string): CspAnalysis {
  const directives: Record<string, string> = {};
  const parts = cspValue.split(";").map((d) => d.trim()).filter(Boolean);

  for (const part of parts) {
    const [directive, ...values] = part.split(/\s+/);
    if (directive) {
      directives[directive.toLowerCase()] = values.join(" ");
    }
  }

  const fullValue = cspValue.toLowerCase();
  return {
    hasUnsafeInline: fullValue.includes("'unsafe-inline'"),
    hasUnsafeEval: fullValue.includes("'unsafe-eval'"),
    hasWildcard: / \*[;\s]| \*$/.test(cspValue) || cspValue.includes(" * "),
    directives,
  };
}

// ---------------------------------------------------------------------------
// HSTS analysis helper
// ---------------------------------------------------------------------------

interface HstsAnalysis {
  maxAge: number;
  includeSubDomains: boolean;
  preload: boolean;
}

function analyzeHSTS(hstsValue: string): HstsAnalysis {
  const lower = hstsValue.toLowerCase();
  const maxAgeMatch = lower.match(/max-age=(\d+)/);
  return {
    maxAge: maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0,
    includeSubDomains: lower.includes("includesubdomains"),
    preload: lower.includes("preload"),
  };
}

// ---------------------------------------------------------------------------
// Grade calculation
// ---------------------------------------------------------------------------

function scoreToGrade(score: number): string {
  if (score >= 100) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function auditHeaders(url: string): Promise<HeaderAuditResult> {
  const issues: Issue[] = [];
  const headersPresent: string[] = [];
  const headersMissing: string[] = [];
  let score = 100;
  let responseHeaders: Record<string, string> = {};
  let cspAnalysis: CspAnalysis | null = null;
  let hstsAnalysis: HstsAnalysis | null = null;

  try {
    // Normalize URL
    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http")) targetUrl = `https://${targetUrl}`;

    // Fetch the target
    const response = await fetch(targetUrl, {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(15_000),
      headers: {
        "User-Agent": "BackendMax-Auditor/2.4.0",
        Accept: "text/html,application/json,*/*",
      },
    });

    // Collect all response headers
    response.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });

    // --- Check each security header ---
    for (const spec of SECURITY_HEADERS) {
      const headerValue = responseHeaders[spec.header];
      if (headerValue) {
        headersPresent.push(spec.header);
      } else {
        headersMissing.push(spec.header);
        // Scale the weight to a 0-100 scale proportionally
        const penalty = Math.round((spec.weight / MAX_DEDUCTIONS) * 100);
        score -= penalty;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, spec.header),
          category: CATEGORY,
          severity: spec.severity,
          title: spec.title,
          description: spec.description,
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }
    }

    // --- Deep CSP analysis ---
    const cspHeader = responseHeaders["content-security-policy"];
    if (cspHeader) {
      cspAnalysis = analyzeCSP(cspHeader);

      if (cspAnalysis.hasUnsafeInline) {
        score -= 5;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "csp-unsafe-inline"),
          category: CATEGORY,
          severity: "warning",
          title: "CSP allows 'unsafe-inline'",
          description:
            "Content-Security-Policy includes 'unsafe-inline', which defeats much of the XSS protection CSP provides. " +
            "Use nonce-based or hash-based CSP instead of 'unsafe-inline'.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      if (cspAnalysis.hasUnsafeEval) {
        score -= 5;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "csp-unsafe-eval"),
          category: CATEGORY,
          severity: "warning",
          title: "CSP allows 'unsafe-eval'",
          description:
            "Content-Security-Policy includes 'unsafe-eval', allowing dynamic code execution via eval(), " +
            "Function(), setTimeout(string), and setInterval(string). Remove 'unsafe-eval' where possible.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      if (cspAnalysis.hasWildcard) {
        score -= 5;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "csp-wildcard"),
          category: CATEGORY,
          severity: "warning",
          title: "CSP uses wildcard (*) source",
          description:
            "Content-Security-Policy uses a wildcard '*' source, which allows loading resources from any origin. " +
            "Replace wildcards with specific trusted origins.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      // Check for missing default-src or script-src
      if (!cspAnalysis.directives["default-src"] && !cspAnalysis.directives["script-src"]) {
        score -= 3;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "csp-no-default-src"),
          category: CATEGORY,
          severity: "warning",
          title: "CSP missing default-src and script-src directives",
          description:
            "The CSP header lacks both default-src and script-src directives. " +
            "Without these, scripts can load from any origin. Add at minimum: default-src 'self'",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }
    }

    // --- Deep HSTS analysis ---
    const hstsHeader = responseHeaders["strict-transport-security"];
    if (hstsHeader) {
      hstsAnalysis = analyzeHSTS(hstsHeader);

      // max-age should be at least 1 year (31536000 seconds)
      if (hstsAnalysis.maxAge < 31536000) {
        score -= 3;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "hsts-short-max-age"),
          category: CATEGORY,
          severity: "warning",
          title: "HSTS max-age is too short",
          description:
            `HSTS max-age is ${hstsAnalysis.maxAge} seconds (${Math.round(hstsAnalysis.maxAge / 86400)} days). ` +
            "Recommended minimum is 31536000 (1 year). Short max-age values leave a wider window for downgrade attacks.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      if (!hstsAnalysis.includeSubDomains) {
        score -= 2;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "hsts-no-subdomains"),
          category: CATEGORY,
          severity: "info",
          title: "HSTS missing includeSubDomains",
          description:
            "HSTS does not include the includeSubDomains directive. Subdomains can still be accessed over HTTP. " +
            "Add includeSubDomains to protect all subdomains.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }

      if (!hstsAnalysis.preload) {
        score -= 1;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "hsts-no-preload"),
          category: CATEGORY,
          severity: "info",
          title: "HSTS missing preload directive",
          description:
            "HSTS does not include the preload directive. Without preload, the first visit is still vulnerable. " +
            "Add preload and submit to hstspreload.org for maximum protection.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }
    }

    // --- Permissions-Policy analysis ---
    const ppHeader = responseHeaders["permissions-policy"];
    if (ppHeader) {
      const sensitiveFeatures = ["camera", "microphone", "geolocation", "payment", "usb", "bluetooth"];
      const ppLower = ppHeader.toLowerCase();
      const unrestrictedFeatures: string[] = [];

      for (const feature of sensitiveFeatures) {
        // Feature is restricted if it appears as feature=() or feature=(self)
        const restrictedPattern = new RegExp(`${feature}\\s*=\\s*\\(\\s*\\)`, "i");
        const selfPattern = new RegExp(`${feature}\\s*=\\s*\\(\\s*self\\s*\\)`, "i");
        if (!restrictedPattern.test(ppHeader) && !selfPattern.test(ppHeader) && ppLower.includes(feature)) {
          // Feature is mentioned but not restricted — check if it allows all
          const wildcardPattern = new RegExp(`${feature}\\s*=\\s*\\*`, "i");
          if (wildcardPattern.test(ppHeader)) {
            unrestrictedFeatures.push(feature);
          }
        } else if (!ppLower.includes(feature)) {
          // Feature is not mentioned at all — browser defaults may allow it
          unrestrictedFeatures.push(feature);
        }
      }

      if (unrestrictedFeatures.length > 0) {
        score -= 2;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "pp-unrestricted"),
          category: CATEGORY,
          severity: "info",
          title: "Permissions-Policy does not restrict sensitive features",
          description:
            `Sensitive browser features not explicitly restricted: ${unrestrictedFeatures.join(", ")}. ` +
            "Restrict unused features with Permissions-Policy to reduce attack surface.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }
    }

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    return {
      url: targetUrl,
      issues,
      headers: responseHeaders,
      summary: {
        grade: scoreToGrade(score),
        score,
        headersPresent,
        headersMissing,
        cspAnalysis: cspAnalysis
          ? {
              hasUnsafeInline: cspAnalysis.hasUnsafeInline,
              hasUnsafeEval: cspAnalysis.hasUnsafeEval,
              hasWildcard: cspAnalysis.hasWildcard,
            }
          : null,
        hstsAnalysis: hstsAnalysis
          ? {
              maxAge: hstsAnalysis.maxAge,
              includeSubDomains: hstsAnalysis.includeSubDomains,
              preload: hstsAnalysis.preload,
            }
          : null,
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
          title: "Header audit failed — could not reach URL",
          description: `Failed to fetch ${url}: ${error instanceof Error ? error.message : String(error)}`,
          file: url,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        },
      ],
      headers: responseHeaders,
      summary: {
        grade: "F",
        score: 0,
        headersPresent: [],
        headersMissing: SECURITY_HEADERS.map((h) => h.header),
        cspAnalysis: null,
        hstsAnalysis: null,
      },
    };
  }
}
