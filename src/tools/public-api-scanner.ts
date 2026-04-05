// =============================================================================
// backend-max — Public API Surface Scanner
//
// Discovers API endpoints by analyzing frontend JavaScript bundles fetched
// over HTTP. Extracts fetch/axios calls and URL patterns from JS source,
// probes discovered endpoints for reachability, and flags unprotected or
// sensitive APIs. No source code access needed.
// =============================================================================

import type { Issue, IssueCategory, Severity } from "../types.js";
import { generateIssueId } from "../utils/helpers.js";

const CATEGORY: IssueCategory = "security";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DiscoveredEndpoint {
  url: string;
  method: string;
  statusCode: number | null;
  authRequired: boolean;
  source: string; // which JS file it was found in
}

export interface PublicApiScanResult {
  url: string;
  issues: Issue[];
  endpoints: DiscoveredEndpoint[];
  summary: {
    totalEndpoints: number;
    publicEndpoints: number;
    authRequiredEndpoints: number;
    notFoundEndpoints: number;
    apiDomains: string[];
    score: number; // 0-100
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Script sources to skip (analytics, tracking, tag managers). */
const SKIP_PATTERNS = [
  /google-analytics/i,
  /googletagmanager/i,
  /gtag/i,
  /facebook.*pixel/i,
  /hotjar/i,
  /segment\.com/i,
  /mixpanel/i,
  /intercom/i,
  /crisp/i,
  /zendesk/i,
  /sentry/i,
  /datadog/i,
  /newrelic/i,
  /amplitude/i,
  /clarity\.ms/i,
  /polyfill/i,
];

/** Patterns that identify admin/internal endpoints. */
const ADMIN_PATTERNS = [
  /\/admin/i,
  /\/internal/i,
  /\/_internal/i,
  /\/debug/i,
  /\/manage/i,
  /\/dashboard\/api/i,
  /\/console/i,
  /\/system/i,
  /\/health/i,
  /\/metrics/i,
  /\/status/i,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Create an Issue object with common defaults. */
function createIssue(
  targetUrl: string,
  severity: Severity,
  title: string,
  description: string,
  detail: string,
): Issue {
  return {
    id: generateIssueId(CATEGORY, targetUrl, detail),
    category: CATEGORY,
    severity,
    title,
    description,
    file: targetUrl,
    line: null,
    status: "open",
    firstSeen: new Date().toISOString(),
    fixedAt: null,
  };
}

/** Fetch URL with timeout, return body or null. */
async function safeFetchText(
  fetchUrl: string,
  maxBytes: number = 500_000,
): Promise<string | null> {
  try {
    const response = await fetch(fetchUrl, {
      redirect: "follow",
      signal: AbortSignal.timeout(10_000),
      headers: {
        "User-Agent": "BackendMax-Auditor/2.4.0",
        Accept: "*/*",
      },
    });
    if (!response.ok) return null;
    const text = await response.text();
    return text.slice(0, maxBytes);
  } catch {
    return null;
  }
}

/** Probe an endpoint and return status + headers. */
async function probeEndpoint(
  endpointUrl: string,
  method: string = "GET",
): Promise<{ status: number; headers: Record<string, string> } | null> {
  try {
    const response = await fetch(endpointUrl, {
      method: method === "GET" ? "GET" : "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(8_000),
      headers: {
        "User-Agent": "BackendMax-Auditor/2.4.0",
        Accept: "application/json,*/*",
      },
    });
    const headers: Record<string, string> = {};
    response.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    return { status: response.status, headers };
  } catch {
    return null;
  }
}

/** Determine if a script src should be skipped (analytics, tracking, etc.). */
function shouldSkipScript(src: string): boolean {
  return SKIP_PATTERNS.some((p) => p.test(src));
}

/** Resolve a potentially relative URL against a base. */
function resolveUrl(base: string, relative: string): string | null {
  try {
    return new URL(relative, base).toString();
  } catch {
    return null;
  }
}

/** Extract API endpoint patterns from JavaScript source code. */
function extractEndpoints(
  jsContent: string,
  sourceFile: string,
  baseUrl: string,
): Array<{ url: string; method: string; source: string }> {
  const found: Array<{ url: string; method: string; source: string }> = [];
  const seen = new Set<string>();

  // --- Pattern 1: fetch("...") or fetch('...') ---
  const fetchPattern = /fetch\s*\(\s*["'`]([^"'`]+)["'`]/g;
  let match: RegExpExecArray | null;

  while ((match = fetchPattern.exec(jsContent)) !== null) {
    const urlStr = match[1];
    if (isApiUrl(urlStr)) {
      const key = `GET:${urlStr}`;
      if (!seen.has(key)) {
        seen.add(key);
        found.push({ url: urlStr, method: "GET", source: sourceFile });
      }
    }
  }

  // --- Pattern 2: fetch with method in options ---
  const fetchMethodPattern =
    /fetch\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{[^}]*method\s*:\s*["'`](\w+)["'`]/g;
  while ((match = fetchMethodPattern.exec(jsContent)) !== null) {
    const urlStr = match[1];
    const method = match[2].toUpperCase();
    if (isApiUrl(urlStr)) {
      const key = `${method}:${urlStr}`;
      if (!seen.has(key)) {
        seen.add(key);
        found.push({ url: urlStr, method, source: sourceFile });
      }
    }
  }

  // --- Pattern 3: axios.get/post/put/delete/patch("...") ---
  const axiosPattern =
    /axios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*["'`]([^"'`]+)["'`]/gi;
  while ((match = axiosPattern.exec(jsContent)) !== null) {
    const method = match[1].toUpperCase();
    const urlStr = match[2];
    if (isApiUrl(urlStr)) {
      const key = `${method}:${urlStr}`;
      if (!seen.has(key)) {
        seen.add(key);
        found.push({ url: urlStr, method, source: sourceFile });
      }
    }
  }

  // --- Pattern 4: URL strings matching API patterns ---
  const apiUrlPattern = /["'`]((?:https?:\/\/[^"'`]*)?\/(?:api|v[12]|v3|graphql)[^"'`]*)["'`]/g;
  while ((match = apiUrlPattern.exec(jsContent)) !== null) {
    const urlStr = match[1];
    const key = `GET:${urlStr}`;
    if (!seen.has(key)) {
      seen.add(key);
      found.push({ url: urlStr, method: "GET", source: sourceFile });
    }
  }

  // --- Pattern 5: Absolute URLs to API-like domains ---
  const absoluteApiPattern = /["'`](https?:\/\/(?:api\.|[^"'`]*\/api\/)[^"'`]*)["'`]/g;
  while ((match = absoluteApiPattern.exec(jsContent)) !== null) {
    const urlStr = match[1];
    const key = `GET:${urlStr}`;
    if (!seen.has(key)) {
      seen.add(key);
      found.push({ url: urlStr, method: "GET", source: sourceFile });
    }
  }

  return found;
}

/** Check if a URL string looks like an API endpoint. */
function isApiUrl(urlStr: string): boolean {
  // Must contain API-like path segments or be an absolute API URL
  return (
    /\/api\//i.test(urlStr) ||
    /\/v[123]\//i.test(urlStr) ||
    /\/graphql/i.test(urlStr) ||
    /^https?:\/\/api\./i.test(urlStr) ||
    /\/rest\//i.test(urlStr) ||
    /\/rpc\//i.test(urlStr)
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function scanPublicApi(url: string): Promise<PublicApiScanResult> {
  const issues: Issue[] = [];
  const allEndpoints: DiscoveredEndpoint[] = [];
  let score = 100;

  try {
    // Normalize URL
    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http")) targetUrl = `https://${targetUrl}`;

    // =====================================================================
    // Step 1: Fetch HTML page and extract script URLs
    // =====================================================================

    const html = await safeFetchText(targetUrl, 500_000);
    if (!html) {
      return {
        url: targetUrl,
        issues: [
          createIssue(
            targetUrl,
            "warning",
            "Could not fetch page for API scanning",
            `Failed to fetch ${targetUrl}. The page may be down or blocking automated requests.`,
            "fetch-failed",
          ),
        ],
        endpoints: [],
        summary: {
          totalEndpoints: 0,
          publicEndpoints: 0,
          authRequiredEndpoints: 0,
          notFoundEndpoints: 0,
          apiDomains: [],
          score: 0,
        },
      };
    }

    // Extract <script src="..."> URLs
    const scriptSrcPattern = /<script[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi;
    const scriptUrls: string[] = [];
    let match: RegExpExecArray | null;

    while ((match = scriptSrcPattern.exec(html)) !== null) {
      const src = match[1];

      // Skip analytics/tracking scripts
      if (shouldSkipScript(src)) continue;

      const resolved = resolveUrl(targetUrl, src);
      if (resolved) {
        scriptUrls.push(resolved);
      }
    }

    // =====================================================================
    // Step 2: Fetch JS bundles (limit to 5)
    // =====================================================================

    // Prioritize main/app bundles over vendor/chunk bundles
    const sortedScripts = scriptUrls.sort((a, b) => {
      const aIsMain = /main|app|index|entry/i.test(a) ? 0 : 1;
      const bIsMain = /main|app|index|entry/i.test(b) ? 0 : 1;
      return aIsMain - bIsMain;
    });

    const scriptsToFetch = sortedScripts.slice(0, 5);
    const rawEndpoints: Array<{ url: string; method: string; source: string }> = [];

    // Also scan inline scripts in the HTML
    const inlineScriptPattern = /<script[^>]*>([^<]+)<\/script>/gi;
    while ((match = inlineScriptPattern.exec(html)) !== null) {
      const inlineContent = match[1];
      if (inlineContent.length > 50) {
        rawEndpoints.push(
          ...extractEndpoints(inlineContent, `${targetUrl} (inline)`, targetUrl),
        );
      }
    }

    // Fetch external scripts in parallel
    const scriptBodies = await Promise.all(
      scriptsToFetch.map(async (scriptUrl) => {
        const body = await safeFetchText(scriptUrl, 1_000_000);
        return { scriptUrl, body };
      }),
    );

    for (const { scriptUrl, body } of scriptBodies) {
      if (!body) continue;
      rawEndpoints.push(...extractEndpoints(body, scriptUrl, targetUrl));
    }

    // =====================================================================
    // Step 3 & 4: Deduplicate and probe discovered endpoints
    // =====================================================================

    // Deduplicate by method + URL
    const uniqueEndpoints = new Map<string, { url: string; method: string; source: string }>();
    for (const ep of rawEndpoints) {
      const key = `${ep.method}:${ep.url}`;
      if (!uniqueEndpoints.has(key)) {
        uniqueEndpoints.set(key, ep);
      }
    }

    // Resolve relative URLs and probe each endpoint
    const apiDomains = new Set<string>();
    let publicEndpoints = 0;
    let authRequiredEndpoints = 0;
    let notFoundEndpoints = 0;

    // Limit probing to 20 endpoints to avoid excessive requests
    const endpointsToProbe = [...uniqueEndpoints.values()].slice(0, 20);

    for (const ep of endpointsToProbe) {
      // Resolve the URL
      let fullUrl: string;
      if (ep.url.startsWith("http")) {
        fullUrl = ep.url;
      } else {
        const resolved = resolveUrl(targetUrl, ep.url);
        if (!resolved) continue;
        fullUrl = resolved;
      }

      // Track API domain
      try {
        const domain = new URL(fullUrl).hostname;
        apiDomains.add(domain);
      } catch {
        // Malformed URL
        continue;
      }

      // Probe the endpoint
      const probeResult = await probeEndpoint(fullUrl, ep.method);
      const statusCode = probeResult?.status ?? null;
      const authRequired = statusCode === 401 || statusCode === 403;

      const endpoint: DiscoveredEndpoint = {
        url: fullUrl,
        method: ep.method,
        statusCode,
        authRequired,
        source: ep.source,
      };
      allEndpoints.push(endpoint);

      // =====================================================================
      // Step 5: Categorize
      // =====================================================================

      if (statusCode === 200) {
        publicEndpoints++;
      } else if (authRequired) {
        authRequiredEndpoints++;
      } else if (statusCode === 404) {
        notFoundEndpoints++;
      }

      // =====================================================================
      // Step 6: Flag interesting findings
      // =====================================================================

      // Public endpoint (200 without auth) — may be intentional, but flag
      if (statusCode === 200 && !authRequired) {
        // Check if it's an admin/internal endpoint
        const isAdminEndpoint = ADMIN_PATTERNS.some((p) => p.test(fullUrl));
        if (isAdminEndpoint) {
          score -= 15;
          issues.push(
            createIssue(
              fullUrl,
              "critical",
              `Admin/internal endpoint publicly accessible: ${ep.url}`,
              `The endpoint ${fullUrl} appears to be an admin or internal API that returns 200 ` +
                "without authentication. This may expose sensitive functionality. " +
                "Add authentication and authorization checks.",
              `admin-public-${ep.url}`,
            ),
          );
        }
      }

      // GraphQL endpoint — check introspection
      if (/graphql/i.test(fullUrl) && statusCode !== null && statusCode < 500) {
        try {
          const introspectionResp = await fetch(fullUrl, {
            method: "POST",
            signal: AbortSignal.timeout(8_000),
            headers: {
              "Content-Type": "application/json",
              "User-Agent": "BackendMax-Auditor/2.4.0",
            },
            body: JSON.stringify({
              query: "{ __schema { types { name } } }",
            }),
          });
          const introspectionBody = await introspectionResp.text();

          if (
            introspectionResp.status === 200 &&
            introspectionBody.includes("__schema")
          ) {
            score -= 10;
            issues.push(
              createIssue(
                fullUrl,
                "warning",
                "GraphQL introspection is enabled",
                `The GraphQL endpoint at ${fullUrl} allows introspection queries. ` +
                  "This exposes the entire API schema to anyone. " +
                  "Disable introspection in production.",
                `graphql-introspection-${fullUrl}`,
              ),
            );
          }
        } catch {
          // Introspection check failed — non-critical
        }
      }

      // Verbose error response on non-200 endpoints
      if (probeResult && statusCode && statusCode >= 400 && statusCode < 500) {
        // We already have the status; do a GET to check response body
        try {
          const errorResp = await fetch(fullUrl, {
            method: "GET",
            redirect: "follow",
            signal: AbortSignal.timeout(5_000),
            headers: {
              "User-Agent": "BackendMax-Auditor/2.4.0",
              Accept: "application/json,*/*",
            },
          });
          const errorBody = (await errorResp.text()).slice(0, 50_000);

          // Check for verbose error info
          const verbosePatterns = [
            /stack.*trace/i,
            /at Module\./,
            /Traceback/,
            /Exception/i,
            /internal server/i,
          ];

          if (verbosePatterns.some((p) => p.test(errorBody))) {
            score -= 5;
            issues.push(
              createIssue(
                fullUrl,
                "warning",
                `Verbose error response from ${ep.url}`,
                `The endpoint ${fullUrl} returns detailed error information (status ${statusCode}). ` +
                  "Error responses should be generic in production to prevent information leakage.",
                `verbose-error-${ep.url}`,
              ),
            );
          }
        } catch {
          // Error body check failed — non-critical
        }
      }
    }

    // Flag if many endpoints are public (potential over-exposure)
    if (publicEndpoints > 5) {
      score -= 5;
      issues.push(
        createIssue(
          targetUrl,
          "info",
          `${publicEndpoints} API endpoints accessible without authentication`,
          `Found ${publicEndpoints} API endpoints returning 200 without any authentication. ` +
            "Review whether all of these should be publicly accessible. " +
            "Consider adding authentication to sensitive endpoints.",
          "many-public-endpoints",
        ),
      );
    }

    // =====================================================================
    // Final score
    // =====================================================================

    score = Math.max(0, score);

    return {
      url: targetUrl,
      issues,
      endpoints: allEndpoints,
      summary: {
        totalEndpoints: allEndpoints.length,
        publicEndpoints,
        authRequiredEndpoints,
        notFoundEndpoints,
        apiDomains: [...apiDomains],
        score,
      },
    };
  } catch (error) {
    return {
      url,
      issues: [
        createIssue(
          url,
          "warning",
          "Public API scan failed — could not analyze",
          `Failed to scan public API surface for ${url}: ${error instanceof Error ? error.message : String(error)}`,
          "scan-failed",
        ),
      ],
      endpoints: [],
      summary: {
        totalEndpoints: 0,
        publicEndpoints: 0,
        authRequiredEndpoints: 0,
        notFoundEndpoints: 0,
        apiDomains: [],
        score: 0,
      },
    };
  }
}
