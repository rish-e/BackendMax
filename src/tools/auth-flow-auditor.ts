// =============================================================================
// backend-max — Authentication Flow Auditor
//
// Analyzes the authentication surface of a deployed application over HTTP.
// Discovers login endpoints, detects auth mechanisms, checks for CSRF
// tokens, tests for account enumeration, inspects password reset flows,
// and verifies rate limiting — all without source code access.
// =============================================================================

import type { Issue, IssueCategory, Severity } from "../types.js";
import { generateIssueId } from "../utils/helpers.js";

const CATEGORY: IssueCategory = "auth";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuthFlowAuditResult {
  url: string;
  issues: Issue[];
  summary: {
    loginEndpoint: string | null;
    authMechanisms: string[];
    hasCSRF: boolean;
    hasRateLimiting: boolean;
    accountEnumerationRisk: boolean;
    passwordResetFound: boolean;
    score: number; // 0-100
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Common login paths to probe. */
const LOGIN_PATHS = [
  "/login",
  "/signin",
  "/sign-in",
  "/auth/login",
  "/api/auth/signin",
  "/auth",
  "/account/login",
  "/users/sign_in",
  "/admin/login",
];

/** Common password reset paths. */
const RESET_PATHS = [
  "/forgot-password",
  "/forgot_password",
  "/reset-password",
  "/reset_password",
  "/auth/forgot-password",
  "/account/forgot-password",
  "/password/reset",
  "/api/auth/forgot-password",
];

/** OAuth provider patterns to detect in HTML. */
const OAUTH_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /accounts\.google\.com|googleapis\.com\/auth|google.*oauth|sign.*in.*with.*google/i, name: "Google OAuth" },
  { pattern: /github\.com\/login\/oauth|sign.*in.*with.*github/i, name: "GitHub OAuth" },
  { pattern: /appleid\.apple\.com|sign.*in.*with.*apple/i, name: "Apple Sign-In" },
  { pattern: /login\.microsoftonline\.com|sign.*in.*with.*microsoft/i, name: "Microsoft OAuth" },
  { pattern: /facebook\.com\/v\d+.*dialog\/oauth|sign.*in.*with.*facebook/i, name: "Facebook OAuth" },
  { pattern: /twitter\.com\/i\/oauth|sign.*in.*with.*twitter/i, name: "Twitter/X OAuth" },
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

/** Fetch a URL and return status + body, or null on failure. */
async function safeFetch(
  fetchUrl: string,
  options?: RequestInit,
): Promise<{ status: number; body: string; headers: Record<string, string> } | null> {
  try {
    const response = await fetch(fetchUrl, {
      redirect: "follow",
      signal: AbortSignal.timeout(10_000),
      headers: {
        "User-Agent": "BackendMax-Auditor/2.4.0",
        Accept: "text/html,application/json,*/*",
        ...(options?.headers as Record<string, string> | undefined),
      },
      ...options,
    });
    const body = (await response.text()).slice(0, 200_000);
    const headers: Record<string, string> = {};
    response.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    return { status: response.status, body, headers };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function auditAuthFlow(url: string): Promise<AuthFlowAuditResult> {
  const issues: Issue[] = [];
  let score = 100;

  let loginEndpoint: string | null = null;
  const authMechanisms: string[] = [];
  let hasCSRF = false;
  let hasRateLimiting = false;
  let accountEnumerationRisk = false;
  let passwordResetFound = false;

  try {
    // Normalize URL
    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http")) targetUrl = `https://${targetUrl}`;

    // =====================================================================
    // Step 1: Find the login page
    // =====================================================================

    // First, fetch the main page to look for login links
    const mainPage = await safeFetch(targetUrl);

    // Try known login paths
    for (const loginPath of LOGIN_PATHS) {
      const loginUrl = new URL(loginPath, targetUrl).toString();
      const result = await safeFetch(loginUrl);
      if (result && result.status >= 200 && result.status < 400) {
        loginEndpoint = loginUrl;
        break;
      }
    }

    // Also check if main page itself has a login form
    if (!loginEndpoint && mainPage) {
      const formMatch = mainPage.body.match(
        /<form[^>]*(?:action=["']([^"']*)["'])?[^>]*>/gi,
      );
      if (formMatch) {
        for (const form of formMatch) {
          const lower = form.toLowerCase();
          if (
            lower.includes("login") ||
            lower.includes("signin") ||
            lower.includes("sign-in") ||
            lower.includes("password")
          ) {
            loginEndpoint = targetUrl;
            break;
          }
        }
      }
    }

    if (!loginEndpoint) {
      issues.push(
        createIssue(
          targetUrl,
          "info",
          "No login endpoint discovered",
          "Could not find a login page at common paths. The application may use " +
            "a third-party auth provider, SPA-based auth, or non-standard login routes.",
          "no-login-found",
        ),
      );

      return {
        url: targetUrl,
        issues,
        summary: {
          loginEndpoint: null,
          authMechanisms,
          hasCSRF: false,
          hasRateLimiting: false,
          accountEnumerationRisk: false,
          passwordResetFound: false,
          score: Math.max(0, score),
        },
      };
    }

    // =====================================================================
    // Step 2: Analyze login page HTML
    // =====================================================================

    const loginPage = await safeFetch(loginEndpoint);
    if (loginPage) {
      const html = loginPage.body;

      // --- Detect auth mechanisms ---

      // Password form
      if (/<input[^>]*type=["']password["']/i.test(html)) {
        authMechanisms.push("password");
      }

      // OTP / magic link
      if (
        /magic[\s-]?link/i.test(html) ||
        /one[\s-]?time[\s-]?password/i.test(html) ||
        /OTP/i.test(html) ||
        /passwordless/i.test(html)
      ) {
        authMechanisms.push("OTP/magic-link");
      }

      // SSO
      if (/SSO|single[\s-]?sign[\s-]?on|SAML|saml/i.test(html)) {
        authMechanisms.push("SSO");
      }

      // OAuth providers
      for (const oauth of OAUTH_PATTERNS) {
        if (oauth.pattern.test(html)) {
          authMechanisms.push(oauth.name);
        }
      }

      if (authMechanisms.length === 0) {
        authMechanisms.push("unknown");
      }

      // --- Check for CSRF token ---
      const csrfPatterns = [
        /<input[^>]*name=["']_?csrf[^"']*["'][^>]*>/i,
        /<input[^>]*name=["']authenticity_token["'][^>]*>/i,
        /<input[^>]*name=["']__RequestVerificationToken["'][^>]*>/i,
        /<meta[^>]*name=["']csrf-token["'][^>]*>/i,
        /csrfToken/i,
        /csrfmiddlewaretoken/i,
        /X-CSRF-TOKEN/i,
      ];

      hasCSRF = csrfPatterns.some((p) => p.test(html));

      if (!hasCSRF && authMechanisms.includes("password")) {
        score -= 10;
        issues.push(
          createIssue(
            loginEndpoint,
            "warning",
            "No CSRF token found on login form",
            "The login form does not appear to include a CSRF token. " +
              "Without CSRF protection, attackers could trick authenticated users " +
              "into submitting login requests. Add CSRF token validation.",
            "missing-csrf",
          ),
        );
      }

      // --- Check form action uses HTTPS ---
      const formActionMatch = html.match(
        /<form[^>]*action=["'](http:\/\/[^"']+)["']/i,
      );
      if (formActionMatch) {
        score -= 15;
        issues.push(
          createIssue(
            loginEndpoint,
            "critical",
            "Login form submits over HTTP (not HTTPS)",
            `The login form action points to ${formActionMatch[1]} which uses plain HTTP. ` +
              "Credentials will be transmitted in plaintext. Change the form action to use HTTPS.",
            "form-action-http",
          ),
        );
      }

      // --- Check autocomplete on password field ---
      const passwordInputMatch = html.match(
        /<input[^>]*type=["']password["'][^>]*>/i,
      );
      if (passwordInputMatch) {
        const passwordInput = passwordInputMatch[0];
        if (!/autocomplete\s*=\s*["'](?:off|new-password|current-password)["']/i.test(passwordInput)) {
          issues.push(
            createIssue(
              loginEndpoint,
              "info",
              "Password field missing autocomplete attribute",
              "The password input does not specify an autocomplete attribute. " +
                'Set autocomplete="current-password" for login or autocomplete="new-password" ' +
                "for registration to improve password manager compatibility and security.",
              "password-autocomplete",
            ),
          );
        }
      }

      // --- Check for rate limiting headers ---
      const rateLimitHeaders = ["x-ratelimit-limit", "x-ratelimit-remaining", "retry-after", "x-rate-limit-limit"];
      for (const rlHeader of rateLimitHeaders) {
        if (loginPage.headers[rlHeader]) {
          hasRateLimiting = true;
          break;
        }
      }
    }

    // =====================================================================
    // Step 3: Test for account enumeration
    // =====================================================================

    // We try two POSTs with clearly fake credentials and compare error messages
    const loginPostUrl = loginEndpoint;
    const fakeEmail1 = "definitely-not-a-real-user-xyzzy@nonexistent-domain-test.example";
    const fakeEmail2 = "admin@example.com"; // Common format

    const enumResult1 = await safeFetch(loginPostUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "BackendMax-Auditor/2.4.0",
      },
      body: `email=${encodeURIComponent(fakeEmail1)}&password=FakePassword123!`,
    });

    const enumResult2 = await safeFetch(loginPostUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "BackendMax-Auditor/2.4.0",
      },
      body: `email=${encodeURIComponent(fakeEmail2)}&password=FakePassword123!`,
    });

    if (enumResult1 && enumResult2) {
      // Compare response bodies — if they're significantly different, there
      // may be account enumeration. We strip dynamic tokens/timestamps first.
      const normalize = (s: string) =>
        s
          .replace(/csrf[^"']*/gi, "")
          .replace(/token[^"']*/gi, "")
          .replace(/\d{10,}/g, "") // timestamps
          .trim();

      const body1 = normalize(enumResult1.body);
      const body2 = normalize(enumResult2.body);

      // Check for different status codes
      if (enumResult1.status !== enumResult2.status) {
        accountEnumerationRisk = true;
      }

      // Check for different error messages
      if (
        body1 !== body2 &&
        Math.abs(body1.length - body2.length) > 50
      ) {
        accountEnumerationRisk = true;
      }

      // Check for explicit "user not found" type messages
      const enumPatterns = [
        /user not found/i,
        /account not found/i,
        /email not found/i,
        /no account.*email/i,
        /doesn't exist/i,
        /does not exist/i,
        /not registered/i,
        /invalid email/i,
      ];

      for (const p of enumPatterns) {
        if (p.test(enumResult1.body) || p.test(enumResult2.body)) {
          accountEnumerationRisk = true;
          break;
        }
      }

      if (accountEnumerationRisk) {
        score -= 10;
        issues.push(
          createIssue(
            loginPostUrl,
            "warning",
            "Potential account enumeration vulnerability",
            "The login endpoint returns different responses for valid vs. invalid email addresses. " +
              "This allows attackers to enumerate valid accounts. Use a generic error message " +
              'like "Invalid email or password" regardless of whether the account exists.',
            "account-enumeration",
          ),
        );
      }
    }

    // =====================================================================
    // Step 4: Check password reset flow
    // =====================================================================

    for (const resetPath of RESET_PATHS) {
      const resetUrl = new URL(resetPath, targetUrl).toString();
      const result = await safeFetch(resetUrl);
      if (result && result.status >= 200 && result.status < 400) {
        passwordResetFound = true;

        // Check if password reset reveals email existence
        const resetPost = await safeFetch(resetUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "BackendMax-Auditor/2.4.0",
          },
          body: `email=${encodeURIComponent("definitely-fake-xyzzy@nonexistent-domain-test.example")}`,
        });

        if (resetPost) {
          const enumResetPatterns = [
            /email not found/i,
            /no account/i,
            /doesn't exist/i,
            /does not exist/i,
            /not registered/i,
            /user not found/i,
          ];

          for (const p of enumResetPatterns) {
            if (p.test(resetPost.body)) {
              score -= 5;
              issues.push(
                createIssue(
                  resetUrl,
                  "warning",
                  "Password reset reveals email existence",
                  "The password reset endpoint indicates whether an email address is registered. " +
                    "Use a generic message like \"If an account exists, a reset email has been sent\" " +
                    "to prevent email enumeration.",
                  "reset-enumeration",
                ),
              );
              break;
            }
          }
        }
        break;
      }
    }

    // Also check if login page body has a "forgot password" link
    if (!passwordResetFound && loginPage) {
      const loginBody = (await safeFetch(loginEndpoint))?.body ?? "";
      if (/forgot.*password|reset.*password/i.test(loginBody)) {
        passwordResetFound = true;
      }
    }

    // =====================================================================
    // Step 5: Test rate limiting
    // =====================================================================

    if (loginEndpoint && !hasRateLimiting) {
      // Send 5 rapid requests to the login endpoint
      const rapidRequests = Array.from({ length: 5 }, () =>
        safeFetch(loginEndpoint!, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "BackendMax-Auditor/2.4.0",
          },
          body: "email=ratelimit-test@example.com&password=TestPassword123!",
        }),
      );

      const results = await Promise.all(rapidRequests);

      for (const result of results) {
        if (!result) continue;

        // Check for 429 Too Many Requests
        if (result.status === 429) {
          hasRateLimiting = true;
          break;
        }

        // Check for rate limit headers
        const rlHeaders = ["x-ratelimit-limit", "x-ratelimit-remaining", "retry-after", "x-rate-limit-limit"];
        for (const h of rlHeaders) {
          if (result.headers[h]) {
            hasRateLimiting = true;
            break;
          }
        }
        if (hasRateLimiting) break;
      }

      if (!hasRateLimiting) {
        score -= 10;
        issues.push(
          createIssue(
            loginEndpoint,
            "warning",
            "No rate limiting detected on login endpoint",
            "Sent 5 rapid POST requests to the login endpoint without triggering rate limiting " +
              "(no 429 status or X-RateLimit-* headers). Without rate limiting, the login endpoint " +
              "is vulnerable to brute-force attacks. Implement rate limiting with backoff.",
            "no-rate-limiting",
          ),
        );
      }
    }

    // =====================================================================
    // Final score
    // =====================================================================

    score = Math.max(0, score);

    return {
      url: targetUrl,
      issues,
      summary: {
        loginEndpoint,
        authMechanisms,
        hasCSRF,
        hasRateLimiting,
        accountEnumerationRisk,
        passwordResetFound,
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
          "Auth flow audit failed — could not analyze",
          `Failed to audit auth flow for ${url}: ${error instanceof Error ? error.message : String(error)}`,
          "auth-audit-failed",
        ),
      ],
      summary: {
        loginEndpoint: null,
        authMechanisms: [],
        hasCSRF: false,
        hasRateLimiting: false,
        accountEnumerationRisk: false,
        passwordResetFound: false,
        score: 0,
      },
    };
  }
}
