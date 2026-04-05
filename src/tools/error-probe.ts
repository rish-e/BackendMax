// =============================================================================
// backend-max — Error Handling Probe
//
// Probes a deployed application for information disclosure through error
// responses. Tests 404 pages, malformed input, long URLs, wrong content
// types, and SQL injection patterns to detect stack traces, framework
// names, database errors, and debug output. No source code needed.
// =============================================================================

import type { Issue, IssueCategory, Severity } from "../types.js";
import { generateIssueId } from "../utils/helpers.js";

const CATEGORY: IssueCategory = "error-handling";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ErrorProbeResult {
  url: string;
  issues: Issue[];
  summary: {
    probesRun: number;
    informationLeaks: number;
    stackTraceExposed: boolean;
    frameworkExposed: string | null;
    databaseExposed: boolean;
    debugModeDetected: boolean;
    score: number; // 0-100
  };
}

// ---------------------------------------------------------------------------
// Detection patterns
// ---------------------------------------------------------------------------

/** Patterns that indicate stack trace exposure. */
const STACK_TRACE_PATTERNS = [
  /at Module\./i,
  /at Object\./i,
  /at Function\./i,
  /at process\./i,
  /Traceback \(most recent call/i,
  /Exception in thread/i,
  /Error:\s+.*\n\s+at\s/,
  /\.java:\d+\)/,
  /\.py", line \d+/,
  /\.rb:\d+:in/,
  /\.php on line \d+/,
];

/** Patterns that reveal framework/technology. */
const FRAMEWORK_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /Express/i, name: "Express" },
  { pattern: /Django/i, name: "Django" },
  { pattern: /Rails/i, name: "Ruby on Rails" },
  { pattern: /Laravel/i, name: "Laravel" },
  { pattern: /Spring(?:Boot)?/i, name: "Spring" },
  { pattern: /ASP\.NET/i, name: "ASP.NET" },
  { pattern: /Flask/i, name: "Flask" },
  { pattern: /FastAPI/i, name: "FastAPI" },
  { pattern: /Koa/i, name: "Koa" },
  { pattern: /Hapi/i, name: "Hapi" },
  { pattern: /Next\.js/i, name: "Next.js" },
  { pattern: /Nuxt/i, name: "Nuxt" },
  { pattern: /Symfony/i, name: "Symfony" },
  { pattern: /CakePHP/i, name: "CakePHP" },
];

/** Patterns that indicate database error exposure. */
const DATABASE_PATTERNS = [
  /SQL\s+syntax/i,
  /mysql/i,
  /postgres/i,
  /sqlite/i,
  /ORA-\d{5}/,
  /SQLSTATE\[/,
  /Microsoft SQL Server/i,
  /pg_query/i,
  /relation ".*" does not exist/i,
  /column ".*" does not exist/i,
  /syntax error at or near/i,
  /Unclosed quotation mark/i,
  /MongoDB\s+Error/i,
];

/** Patterns that indicate debug mode. */
const DEBUG_PATTERNS = [
  /DEBUG\s*[:=]\s*True/i,
  /\bstack\b.*\btrace\b/i,
  /\bverbose\b.*\berror\b/i,
  /WEB_DEBUG/i,
  /APP_DEBUG/i,
  /debug_toolbar/i,
  /DJANGO_SETTINGS_MODULE/i,
  /NODE_ENV.*development/i,
];

/** Patterns indicating file path disclosure. */
const FILE_PATH_PATTERNS = [
  /\/home\/\w+\//,
  /\/var\/www\//,
  /\/usr\/local\//,
  /\/opt\//,
  /C:\\Users\\/i,
  /C:\\inetpub\\/i,
  /C:\\Windows\\/i,
  /\/app\/src\//,
  /\/node_modules\//,
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

/** Analyze a response body for dangerous patterns. Returns categorized findings. */
function analyzeBody(body: string): {
  hasStackTrace: boolean;
  framework: string | null;
  hasDatabase: boolean;
  hasDebug: boolean;
  hasFilePaths: boolean;
} {
  const hasStackTrace = STACK_TRACE_PATTERNS.some((p) => p.test(body));
  let framework: string | null = null;
  for (const fp of FRAMEWORK_PATTERNS) {
    if (fp.pattern.test(body)) {
      framework = fp.name;
      break;
    }
  }
  const hasDatabase = DATABASE_PATTERNS.some((p) => p.test(body));
  const hasDebug = DEBUG_PATTERNS.some((p) => p.test(body));
  const hasFilePaths = FILE_PATH_PATTERNS.some((p) => p.test(body));

  return { hasStackTrace, framework, hasDatabase, hasDebug, hasFilePaths };
}

/** Send a probe request and return status + body. */
async function sendProbe(
  probeUrl: string,
  options?: RequestInit,
): Promise<{ status: number; body: string } | null> {
  try {
    const response = await fetch(probeUrl, {
      redirect: "follow",
      signal: AbortSignal.timeout(10_000),
      headers: {
        "User-Agent": "BackendMax-Auditor/2.4.0",
        Accept: "text/html,application/json,*/*",
        ...(options?.headers as Record<string, string> | undefined),
      },
      ...options,
    });
    // Limit body reading to 100KB to avoid memory issues
    const body = await response.text();
    return { status: response.status, body: body.slice(0, 100_000) };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Probe definitions
// ---------------------------------------------------------------------------

interface ProbeConfig {
  name: string;
  buildRequest: (baseUrl: string) => { url: string; options?: RequestInit };
  analyzeExtra?: (body: string, status: number) => {
    severity: Severity;
    title: string;
    description: string;
    detail: string;
  } | null;
}

const PROBES: ProbeConfig[] = [
  // Probe 1: Non-existent page (404 check)
  {
    name: "404-probe",
    buildRequest: (baseUrl) => ({
      url: new URL("/this-path-does-not-exist-probe-404", baseUrl).toString(),
    }),
  },

  // Probe 2: Malformed query string with script injection
  {
    name: "xss-reflection",
    buildRequest: (baseUrl) => ({
      url: new URL("/?<script>alert(1)</script>", baseUrl).toString(),
    }),
    analyzeExtra: (body, _status) => {
      // Check if our injected script tag is reflected verbatim in the response
      if (body.includes("<script>alert(1)</script>")) {
        return {
          severity: "critical",
          title: "Input reflected in error page — potential XSS",
          description:
            "The injected <script> tag was reflected verbatim in the error response. " +
            "This indicates a reflected XSS vulnerability. Sanitize all user input " +
            "before including it in HTML responses.",
          detail: "xss-reflection",
        };
      }
      return null;
    },
  },

  // Probe 3: Extremely long URL path
  {
    name: "long-url",
    buildRequest: (baseUrl) => {
      const longPath = "/" + "a".repeat(2500);
      return { url: new URL(longPath, baseUrl).toString() };
    },
    analyzeExtra: (_body, status) => {
      if (status !== 413 && status !== 414 && status !== 431) {
        return {
          severity: "info",
          title: "Server accepts extremely long URLs",
          description:
            `Server returned ${status} for a 2500+ character URL instead of 413/414/431. ` +
            "Consider configuring URL length limits to prevent potential DoS vectors.",
          detail: "long-url-accepted",
        };
      }
      return null;
    },
  },

  // Probe 4: Wrong Content-Type on POST
  {
    name: "wrong-content-type",
    buildRequest: (baseUrl) => ({
      url: new URL("/api/health", baseUrl).toString(),
      options: {
        method: "POST",
        headers: {
          "Content-Type": "text/plain",
          "User-Agent": "BackendMax-Auditor/2.4.0",
        },
        body: "this is not json",
      },
    }),
  },

  // Probe 5: SQL injection pattern in query parameter
  {
    name: "sqli-probe",
    buildRequest: (baseUrl) => ({
      url: new URL("/?id=1' OR '1'='1", baseUrl).toString(),
    }),
  },
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function probeErrorHandling(url: string): Promise<ErrorProbeResult> {
  const issues: Issue[] = [];
  let score = 100;
  let probesRun = 0;
  let informationLeaks = 0;
  let stackTraceExposed = false;
  let frameworkExposed: string | null = null;
  let databaseExposed = false;
  let debugModeDetected = false;

  try {
    // Normalize URL
    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http")) targetUrl = `https://${targetUrl}`;

    // -----------------------------------------------------------------------
    // Run all probes
    // -----------------------------------------------------------------------

    for (const probe of PROBES) {
      const { url: probeUrl, options } = probe.buildRequest(targetUrl);
      const result = await sendProbe(probeUrl, options);

      if (!result) continue;
      probesRun++;

      const { status, body } = result;
      const analysis = analyzeBody(body);

      // --- Stack trace detection ---
      if (analysis.hasStackTrace) {
        stackTraceExposed = true;
        informationLeaks++;
        score -= 15;
        issues.push(
          createIssue(
            probeUrl,
            "critical",
            `Stack trace exposed in ${probe.name} response`,
            `The ${probe.name} probe (${status}) returned a response containing stack traces. ` +
              "Stack traces reveal internal code structure and can help attackers craft targeted exploits. " +
              "Configure custom error pages and disable verbose errors in production.",
            `${probe.name}-stack-trace`,
          ),
        );
      }

      // --- Framework disclosure ---
      if (analysis.framework) {
        if (!frameworkExposed) frameworkExposed = analysis.framework;
        informationLeaks++;
        score -= 8;
        issues.push(
          createIssue(
            probeUrl,
            "warning",
            `Framework disclosed: ${analysis.framework}`,
            `The ${probe.name} probe response reveals the use of ${analysis.framework}. ` +
              "Knowing the exact framework helps attackers target known vulnerabilities. " +
              "Use generic error pages that don't reference framework internals.",
            `${probe.name}-framework-${analysis.framework}`,
          ),
        );
      }

      // --- Database error disclosure ---
      if (analysis.hasDatabase) {
        databaseExposed = true;
        informationLeaks++;
        score -= 15;
        issues.push(
          createIssue(
            probeUrl,
            "critical",
            `Database error exposed in ${probe.name} response`,
            `The ${probe.name} probe triggered a response containing database error details. ` +
              "Database errors can reveal table names, column names, and query structure. " +
              "Catch all database exceptions and return generic error messages to clients.",
            `${probe.name}-database-leak`,
          ),
        );
      }

      // --- Debug mode detection ---
      if (analysis.hasDebug) {
        debugModeDetected = true;
        informationLeaks++;
        score -= 10;
        issues.push(
          createIssue(
            probeUrl,
            "warning",
            `Debug mode indicators in ${probe.name} response`,
            `The ${probe.name} probe response contains debug mode indicators. ` +
              "Ensure DEBUG is disabled in production and no debug toolbars are exposed.",
            `${probe.name}-debug-mode`,
          ),
        );
      }

      // --- File path disclosure ---
      if (analysis.hasFilePaths) {
        informationLeaks++;
        score -= 5;
        issues.push(
          createIssue(
            probeUrl,
            "warning",
            `File paths exposed in ${probe.name} response`,
            `The ${probe.name} probe response contains server file system paths. ` +
              "File paths reveal the deployment structure and can aid directory traversal attacks. " +
              "Strip file paths from error messages in production.",
            `${probe.name}-file-paths`,
          ),
        );
      }

      // --- Probe-specific extra analysis ---
      if (probe.analyzeExtra) {
        const extra = probe.analyzeExtra(body, status);
        if (extra) {
          informationLeaks++;
          score -= extra.severity === "critical" ? 15 : extra.severity === "warning" ? 8 : 3;
          issues.push(createIssue(probeUrl, extra.severity, extra.title, extra.description, extra.detail));
        }
      }
    }

    // -----------------------------------------------------------------------
    // Final score
    // -----------------------------------------------------------------------

    score = Math.max(0, score);

    return {
      url: targetUrl,
      issues,
      summary: {
        probesRun,
        informationLeaks,
        stackTraceExposed,
        frameworkExposed,
        databaseExposed,
        debugModeDetected,
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
          "Error probe failed — could not analyze",
          `Failed to probe error handling for ${url}: ${error instanceof Error ? error.message : String(error)}`,
          "probe-failed",
        ),
      ],
      summary: {
        probesRun,
        informationLeaks: 0,
        stackTraceExposed: false,
        frameworkExposed: null,
        databaseExposed: false,
        debugModeDetected: false,
        score: 0,
      },
    };
  }
}
