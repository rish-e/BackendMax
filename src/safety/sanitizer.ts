/**
 * Output Sanitizer — Scrubs sensitive data from reports, logs, and MCP responses.
 * Runs regex patterns to detect and redact common secret formats.
 */

// ---------------------------------------------------------------------------
// Secret detection patterns
// ---------------------------------------------------------------------------

interface SecretPattern {
  name: string;
  regex: RegExp;
  replacement: string;
  contextRequired?: boolean;
}

/** All secret patterns used for detection and redaction. */
export const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "AWS Access Key",
    regex: /(AKIA[0-9A-Z]{16})/g,
    replacement: "[REDACTED_AWS_KEY]",
  },
  {
    name: "GitHub Token",
    regex: /(ghp_[A-Za-z0-9]{36})/g,
    replacement: "[REDACTED_GITHUB_TOKEN]",
  },
  {
    name: "GitHub PAT",
    regex: /(github_pat_[A-Za-z0-9_]{82})/g,
    replacement: "[REDACTED_GITHUB_TOKEN]",
  },
  {
    name: "Stripe Secret Key",
    regex: /(sk_live_[A-Za-z0-9]{24,})/g,
    replacement: "[REDACTED_STRIPE_KEY]",
  },
  {
    name: "Stripe Publishable Key",
    regex: /(pk_live_[A-Za-z0-9]{24,})/g,
    replacement: "[REDACTED_STRIPE_KEY]",
  },
  {
    name: "JWT",
    regex: /(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g,
    replacement: "[REDACTED_JWT]",
  },
  {
    name: "Generic API Key",
    regex: /(api[_-]?key[_-]?[=:]\s*['"]?[A-Za-z0-9_-]{20,})/gi,
    replacement: "[REDACTED_API_KEY]",
  },
  {
    name: "Connection String",
    regex: /((?:postgres|mysql|mongodb|redis|amqp)(?:\+srv)?:\/\/[^\s'"]+)/gi,
    replacement: "[REDACTED_CONNECTION_STRING]",
  },
  {
    name: "Private Key",
    regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g,
    replacement: "[REDACTED_PRIVATE_KEY]",
  },
  {
    name: "Slack Token",
    regex: /(xox[bpras]-[A-Za-z0-9-]{10,})/g,
    replacement: "[REDACTED_SLACK_TOKEN]",
  },
  {
    name: "SendGrid Key",
    regex: /(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})/g,
    replacement: "[REDACTED_SENDGRID_KEY]",
  },
  {
    name: "Twilio Key",
    regex: /(SK[a-f0-9]{32})/g,
    replacement: "[REDACTED_TWILIO_KEY]",
  },
];

/** AWS secret key pattern — only applied near AWS context. */
const AWS_SECRET_REGEX = /([A-Za-z0-9/+=]{40})/g;
const AWS_CONTEXT_REGEX = /aws|amazon|AKIA|secret.?access/i;

/** Long hex strings in suspicious context. */
const LONG_HEX_REGEX = /(['"][a-f0-9]{32,}['"])/g;
const SUSPICIOUS_CONTEXT_REGEX = /secret|token|key|password/i;

/** Fields that should be completely redacted when writing to disk. */
const SENSITIVE_FIELD_NAMES: Set<string> = new Set([
  "password",
  "secret",
  "token",
  "apiKey",
  "api_key",
  "accessToken",
  "access_token",
  "refreshToken",
  "refresh_token",
  "privateKey",
  "private_key",
]);

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Deep-clone any value. Handles objects, arrays, and primitives.
 */
function deepClone<T>(value: T): T {
  if (value === null || value === undefined) return value;
  if (typeof value !== "object") return value;
  return JSON.parse(JSON.stringify(value)) as T;
}

/**
 * Apply all secret-detection regexes to a single string.
 */
function scrubString(input: string): string {
  let result = input;

  // Apply standard patterns
  for (const pattern of SECRET_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.regex.lastIndex = 0;
    result = result.replace(pattern.regex, pattern.replacement);
  }

  // AWS secret — only if AWS context is nearby
  if (AWS_CONTEXT_REGEX.test(result)) {
    result = result.replace(AWS_SECRET_REGEX, (match) => {
      // Avoid false positives on base64 that's clearly not a key
      if (/^[A-Za-z]+$/.test(match)) return match;
      return "[REDACTED_AWS_SECRET]";
    });
  }

  // Long hex in suspicious context
  const lines = result.split("\n");
  const scrubbed: string[] = [];
  for (const line of lines) {
    if (SUSPICIOUS_CONTEXT_REGEX.test(line)) {
      LONG_HEX_REGEX.lastIndex = 0;
      scrubbed.push(line.replace(LONG_HEX_REGEX, "[REDACTED_HEX_SECRET]"));
    } else {
      scrubbed.push(line);
    }
  }
  result = scrubbed.join("\n");

  return result;
}

/**
 * Walk an object tree and apply a transformation to every string value.
 */
function walkAndScrub(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;

  if (typeof obj === "string") {
    return scrubString(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => walkAndScrub(item));
  }

  if (typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = walkAndScrub(value);
    }
    return result;
  }

  return obj;
}

/**
 * Walk an object tree and redact entire fields by name.
 */
function redactSensitiveFields(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;

  if (Array.isArray(obj)) {
    return obj.map((item) => redactSensitiveFields(item));
  }

  if (typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      if (SENSITIVE_FIELD_NAMES.has(key)) {
        result[key] = "[FIELD_REDACTED]";
      } else {
        result[key] = redactSensitiveFields(value);
      }
    }
    return result;
  }

  return obj;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Sanitize a report object by scrubbing secret patterns from all string values.
 * Returns a deep clone — the original object is never mutated.
 *
 * @param report - Any object (typically a DiagnosisReport).
 * @returns A sanitized deep clone.
 */
export function sanitizeReport(report: unknown): unknown {
  const cloned = deepClone(report);
  return walkAndScrub(cloned);
}

/**
 * Sanitize data for writing to disk. Applies all report sanitization plus
 * removes entire fields with sensitive names (password, secret, token, etc.).
 *
 * @param data - Any object to sanitize before persisting.
 * @returns A sanitized deep clone safe for disk storage.
 */
export function sanitizeForDisk(data: unknown): unknown {
  const scrubbed = sanitizeReport(data);
  return redactSensitiveFields(scrubbed);
}

/**
 * Sanitize data and serialize to a JSON string. Applies a final regex pass
 * over the stringified output to catch anything the object walk missed.
 *
 * @param data - Any object to sanitize and serialize.
 * @returns A sanitized JSON string.
 */
export function sanitizeForOutput(data: unknown): string {
  const diskSafe = sanitizeForDisk(data);
  let json = JSON.stringify(diskSafe, null, 2);

  // Final pass: apply patterns to the raw string
  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    json = json.replace(pattern.regex, pattern.replacement);
  }

  return json;
}

/**
 * Quick check whether a string contains any detectable secret patterns.
 * Useful for pre-flight validation before writing to disk or returning output.
 *
 * @param text - The text to scan.
 * @returns An object indicating if secrets were found and which pattern types matched.
 */
export function containsSecrets(text: string): { found: boolean; patterns: string[] } {
  const matched: string[] = [];

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    if (pattern.regex.test(text)) {
      matched.push(pattern.name);
    }
  }

  // Check AWS secret in context
  if (AWS_CONTEXT_REGEX.test(text)) {
    AWS_SECRET_REGEX.lastIndex = 0;
    if (AWS_SECRET_REGEX.test(text)) {
      matched.push("AWS Secret Key");
    }
  }

  return {
    found: matched.length > 0,
    patterns: matched,
  };
}
