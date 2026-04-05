// =============================================================================
// backend-max — DNS & Infrastructure Auditor
//
// Analyzes DNS records, email security (SPF/DMARC/DKIM), CDN detection,
// and Certificate Authority Authorization for a given URL — all over the
// network using Node.js built-in DNS resolution. No source code needed.
// =============================================================================

import dns from "node:dns/promises";
import { URL } from "node:url";
import type { Issue, IssueCategory, Severity } from "../types.js";
import { generateIssueId } from "../utils/helpers.js";

const CATEGORY: IssueCategory = "dns";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DnsAuditResult {
  url: string;
  issues: Issue[];
  summary: {
    hostname: string;
    ipAddresses: string[];
    cnameChain: string[];
    mxRecords: string[];
    nameservers: string[];
    cdnDetected: string | null;
    hasSPF: boolean;
    hasDMARC: boolean;
    hasCAA: boolean;
    score: number; // 0-100
  };
}

// ---------------------------------------------------------------------------
// CDN detection patterns (matched against CNAME records)
// ---------------------------------------------------------------------------

const CDN_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /cloudflare/i, name: "Cloudflare" },
  { pattern: /fastly/i, name: "Fastly" },
  { pattern: /akamai/i, name: "Akamai" },
  { pattern: /cloudfront/i, name: "AWS CloudFront" },
  { pattern: /vercel/i, name: "Vercel" },
  { pattern: /netlify/i, name: "Netlify" },
  { pattern: /cdn77/i, name: "CDN77" },
  { pattern: /stackpath/i, name: "StackPath" },
  { pattern: /edgecast/i, name: "Edgecast" },
  { pattern: /azureedge/i, name: "Azure CDN" },
  { pattern: /googleusercontent/i, name: "Google Cloud CDN" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Safely resolve DNS records, returning an empty array on failure. */
async function safeResolve<T>(fn: () => Promise<T[]>): Promise<T[]> {
  try {
    return await fn();
  } catch {
    return [];
  }
}

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

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function auditDns(url: string): Promise<DnsAuditResult> {
  const issues: Issue[] = [];
  let score = 100;

  // Default summary for error fallback
  const emptySummary = {
    hostname: "",
    ipAddresses: [] as string[],
    cnameChain: [] as string[],
    mxRecords: [] as string[],
    nameservers: [] as string[],
    cdnDetected: null as string | null,
    hasSPF: false,
    hasDMARC: false,
    hasCAA: false,
    score: 0,
  };

  try {
    // Normalize URL and extract hostname
    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http")) targetUrl = `https://${targetUrl}`;
    const parsedUrl = new URL(targetUrl);
    const hostname = parsedUrl.hostname;

    // Extract the registrable domain (e.g., "example.com" from "www.example.com")
    const domainParts = hostname.split(".");
    const domain =
      domainParts.length > 2
        ? domainParts.slice(-2).join(".")
        : hostname;

    // -----------------------------------------------------------------------
    // Resolve all DNS record types in parallel
    // -----------------------------------------------------------------------

    const [aRecords, aaaaRecords, cnameRecords, mxRecords, txtRecords, nsRecords] =
      await Promise.all([
        safeResolve(() => dns.resolve4(hostname)),
        safeResolve(() => dns.resolve6(hostname)),
        safeResolve(() => dns.resolveCname(hostname)),
        safeResolve(() => dns.resolveMx(hostname)),
        safeResolve(() => dns.resolveTxt(hostname)),
        safeResolve(() => dns.resolveNs(hostname)),
      ]);

    const ipAddresses = [...aRecords, ...aaaaRecords];

    // If no A/AAAA records at all, that's a critical issue
    if (ipAddresses.length === 0) {
      score -= 20;
      issues.push(
        createIssue(
          targetUrl,
          "critical",
          "No A/AAAA records found",
          `Could not resolve any IP addresses for ${hostname}. The domain may not be properly configured.`,
          "no-ip-records",
        ),
      );
    }

    // No IPv6 (AAAA) records — informational
    if (aaaaRecords.length === 0 && aRecords.length > 0) {
      issues.push(
        createIssue(
          targetUrl,
          "info",
          "No IPv6 (AAAA) records",
          `${hostname} has no IPv6 records. Consider adding AAAA records for dual-stack connectivity.`,
          "no-ipv6",
        ),
      );
    }

    // -----------------------------------------------------------------------
    // MX records
    // -----------------------------------------------------------------------

    const mxStrings = mxRecords.map((r) => `${r.priority} ${r.exchange}`);

    // -----------------------------------------------------------------------
    // SPF check (TXT records starting with "v=spf1")
    // -----------------------------------------------------------------------

    // Flatten TXT record arrays (each TXT record is an array of strings)
    const flatTxt = txtRecords.map((chunks) => chunks.join(""));
    const spfRecord = flatTxt.find((t) => t.startsWith("v=spf1"));
    const hasSPF = !!spfRecord;

    if (!hasSPF) {
      score -= 10;
      issues.push(
        createIssue(
          targetUrl,
          "warning",
          "Missing SPF record",
          `No SPF (Sender Policy Framework) record found for ${domain}. ` +
            'Add a TXT record starting with "v=spf1" to prevent email spoofing.',
          "missing-spf",
        ),
      );
    }

    // -----------------------------------------------------------------------
    // DMARC check (_dmarc.{domain} TXT record)
    // -----------------------------------------------------------------------

    let hasDMARC = false;
    try {
      const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
      const dmarcFlat = dmarcRecords.map((chunks) => chunks.join(""));
      hasDMARC = dmarcFlat.some((t) => t.startsWith("v=DMARC1"));
    } catch {
      // No DMARC record
    }

    if (!hasDMARC) {
      score -= 10;
      issues.push(
        createIssue(
          targetUrl,
          "warning",
          "Missing DMARC record",
          `No DMARC record found at _dmarc.${domain}. ` +
            "Add a DMARC TXT record to specify how email receivers should handle unauthenticated mail.",
          "missing-dmarc",
        ),
      );
    }

    // -----------------------------------------------------------------------
    // DKIM presence note
    // -----------------------------------------------------------------------

    // DKIM selectors are domain-specific and not discoverable without knowing
    // the selector name. We note its absence as informational.
    issues.push(
      createIssue(
        targetUrl,
        "info",
        "DKIM selector unknown — cannot verify",
        `DKIM records require knowing the selector (e.g., "google._domainkey.${domain}"). ` +
          "Verify DKIM is configured with your email provider's recommended selector.",
        "dkim-unknown",
      ),
    );

    // -----------------------------------------------------------------------
    // CDN detection from CNAME records
    // -----------------------------------------------------------------------

    let cdnDetected: string | null = null;
    for (const cname of cnameRecords) {
      for (const cdn of CDN_PATTERNS) {
        if (cdn.pattern.test(cname)) {
          cdnDetected = cdn.name;
          break;
        }
      }
      if (cdnDetected) break;
    }

    // Also check A record reverse DNS or known IP ranges — but CNAME is the
    // primary signal for external auditing.

    // -----------------------------------------------------------------------
    // CAA records (Certificate Authority Authorization)
    // -----------------------------------------------------------------------

    let hasCAA = false;
    try {
      const caaRecords = await dns.resolveCaa(hostname);
      hasCAA = caaRecords.length > 0;
    } catch {
      // No CAA support or no records
    }

    // Also check parent domain for CAA if subdomain has none
    if (!hasCAA && hostname !== domain) {
      try {
        const caaRecords = await dns.resolveCaa(domain);
        hasCAA = caaRecords.length > 0;
      } catch {
        // No CAA
      }
    }

    if (!hasCAA) {
      score -= 5;
      issues.push(
        createIssue(
          targetUrl,
          "warning",
          "No CAA records found",
          `No Certificate Authority Authorization (CAA) records for ${hostname}. ` +
            "CAA records restrict which CAs can issue certificates for your domain, " +
            "reducing the risk of misissued certificates.",
          "missing-caa",
        ),
      );
    }

    // -----------------------------------------------------------------------
    // CDN fragmentation check
    // -----------------------------------------------------------------------

    // Fetch the page and look for resource origins to detect CDN fragmentation
    try {
      const response = await fetch(targetUrl, {
        method: "GET",
        redirect: "follow",
        signal: AbortSignal.timeout(10_000),
        headers: {
          "User-Agent": "BackendMax-Auditor/2.4.0",
          Accept: "text/html,*/*",
        },
      });
      const body = await response.text();

      // Extract all external resource URLs from src/href attributes
      const resourceUrlPattern = /(?:src|href)=["'](https?:\/\/[^"']+)["']/gi;
      const cdnOrigins = new Set<string>();
      let match: RegExpExecArray | null;

      while ((match = resourceUrlPattern.exec(body)) !== null) {
        try {
          const resourceHost = new URL(match[1]).hostname;
          // Only count if it's a different host from the main domain
          if (resourceHost !== hostname) {
            // Check if it matches a known CDN pattern
            for (const cdn of CDN_PATTERNS) {
              if (cdn.pattern.test(resourceHost)) {
                cdnOrigins.add(cdn.name);
                break;
              }
            }
          }
        } catch {
          // Malformed URL, skip
        }
      }

      if (cdnOrigins.size > 2) {
        score -= 5;
        issues.push(
          createIssue(
            targetUrl,
            "info",
            "CDN fragmentation detected",
            `Page loads resources from ${cdnOrigins.size} different CDN providers: ` +
              `${[...cdnOrigins].join(", ")}. Consolidating to fewer CDNs can improve ` +
              "cache hit rates and reduce DNS lookup overhead.",
            "cdn-fragmentation",
          ),
        );
      }
    } catch {
      // Could not fetch page for CDN fragmentation check — non-critical
    }

    // -----------------------------------------------------------------------
    // Nameserver checks
    // -----------------------------------------------------------------------

    if (nsRecords.length === 1) {
      score -= 5;
      issues.push(
        createIssue(
          targetUrl,
          "warning",
          "Single nameserver detected",
          `Only one nameserver (${nsRecords[0]}) found for ${hostname}. ` +
            "Use at least two nameservers for redundancy.",
          "single-ns",
        ),
      );
    }

    // -----------------------------------------------------------------------
    // Final score
    // -----------------------------------------------------------------------

    score = Math.max(0, score);

    return {
      url: targetUrl,
      issues,
      summary: {
        hostname,
        ipAddresses,
        cnameChain: cnameRecords,
        mxRecords: mxStrings,
        nameservers: nsRecords,
        cdnDetected,
        hasSPF,
        hasDMARC,
        hasCAA,
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
          "DNS audit failed — could not analyze",
          `Failed to audit DNS for ${url}: ${error instanceof Error ? error.message : String(error)}`,
          "dns-audit-failed",
        ),
      ],
      summary: { ...emptySummary, hostname: url },
    };
  }
}
