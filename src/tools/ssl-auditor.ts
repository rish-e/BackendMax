// =============================================================================
// backend-max — TLS / SSL Certificate Auditor
//
// Analyzes TLS configuration and certificate health using Node.js built-in
// `node:tls` and `node:https` modules. Checks protocol version, cipher
// strength, certificate expiry, and HTTP-to-HTTPS redirect behavior.
// =============================================================================

import * as https from "node:https";
import * as tls from "node:tls";
import { URL } from "node:url";
import type { Issue, IssueCategory, Severity } from "../types.js";
import { generateIssueId } from "../utils/helpers.js";

const CATEGORY: IssueCategory = "ssl";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SslAuditResult {
  url: string;
  issues: Issue[];
  summary: {
    tlsVersion: string | null;
    cipher: string | null;
    certificateIssuer: string | null;
    certificateExpiry: string | null;
    daysUntilExpiry: number | null;
    hstsEnabled: boolean;
    httpRedirects: boolean;
    score: number; // 0-100
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const USER_AGENT = "BackendMax-Auditor/2.4.0";

/**
 * Connects to a host over HTTPS and extracts TLS socket details and the
 * peer certificate. Returns null if the connection fails.
 */
function getTlsInfo(
  hostname: string,
  port: number,
): Promise<{
  protocol: string | null;
  cipher: { name: string; version: string } | null;
  cert: tls.PeerCertificate | null;
} | null> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      req.destroy();
      resolve(null);
    }, 10_000);

    const req = https.request(
      {
        hostname,
        port,
        path: "/",
        method: "HEAD",
        headers: { "User-Agent": USER_AGENT },
        // Accept any cert so we can still inspect expired/self-signed ones
        rejectUnauthorized: false,
      },
      (res) => {
        const socket = res.socket as tls.TLSSocket;
        clearTimeout(timeout);

        const protocol = socket.getProtocol?.() ?? null;
        const cipherInfo = socket.getCipher?.() ?? null;
        let cert: tls.PeerCertificate | null = null;

        try {
          cert = socket.getPeerCertificate(false);
          // getPeerCertificate returns an empty object when there is no cert
          if (cert && !cert.subject) cert = null;
        } catch {
          cert = null;
        }

        res.resume(); // drain the response
        resolve({
          protocol,
          cipher: cipherInfo ? { name: cipherInfo.name, version: cipherInfo.version } : null,
          cert,
        });
      },
    );

    req.on("error", () => {
      clearTimeout(timeout);
      resolve(null);
    });

    req.end();
  });
}

// ---------------------------------------------------------------------------
// Weak cipher detection
// ---------------------------------------------------------------------------

const WEAK_CIPHER_PATTERNS = [
  "RC4",
  "DES",
  "3DES",
  "NULL",
  "EXPORT",
  "anon",
  "MD5",
];

function isCipherWeak(cipherName: string): boolean {
  const upper = cipherName.toUpperCase();
  return WEAK_CIPHER_PATTERNS.some((p) => upper.includes(p));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function auditSsl(url: string): Promise<SslAuditResult> {
  const issues: Issue[] = [];
  let score = 100;

  // Summary fields
  let tlsVersion: string | null = null;
  let cipher: string | null = null;
  let certificateIssuer: string | null = null;
  let certificateExpiry: string | null = null;
  let daysUntilExpiry: number | null = null;
  let hstsEnabled = false;
  let httpRedirects = false;

  try {
    // Normalize URL
    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http")) targetUrl = `https://${targetUrl}`;

    const parsed = new URL(targetUrl);
    const hostname = parsed.hostname;
    const port = parsed.port ? parseInt(parsed.port, 10) : 443;

    // ------------------------------------------------------------------
    // TLS connection and certificate extraction
    // ------------------------------------------------------------------
    const tlsInfo = await getTlsInfo(hostname, port);

    if (!tlsInfo) {
      score -= 30;
      issues.push({
        id: generateIssueId(CATEGORY, targetUrl, "tls-connect-failed"),
        category: CATEGORY,
        severity: "critical",
        title: "TLS connection failed",
        description:
          `Could not establish a TLS connection to ${hostname}:${port}. ` +
          "The server may not support HTTPS, or there may be a network/firewall issue.",
        file: targetUrl,
        line: null,
        status: "open",
        firstSeen: new Date().toISOString(),
        fixedAt: null,
      });
    } else {
      // --- Protocol version ---
      tlsVersion = tlsInfo.protocol;
      if (tlsVersion) {
        if (tlsVersion === "TLSv1.3") {
          // Best — no penalty
        } else if (tlsVersion === "TLSv1.2") {
          // Acceptable but not ideal
          score -= 3;
          issues.push({
            id: generateIssueId(CATEGORY, targetUrl, "tls-12"),
            category: CATEGORY,
            severity: "info",
            title: "Server uses TLS 1.2 instead of TLS 1.3",
            description:
              "The server negotiated TLS 1.2. While still secure, TLS 1.3 offers improved " +
              "performance (fewer round trips) and stronger security (no legacy cipher suites). " +
              "Consider enabling TLS 1.3 support.",
            file: targetUrl,
            line: null,
            status: "open",
            firstSeen: new Date().toISOString(),
            fixedAt: null,
          });
        } else {
          // TLS 1.1, 1.0, or SSL — critical
          score -= 20;
          issues.push({
            id: generateIssueId(CATEGORY, targetUrl, "tls-legacy"),
            category: CATEGORY,
            severity: "critical",
            title: `Server uses outdated protocol: ${tlsVersion}`,
            description:
              `The server negotiated ${tlsVersion}, which is deprecated and has known vulnerabilities. ` +
              "Disable TLS 1.0 and TLS 1.1. Only allow TLS 1.2 and TLS 1.3.",
            file: targetUrl,
            line: null,
            status: "open",
            firstSeen: new Date().toISOString(),
            fixedAt: null,
          });
        }
      }

      // --- Cipher suite ---
      if (tlsInfo.cipher) {
        cipher = tlsInfo.cipher.name;

        if (isCipherWeak(tlsInfo.cipher.name)) {
          score -= 15;
          issues.push({
            id: generateIssueId(CATEGORY, targetUrl, "weak-cipher"),
            category: CATEGORY,
            severity: "critical",
            title: `Weak cipher suite: ${tlsInfo.cipher.name}`,
            description:
              `The server negotiated a weak cipher suite: ${tlsInfo.cipher.name}. ` +
              "This cipher is vulnerable to known attacks. Configure your server to " +
              "only allow strong cipher suites (AES-GCM, ChaCha20-Poly1305).",
            file: targetUrl,
            line: null,
            status: "open",
            firstSeen: new Date().toISOString(),
            fixedAt: null,
          });
        }
      }

      // --- Certificate analysis ---
      if (tlsInfo.cert) {
        const cert = tlsInfo.cert;

        // Issuer
        if (cert.issuer) {
          const rawIssuer = cert.issuer.O ?? cert.issuer.CN ?? null;
          certificateIssuer = Array.isArray(rawIssuer) ? rawIssuer[0] ?? null : rawIssuer;
        }

        // Expiry
        if (cert.valid_to) {
          certificateExpiry = cert.valid_to;
          const expiryDate = new Date(cert.valid_to);
          const now = new Date();
          daysUntilExpiry = Math.floor(
            (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
          );

          if (daysUntilExpiry < 0) {
            score -= 25;
            issues.push({
              id: generateIssueId(CATEGORY, targetUrl, "cert-expired"),
              category: CATEGORY,
              severity: "critical",
              title: "SSL certificate has expired",
              description:
                `The certificate expired on ${cert.valid_to} (${Math.abs(daysUntilExpiry)} days ago). ` +
                "Browsers will show security warnings. Renew the certificate immediately.",
              file: targetUrl,
              line: null,
              status: "open",
              firstSeen: new Date().toISOString(),
              fixedAt: null,
            });
          } else if (daysUntilExpiry <= 7) {
            score -= 15;
            issues.push({
              id: generateIssueId(CATEGORY, targetUrl, "cert-expiry-critical"),
              category: CATEGORY,
              severity: "critical",
              title: `SSL certificate expires in ${daysUntilExpiry} day(s)`,
              description:
                `The certificate expires on ${cert.valid_to} — only ${daysUntilExpiry} day(s) remaining. ` +
                "Renew immediately to avoid downtime and browser security warnings.",
              file: targetUrl,
              line: null,
              status: "open",
              firstSeen: new Date().toISOString(),
              fixedAt: null,
            });
          } else if (daysUntilExpiry <= 30) {
            score -= 5;
            issues.push({
              id: generateIssueId(CATEGORY, targetUrl, "cert-expiry-warning"),
              category: CATEGORY,
              severity: "warning",
              title: `SSL certificate expires in ${daysUntilExpiry} days`,
              description:
                `The certificate expires on ${cert.valid_to} — ${daysUntilExpiry} days remaining. ` +
                "Plan certificate renewal soon to avoid unexpected expiry.",
              file: targetUrl,
              line: null,
              status: "open",
              firstSeen: new Date().toISOString(),
              fixedAt: null,
            });
          }
        }

        // Check if self-signed
        if (cert.issuer && cert.subject) {
          const issuerCN = cert.issuer.CN ?? "";
          const subjectCN = cert.subject.CN ?? "";
          if (issuerCN === subjectCN && issuerCN !== "") {
            score -= 10;
            issues.push({
              id: generateIssueId(CATEGORY, targetUrl, "self-signed"),
              category: CATEGORY,
              severity: "warning",
              title: "SSL certificate appears to be self-signed",
              description:
                `The certificate issuer (${issuerCN}) matches the subject, indicating a self-signed certificate. ` +
                "Browsers will not trust this certificate. Use a certificate from a trusted CA (e.g., Let's Encrypt).",
              file: targetUrl,
              line: null,
              status: "open",
              firstSeen: new Date().toISOString(),
              fixedAt: null,
            });
          }
        }
      } else {
        score -= 10;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "no-cert"),
          category: CATEGORY,
          severity: "warning",
          title: "Could not retrieve SSL certificate",
          description:
            "The TLS connection succeeded but no peer certificate was returned. " +
            "This may indicate a misconfigured server or proxy.",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }
    }

    // ------------------------------------------------------------------
    // Check HSTS header
    // ------------------------------------------------------------------
    try {
      const resp = await fetch(targetUrl, {
        method: "HEAD",
        redirect: "follow",
        signal: AbortSignal.timeout(10_000),
        headers: { "User-Agent": USER_AGENT },
      });

      const hstsHeader = resp.headers.get("strict-transport-security");
      if (hstsHeader) {
        hstsEnabled = true;
      } else {
        score -= 5;
        issues.push({
          id: generateIssueId(CATEGORY, targetUrl, "no-hsts"),
          category: CATEGORY,
          severity: "warning",
          title: "No HSTS header on HTTPS response",
          description:
            "The HTTPS response does not include a Strict-Transport-Security header. " +
            "Without HSTS, browsers can be tricked into downgrading to HTTP. " +
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
          file: targetUrl,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        });
      }
    } catch {
      // HSTS check failed — non-fatal
    }

    // ------------------------------------------------------------------
    // Check HTTP -> HTTPS redirect
    // ------------------------------------------------------------------
    if (targetUrl.startsWith("https://")) {
      try {
        const httpUrl = targetUrl.replace("https://", "http://");
        const httpResp = await fetch(httpUrl, {
          method: "HEAD",
          redirect: "manual",
          signal: AbortSignal.timeout(5_000),
          headers: { "User-Agent": USER_AGENT },
        });

        if (httpResp.status === 301 || httpResp.status === 308) {
          const location = httpResp.headers.get("location") ?? "";
          if (location.startsWith("https://")) {
            httpRedirects = true;
          }
        }

        if (!httpRedirects) {
          score -= 10;
          issues.push({
            id: generateIssueId(CATEGORY, targetUrl, "no-https-redirect"),
            category: CATEGORY,
            severity: "warning",
            title: "HTTP does not redirect to HTTPS",
            description:
              `HTTP request returned status ${httpResp.status} instead of a 301/308 redirect to HTTPS. ` +
              "Configure your server to permanently redirect all HTTP traffic to HTTPS.",
            file: targetUrl,
            line: null,
            status: "open",
            firstSeen: new Date().toISOString(),
            fixedAt: null,
          });
        }
      } catch {
        // HTTP port may be closed — that is acceptable for HTTPS-only sites
        httpRedirects = false;
      }
    }

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    return {
      url: targetUrl,
      issues,
      summary: {
        tlsVersion,
        cipher,
        certificateIssuer,
        certificateExpiry,
        daysUntilExpiry,
        hstsEnabled,
        httpRedirects,
        score,
      },
    };
  } catch (error) {
    return {
      url,
      issues: [
        {
          id: generateIssueId(CATEGORY, url, "audit-failed"),
          category: CATEGORY,
          severity: "warning",
          title: "SSL audit failed — unexpected error",
          description: `SSL audit of ${url} failed: ${error instanceof Error ? error.message : String(error)}`,
          file: url,
          line: null,
          status: "open",
          firstSeen: new Date().toISOString(),
          fixedAt: null,
        },
      ],
      summary: {
        tlsVersion: null,
        cipher: null,
        certificateIssuer: null,
        certificateExpiry: null,
        daysUntilExpiry: null,
        hstsEnabled: false,
        httpRedirects: false,
        score: 0,
      },
    };
  }
}
