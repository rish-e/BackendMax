#!/usr/bin/env node

/**
 * Backend Max — MCP Server
 *
 * The AI-powered backend diagnostic that understands what you're building
 * and makes sure it actually works.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { scanRoutes } from "./tools/route-scanner.js";
import { checkContracts } from "./tools/contract-checker.js";
import { auditErrorHandling } from "./tools/error-auditor.js";
import { scanEnvVars } from "./tools/env-scanner.js";
import { auditSecurity } from "./tools/security-auditor.js";
import { auditPerformance } from "./tools/performance-auditor.js";
import { auditPrisma } from "./tools/prisma-auditor.js";
import { auditServerActions } from "./tools/server-actions-auditor.js";
import { generateDocs } from "./tools/doc-generator.js";
import { updateLedger, getLedger } from "./tools/ledger-manager.js";
import {
  getContext,
  initContext,
  updateContext,
} from "./tools/context-manager.js";
import { runFullDiagnosis } from "./tools/orchestrator.js";
import { fixIssue } from "./tools/fix-engine.js";
import { runSafetyChecks } from "./safety/index.js";
import { runLiveTests } from "./tools/live-tester.js";
import { buildApiGraph, queryApiGraph } from "./tools/api-graph.js";
import { getCommonPatterns } from "./tools/pattern-tracker.js";
import type { ApiGraph } from "./types.js";

const server = new McpServer(
  {
    name: "backend-max",
    version: "2.0.0",
  },
  {
    capabilities: { logging: {} },
    instructions: `Backend Max is an AI-powered backend diagnostic tool. It understands what the user is building and verifies the backend works correctly.

Key workflow:
1. Always run "init_context" first if no context exists — this understands the project
2. Use "run_diagnosis" for a full health check
3. Use individual audit tools for targeted checks
4. Use "get_api_docs" to read the living documentation
5. Use "fix_issue" to apply proposed fixes

The tool only analyzes backend code. It never modifies frontend/UI code.`,
  }
);

// ─── Core Orchestration ──────────────────────────────────────────────

server.tool(
  "run_diagnosis",
  "Run a full backend diagnosis — scans routes, checks contracts, audits errors, env vars, security, and performance. Generates documentation and updates the issue ledger. This is the main entry point.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
    focus: z
      .enum([
        "all",
        "routes",
        "contracts",
        "errors",
        "env",
        "security",
        "performance",
        "prisma",
        "server-actions",
      ])
      .default("all")
      .describe("Focus area for the diagnosis (default: all)"),
  },
  async ({ projectPath, focus }) => {
    try {
      const result = await runFullDiagnosis(projectPath, focus);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Diagnosis failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Project Context ─────────────────────────────────────────────────

server.tool(
  "init_context",
  "Analyze a project for the first time to understand what it does. Scans routes, package.json, database schema, and README to build a project understanding. Run this before any diagnosis.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const context = await initContext(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(context, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Context init failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "update_context",
  "Update the project understanding with user-provided corrections or additions.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
    updates: z
      .object({
        description: z.string().optional(),
        domains: z.array(z.string()).optional(),
        notes: z.array(z.string()).optional(),
      })
      .describe("Updates to apply to the project context"),
  },
  async ({ projectPath, updates }) => {
    try {
      const context = await updateContext(projectPath, updates);
      return {
        content: [{ type: "text", text: JSON.stringify(context, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Context update failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "get_context",
  "Get the current project understanding.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const context = await getContext(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(context, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `No project context found. Run init_context first.`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Individual Audit Tools ──────────────────────────────────────────

server.tool(
  "scan_routes",
  "Scan and parse all API routes in a Next.js project. Returns the full API surface: endpoints, HTTP methods, parameters, and file locations.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const routes = await scanRoutes(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(routes, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Route scan failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "check_contracts",
  "Verify frontend-backend contracts. Finds all API calls in frontend code and cross-references them against backend route definitions. Detects mismatches, dead endpoints, and phantom calls.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const result = await checkContracts(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Contract check failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "audit_errors",
  "Audit error handling across all API routes. Checks for try/catch coverage, consistent error response formats, unhandled promise rejections, and missing global error handlers.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const result = await auditErrorHandling(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error audit failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "audit_env",
  "Scan environment variable usage. Cross-references process.env references against .env files, checks for missing NEXT_PUBLIC_ prefixes, and detects undefined variables.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const result = await scanEnvVars(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Env audit failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "audit_security",
  "Check security posture. Detects auth middleware gaps, CORS misconfigurations, missing input validation, and known vulnerability patterns.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const result = await auditSecurity(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Security audit failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "audit_performance",
  "Detect performance anti-patterns. Finds N+1 queries, unbounded database calls, missing pagination, and payload bloat (backend returns more data than frontend uses).",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const result = await auditPerformance(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Performance audit failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "audit_prisma",
  "Audit Prisma schema and database usage. Parses schema.prisma, cross-references database calls against the schema to find nonexistent models/fields, suggests missing indexes, and checks for migration drift.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const result = await auditPrisma(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Prisma audit failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "audit_server_actions",
  "Audit Next.js Server Actions. Finds all 'use server' functions and checks for missing validation, error handling, auth checks, and unprotected database calls.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const result = await auditServerActions(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Server actions audit failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Documentation & History ─────────────────────────────────────────

server.tool(
  "get_api_docs",
  "Get the auto-generated living API documentation for the project. Returns the full route map with request/response types, auth requirements, and frontend consumers.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const docs = await generateDocs(projectPath);
      return {
        content: [{ type: "text", text: docs }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Doc generation failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "get_ledger",
  "Get the issue ledger — tracks every issue from discovery through fix. Filter by status, severity, or category.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
    filter: z
      .object({
        status: z
          .enum(["all", "open", "fixed", "ignored", "regressed"])
          .default("all"),
        severity: z
          .enum(["all", "critical", "warning", "info"])
          .default("all"),
        category: z.string().optional(),
      })
      .default({ status: "all", severity: "all" })
      .describe("Filter criteria for ledger entries"),
  },
  async ({ projectPath, filter }) => {
    try {
      const ledger = await getLedger(projectPath, filter);
      return {
        content: [{ type: "text", text: JSON.stringify(ledger, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Ledger read failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Fix Engine ──────────────────────────────────────────────────────

server.tool(
  "fix_issue",
  "Apply a proposed fix for a specific issue. Only fixes backend code — never touches frontend files.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
    issueId: z.string().describe("The issue ID to fix (e.g., CTR-001)"),
  },
  async ({ projectPath, issueId }) => {
    try {
      const result = await fixIssue(projectPath, issueId);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Fix failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Safety ──────────────────────────────────────────────────────────

server.tool(
  "run_safety_check",
  "Run safety validation on a project path. Validates the path is safe to scan, ensures .backend-doctor/ is in .gitignore, and prunes old reports. Call this before any diagnosis to verify the project is safe to analyze.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
  },
  async ({ projectPath }) => {
    try {
      const result = await runSafetyChecks(projectPath);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Safety check failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Live Testing ────────────────────────────────────────────────────

server.tool(
  "live_test",
  "Run live HTTP tests against discovered API endpoints. SAFETY: Only GET endpoints are tested. DELETE is never called. POST/PUT/PATCH are skipped (no safe payload generation). Only localhost URLs are accepted.",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
    baseUrl: z
      .string()
      .describe('Base URL of the running server (e.g., "http://localhost:3000")'),
    timeout: z
      .number()
      .default(5000)
      .describe("Per-request timeout in milliseconds (default: 5000)"),
    includeAuth: z
      .boolean()
      .default(false)
      .describe("Whether to test endpoints that require authentication"),
    dryRun: z
      .boolean()
      .default(false)
      .describe("If true, show what would be tested without making HTTP calls"),
  },
  async ({ projectPath, baseUrl, timeout, includeAuth, dryRun }) => {
    try {
      const result = await runLiveTests(projectPath, {
        baseUrl,
        timeout,
        includeAuth,
        dryRun,
      });
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Live test failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── API Graph ───────────────────────────────────────────────────────

/** Cache for API graphs to avoid rebuilding on repeated queries. */
const graphCache = new Map<string, ApiGraph>();

server.tool(
  "query_api",
  'Query the API graph with natural language. Builds a graph of routes, models, frontend components, and middleware, then queries it. Examples: "unprotected routes", "routes that write to users", "unused models".',
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project root directory"),
    query: z
      .string()
      .describe('Natural language query (e.g., "unprotected routes", "routes that write to users")'),
    rebuild: z
      .boolean()
      .default(false)
      .describe("Force rebuild the API graph (default: use cache)"),
  },
  async ({ projectPath, query, rebuild }) => {
    try {
      let graph = graphCache.get(projectPath);
      if (!graph || rebuild) {
        graph = await buildApiGraph(projectPath);
        graphCache.set(projectPath, graph);
      }

      const result = queryApiGraph(graph, query);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `API graph query failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Pattern Tracking ────────────────────────────────────────────────

server.tool(
  "get_patterns",
  "Get common patterns across projects. Shows the most frequently encountered issues for a given framework. Data is stored locally only — never sent externally.",
  {
    framework: z
      .string()
      .default("all")
      .describe('Framework to filter by (e.g., "nextjs", "express", or "all")'),
  },
  async ({ framework }) => {
    try {
      const patterns = await getCommonPatterns(framework);
      if (patterns.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: "No patterns tracked yet. Patterns are collected automatically after each diagnosis (opt-in).",
            },
          ],
        };
      }
      return {
        content: [{ type: "text", text: JSON.stringify(patterns, null, 2) }],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Pattern retrieval failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Start Server ────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Server failed to start:", error);
  process.exit(1);
});
