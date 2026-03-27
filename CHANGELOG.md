# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] — 2026-03-27

### Added — Tier 1 Feature Drop

#### Auto-Fix Engine (v2)
- Generates actual unified diff patches for common issue categories
- Patches for: error handling (try/catch wrapping), validation (Zod schemas), auth checks, performance (pagination), env var guards
- `fix_issue` now returns `git apply`-compatible diffs instead of text descriptions
- New MCP tool: `fix_all_issues` — batch-generate patches for all open issues
- Fallback: detailed markdown fix descriptions when auto-patching isn't possible

#### Watch Mode / Incremental Analysis
- New MCP tool: `watch_diagnosis` — compares current state against last saved report
- Reports: new issues, fixed issues, health score delta, changed files
- New MCP tool: `check_changes` — quick check of what changed since last run (no re-analysis)
- First run automatically establishes baseline; subsequent runs show deltas

#### tRPC Support
- Full tRPC router analyzer implementing FrameworkAnalyzer interface
- Detects `@trpc/server` / `@trpc/next` in dependencies
- Parses `router({})` and `createTRPCRouter({})` definitions
- Extracts procedures: queries, mutations, subscriptions
- Checks `.input()` for validation, `protectedProcedure` for auth
- 3 tRPC-specific checks: unvalidated mutations, unprotected mutations, missing error handling
- Maps procedures to RouteInfo format for full compatibility with existing audit engines

#### GraphQL Resolver Analysis
- Full GraphQL analyzer implementing FrameworkAnalyzer interface
- Detects: graphql, @apollo/server, mercurius, graphql-yoga, type-graphql, nexus, @pothos/core
- Parses both object-literal resolvers (`Query: { ... }`) and decorator-based (`@Query`, `@Mutation`)
- N+1 detection: flags resolvers with DB calls when DataLoader is not installed
- 4 GraphQL-specific checks: N+1 queries, unprotected mutations, missing error handling, missing input validation
- Supports NestJS GraphQL / type-graphql decorator patterns

#### Dependency Vulnerability Scanner
- Heuristic-based scanner — no network required for basic checks
- Built-in database of 12+ known vulnerable packages with version-range matching
- Deprecated/compromised package detection (request, colors, faker, event-stream, etc.)
- Lock file presence check (package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lockb)
- Version range safety checks (unpinned `*`, unbounded `>=` ranges)
- Optional npm audit integration (when package-lock.json exists)
- New MCP tool: `scan_dependencies`
- Integrated into orchestrator with `--focus dependencies`

### Changed
- Framework registry now includes tRPC and GraphQL analyzers (detection priority: Next.js → tRPC → GraphQL → Express)
- Issue ID prefix map expanded: TPC (tRPC), GQL (GraphQL), DEP (dependency), CTM (contract-type-mismatch), EXP (Express), PRS (Prisma), SAC (server-actions)
- Orchestrator runs dependency scan as part of full diagnosis
- Focus areas expanded: `dependencies` added to diagnosis focus enum
- Version bumped to 2.1.0
- Fix engine rewritten from stub to full patch generator

## [2.0.0] — 2026-03-27

### Added — Major Feature Release

#### Prisma Schema Integration
- Full `.prisma` schema parser (regex-based, no heavy dependencies)
- Cross-references every `prisma.*` call against the actual schema
- Detects nonexistent models, nonexistent fields, missing indexes
- Migration drift detection (heuristic — flags stale migrations)
- New MCP tool: `audit_prisma`

#### Deeper Type Flow Analysis
- Traces frontend response variables to check property access patterns
- Compares frontend property usage against backend return types
- Catches deep contract mismatches: `data.user.firstName` vs `data.user.first_name`
- Integrated into contract checker for unified reporting

#### Server Actions Support
- Detects `'use server'` directives (file-level and inline)
- Analyzes server action functions with same audit engines as route handlers
- Checks validation, error handling, auth, and database call patterns
- New MCP tool: `audit_server_actions`

#### CI/CD Mode
- New CLI entry point: `npx backend-max-cli diagnose [path] [options]`
- Flags: `--ci`, `--min-score`, `--fail-on`, `--format`, `--json`
- Output formats: text (colored), markdown (PR comments), JSON, SARIF (GitHub Code Scanning)
- Exit code 1 when health score below threshold or critical issues found
- GitHub Actions compatible

#### Express.js Framework Support
- Full Express route analyzer: `app.get()`, `router.post()`, etc.
- Router mounting resolution (`app.use('/prefix', router)`)
- Express-specific checks: error middleware, 404 handler, body parser, helmet/CORS
- Framework plugin architecture — common `FrameworkAnalyzer` interface

#### Next.js Pages Router Support
- Scans `pages/api/` for Pages Router API routes
- Detects HTTP methods from `req.method` checks inside handlers
- Full parity with App Router analysis (validation, auth, errors, DB calls)

#### Live Testing Mode (Optional)
- HTTP endpoint testing against running dev server
- Safety-first: only tests GET endpoints, never calls DELETE
- Checks status codes, response times, JSON validity, error stack traces
- Localhost-only by default — requires explicit flag for remote
- New MCP tool: `live_test`

#### Queryable API Graph
- Builds a graph of routes, models, components, middleware, and their relationships
- Edges: `calls`, `reads`, `writes`, `protects`, `validates`
- Simple keyword query engine: "unprotected routes", "routes writing to users"
- Saved to `.backend-doctor/api-graph.json`
- New MCP tool: `query_api`

#### Cross-Project Pattern Learning
- Anonymous local pattern tracking (opt-in, never sent externally)
- Tracks issue patterns across projects in `~/.backend-max/patterns.json`
- Provides insights: "This is the #1 most common issue in Next.js projects"
- New MCP tool: `get_patterns`

### Changed
- Route scanner now uses framework plugin architecture (auto-detects framework)
- Doc generator enriched with API graph data (shows "Called by" and "Writes to")
- Orchestrator integrates all new audit engines
- Package now exposes two binaries: `backend-max` (MCP) and `backend-max-cli` (CI/CD)

## [1.1.0] — 2026-03-27

### Added
- **Safety Module** — Complete security subsystem protecting all operations
  - Path Guardian: validates project paths, blocks sensitive directories, prevents path traversal
  - Output Sanitizer: detects and redacts 15+ secret patterns (AWS, GitHub, Stripe, JWT, connection strings, etc.)
  - Scope Limiter: enforces file count, size, and depth limits to prevent resource exhaustion
  - Auto-Gitignore: automatically protects `.backend-doctor/` from git commits
  - Report Pruning: auto-deletes old diagnosis reports based on retention policy
- New MCP tool: `run_safety_check` — validate project safety before diagnosis
- Environment variable values are now stripped at read time — only names are processed

### Changed
- Orchestrator now runs safety checks before every diagnosis
- Env scanner uses sanitized content — values never touch memory
- All reports are sanitized through the Output Sanitizer before disk write

### Security
- 15+ secret pattern detectors (AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, connection strings, Slack tokens, SendGrid keys, Twilio keys, and more)
- Path traversal prevention with symlink resolution
- Blocked sensitive directories: .ssh, .aws, .gnupg, .kube, system paths
- Write operations sandboxed to source files within project boundary

## [1.0.0] — 2026-03-27

### Added

- **MCP Server** — stdio transport for local Claude Code integration
- **Project Understanding** — intent-aware analysis that identifies domains, architecture, and purpose
- **Cross-Boundary Contract Verification** — detects URL, method, payload, and response mismatches between frontend and backend
- **6 Audit Engines:**
  - API Contract Drift detection
  - Error Handling analysis (try/catch coverage, consistent error formats)
  - Input Validation checking (Zod schema coverage, raw body access)
  - Environment Variable verification (missing vars, prefix misuse, undefined refs)
  - Security scanning (auth gaps, CORS config, injection patterns)
  - Performance analysis (N+1 queries, unbounded queries, payload bloat)
- **Living API Documentation** — auto-generated from route handlers, always current
- **Health Score** — composite 0–100 score with per-category breakdowns
- **Issue Lifecycle Tracking** — full ledger from discovery through fix and verification
- **`/doctor` Slash Command** — single command to run the full diagnostic pipeline
- **Next.js App Router Support** — first-class support for Next.js 13+ App Router projects
- **`.backend-doctor/` Output Directory** — structured output with history, docs, and issue tracking

[1.0.0]: https://github.com/rishi-kolisetty/backend-max/releases/tag/v1.0.0
