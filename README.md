<div align="center">

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗  █████╗  ██████╗██╗  ██╗███████╗███╗   ██╗██████╗ ║
║   ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝████╗  ██║██╔══██╗║
║   ██████╔╝███████║██║     █████╔╝ █████╗  ██╔██╗ ██║██║  ██║║
║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██║╚██╗██║██║  ██║║
║   ██████╔╝██║  ██║╚██████╗██║  ██╗███████╗██║ ╚████║██████╔╝║
║   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═════╝║
║                                                              ║
║           ███╗   ███╗ █████╗ ██╗  ██╗                        ║
║           ████╗ ████║██╔══██╗╚██╗██╔╝                        ║
║           ██╔████╔██║███████║ ╚███╔╝                         ║
║           ██║╚██╔╝██║██╔══██║ ██╔██╗                         ║
║           ██║ ╚═╝ ██║██║  ██║██╔╝ ██╗                        ║
║           ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

### 🩺 AI-Powered Backend Diagnostics for Claude Code

**The backend bugs your linter can't see. The contract drift your tests don't cover. Caught before deploy.**

<br />

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1.0-brightgreen.svg?style=for-the-badge)]()
[![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-339933.svg?style=for-the-badge&logo=node.js&logoColor=white)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6.svg?style=for-the-badge&logo=typescript&logoColor=white)]()
[![MCP](https://img.shields.io/badge/MCP-compatible-8B5CF6.svg?style=for-the-badge)]()

<br />

[Quick Start](#-quick-start) · [Features](#-features-deep-dive) · [Tools](#-available-tools) · [Roadmap](#-roadmap)

</div>

<!-- ═══════════════════════════════════════════════════════════ -->

<br />

## 🤔 What Is This?

**Backend Max** is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that gives Claude deep diagnostic vision into your backend. It statically analyzes your codebase — both frontend *and* backend — to surface bugs, contract drift, missing validation, security gaps, and performance anti-patterns that no other single tool catches.

Think of it as a **senior backend engineer** that reviews every route, checks every contract, and never goes on vacation.

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## 🔭 How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   📂 Your Codebase          🩺 Backend Max           📋 Report     │
│                                                                     │
│   ┌───────────┐             ┌──────────────┐        ┌───────────┐  │
│   │ Frontend   │────────▶   │  Cross-       │        │ Health    │  │
│   │ API Calls  │            │  Boundary     │──────▶ │ Score     │  │
│   └───────────┘             │  Analysis     │        ├───────────┤  │
│                             │              │        │ Issues    │  │
│   ┌───────────┐             │  ┌──────────┐ │        ├───────────┤  │
│   │ Backend   │────────▶   │  │ 6 Audit  │ │──────▶ │ API Docs  │  │
│   │ Routes    │            │  │ Engines  │ │        ├───────────┤  │
│   └───────────┘             │  └──────────┘ │        │ Fixes     │  │
│                             │              │        │ Guide     │  │
│   ┌───────────┐             │  ┌──────────┐ │        └───────────┘  │
│   │ Config    │────────▶   │  │ Intent   │ │                       │
│   │ & Env     │            │  │ Engine   │ │                       │
│   └───────────┘             │  └──────────┘ │                       │
│                             └──────────────┘                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## ⚡ Why Backend Max?

Existing tools catch syntax errors and type mismatches. **Backend Max catches the bugs that ship to production.**

| Bug Category | TypeScript | ESLint | Jest/Vitest | **Backend Max** |
|:---|:---:|:---:|:---:|:---:|
| Frontend calls `/api/user` but backend exposes `/api/users` | ❌ | ❌ | ❌ | ✅ |
| Frontend sends `{ name }` but backend expects `{ username }` | ❌ | ❌ | ❌ | ✅ |
| Route handler missing try/catch | ❌ | ❌ | ❌ | ✅ |
| Zod schema missing on POST route | ❌ | ❌ | ❌ | ✅ |
| `process.env.SECRET` used but not in `.env` | ❌ | ❌ | ❌ | ✅ |
| Auth middleware missing on sensitive route | ❌ | ❌ | ❌ | ✅ |
| N+1 query in a loop | ❌ | ❌ | ❌ | ✅ |
| API docs out of date | ❌ | ❌ | ❌ | ✅ |

> 💡 **Backend Max doesn't replace your existing tools.** It catches what they architecturally *cannot* — cross-boundary issues that require understanding both sides of the stack.

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## 🚀 Quick Start

### 1. Install

```bash
git clone https://github.com/rish-e/backend-max.git
cd backend-max
npm install
npm run build
```

### 2. Configure with Claude Code

Add to your Claude Code MCP settings (`.claude/settings.json` or project-level):

```jsonc
{
  "mcpServers": {
    "backend-max": {
      "command": "node",
      "args": ["/path/to/backend-max/dist/index.js"],
      "transport": "stdio"
    }
  }
}
```

### 3. Run Your First Diagnosis

Open Claude Code in any project and type:

```
/doctor
```

That's it. Backend Max will analyze your project and return a full diagnostic report with health score, issues, and fix suggestions.

### 4. CI/CD Mode (Optional)

Run diagnostics from the command line or GitHub Actions:

```bash
# Basic diagnosis
npx backend-max-cli diagnose ./my-project

# CI mode — fail if health score drops below 75 or critical issues found
npx backend-max-cli diagnose ./my-project --ci --min-score 75 --fail-on critical

# Output formats
npx backend-max-cli diagnose ./my-project --format markdown  # PR comments
npx backend-max-cli diagnose ./my-project --format sarif     # GitHub Code Scanning
npx backend-max-cli diagnose ./my-project --format json      # Raw data
```

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## 🔬 Features Deep Dive

### 🆕 v2.1 — Tier 1 Feature Drop

| Feature | Description |
|---------|-------------|
| **🔧 Auto-Fix Engine** | Generates real unified diff patches for common issues — try/catch wrapping, Zod validation, auth guards, pagination. Apply with `git apply` |
| **👁️ Watch Mode** | Incremental analysis — shows new issues, fixed issues, and health score delta since last run. No full re-scan needed |
| **🔀 tRPC Support** | Full router analysis — procedures, input validation, protected/public, queries vs mutations. 3 tRPC-specific checks |
| **🕸️ GraphQL Analysis** | Resolver scanning for Apollo, Yoga, Mercurius, type-graphql, NestJS. N+1 detection, auth checks, input validation |
| **📦 Dependency Scanner** | Built-in vulnerability database (12+ packages), deprecated package detection, lock file checks, npm audit integration |

### v2.0 Features

| Feature | Description |
|---------|-------------|
| **🗄️ Prisma Schema Integration** | Parses your `.prisma` schema and cross-references every database call — catches nonexistent models, fields, and missing indexes |
| **🔍 Deep Type Flow Analysis** | Traces frontend response variables to check property access against backend return types — catches `data.user.firstName` vs `data.user.first_name` |
| **⚡ Server Actions** | Full audit of Next.js Server Actions (`'use server'`) — validation, auth, error handling, database patterns |
| **🚀 CI/CD Mode** | CLI entry point with `--ci`, `--min-score`, `--fail-on`, and 4 output formats (text, markdown, JSON, SARIF) |
| **🟢 Express.js Support** | Route scanning, middleware detection, Express-specific checks (error middleware, 404, helmet/CORS) |
| **📄 Pages Router** | Next.js Pages Router API routes (`pages/api/`) fully supported |
| **🧪 Live Testing** | Optional HTTP endpoint testing against running dev server (GET-only, safety-first) |
| **🕸️ API Graph** | Queryable relationship graph — ask "unprotected routes" or "routes writing to users" |
| **📊 Pattern Learning** | Local cross-project pattern tracking — identifies the most common issues across your projects |
| **📋 SARIF Output** | GitHub Code Scanning integration via SARIF format |

<br />

### 🔗 Cross-Boundary Contract Verification

> **The #1 feature.** No other tool does this.

Backend Max reads your frontend fetch/axios calls *and* your backend route handlers, then cross-references them to find:

- **URL mismatches** — frontend calls `/api/user`, backend serves `/api/users`
- **Method mismatches** — frontend sends `POST`, backend expects `PUT`
- **Payload drift** — frontend sends `{ name, email }`, backend expects `{ username, email }`
- **Response shape drift** — frontend destructures `data.items`, backend returns `data.results`

```typescript
// Frontend: lib/api.ts
const user = await fetch('/api/user', {    // ← "/user" (singular)
  method: 'POST',
  body: JSON.stringify({ name: 'Alice' })  // ← sends "name"
});

// Backend: app/api/users/route.ts          // ← "/users" (plural)
export async function POST(req: Request) {
  const { username } = await req.json();    // ← expects "username"
  // ...
}
```

```
⚠️  CONTRACT DRIFT DETECTED

   Route Mismatch:
   Frontend calls  →  /api/user   (POST)
   Backend serves  →  /api/users  (POST)

   Payload Mismatch:
   Frontend sends  →  { name: string }
   Backend expects →  { username: string }
```

---

### 🧠 Intent-Aware Diagnosis

Backend Max doesn't just scan code — it **understands what you're building**. By analyzing your project structure, route names, and data models, it builds an intent map:

- Identifies your **domains** (auth, billing, users, etc.)
- Understands **relationships** between entities
- Flags issues that are contextually wrong, not just syntactically wrong

> 🎯 *"This route handles payments but doesn't validate the amount field"* is more useful than *"missing validation on line 47"*.

---

### 🛡️ Pre-Deploy Safety Net

Six audit engines run in parallel, each targeting a category of bugs that commonly ship to production:

| # | Audit Engine | What It Catches |
|---|---|---|
| 1 | 🔗 **API Contract Drift** | Frontend↔backend URL, method, payload, and response mismatches |
| 2 | 🚨 **Error Handling** | Missing try/catch, inconsistent error response formats, unhandled promise rejections |
| 3 | ✅ **Input Validation** | Routes without Zod schemas, raw `req.body` access, missing type coercion |
| 4 | 🔑 **Environment Variables** | Undefined refs, missing `.env` entries, `NEXT_PUBLIC_` prefix misuse |
| 5 | 🔒 **Security** | Auth middleware gaps, permissive CORS, SQL/NoSQL injection patterns, exposed secrets |
| 6 | ⚡ **Performance** | N+1 queries, unbounded `SELECT *`, large payload serialization, missing pagination |

Each issue includes:
- **Severity** — `critical` · `warning` · `info`
- **Location** — exact file and line number
- **Explanation** — what's wrong and *why* it matters
- **Fix suggestion** — actionable code-level guidance

---

### 📖 Living API Documentation

Backend Max auto-generates API documentation by reading your actual route handlers. No annotations needed. No Swagger decorators. Just your code.

```markdown
## POST /api/auth/login

Authentication endpoint for user login.

**Request Body:**
| Field    | Type   | Required | Validation       |
|----------|--------|----------|------------------|
| email    | string | ✅       | Valid email      |
| password | string | ✅       | Min 8 characters |

**Response (200):**
| Field | Type   |
|-------|--------|
| token | string |
| user  | object |

**Error Responses:** 401, 422, 500
```

The docs update every time you run a diagnosis. **They can never go stale.**

---

### 📒 Issue Lifecycle Tracking

Every issue is tracked through its full lifecycle:

```
Found → Acknowledged → Fixed → Verified → (Regressed?)
```

Backend Max maintains a **ledger** in `.backend-doctor/history/` so you can:

- See what was fixed and when
- Detect regressions (issues that come back)
- Track your backend health score over time
- Review historical audit reports

---

### 💯 Health Score

A single number, **0–100**, representing your backend's overall health:

```
╔══════════════════════════════════════╗
║  Backend Health Score: 73/100  📊   ║
╠══════════════════════════════════════╣
║  Contracts    ████████░░  80%       ║
║  Error Handling ██████░░░░  60%     ║
║  Validation   ███████░░░  70%       ║
║  Env Vars     █████████░  90%       ║
║  Security     ██████░░░░  60%       ║
║  Performance  ████████░░  80%       ║
╚══════════════════════════════════════╝
```

Track it over time to see your backend getting healthier with every commit.

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## 🛠️ Available Tools

All tools are exposed via MCP and available directly in Claude Code:

| Tool | Description |
|:---|:---|
| `run_diagnosis` | Full diagnostic pipeline — scans routes, checks contracts, runs all audits, generates docs, calculates health score |
| `watch_diagnosis` | Incremental analysis — compares against last report, shows new/fixed issues and health delta |
| `check_changes` | Quick check — shows changed files since last diagnosis without re-running analysis |
| `init_context` | Analyze project structure, identify domains, frameworks, and architecture |
| `check_contracts` | Cross-reference frontend API calls against backend routes |
| `scan_routes` | Discover all API routes/endpoints across all supported frameworks |
| `audit_errors` | Check error handling — try/catch coverage, consistent error formats |
| `audit_env` | Verify environment variables — missing refs, prefix misuse |
| `audit_security` | Security scan — auth gaps, CORS, injection patterns |
| `audit_performance` | Performance anti-patterns — N+1 queries, unbounded queries, missing pagination |
| `audit_prisma` | Prisma schema cross-referencing — nonexistent models/fields, missing indexes |
| `audit_server_actions` | Next.js Server Actions audit — validation, auth, error handling |
| `scan_dependencies` | Dependency vulnerability scanner — known CVEs, deprecated packages, lock file checks |
| `fix_issue` | Generate a unified diff patch for a specific issue |
| `fix_all_issues` | Batch-generate patches for all open issues |
| `get_api_docs` | Auto-generated living API documentation |
| `get_ledger` | Full issue lifecycle ledger — filter by status, severity, category |
| `live_test` | Optional HTTP endpoint testing (GET-only, localhost-only, safety-first) |
| `query_api` | Query the API relationship graph — "unprotected routes", "routes writing to users" |
| `get_patterns` | Cross-project pattern insights — most common issues by framework |
| `run_safety_check` | Validate project safety constraints before diagnosis |

### Tool Usage Examples

```typescript
// In Claude Code, these are called automatically.
// Direct MCP usage:

// Full diagnosis (the /doctor command runs this)
await client.callTool('diagnose', { projectPath: '.' });

// Just check contracts
await client.callTool('verify_contracts', { projectPath: '.' });

// Generate fresh API docs
await client.callTool('generate_docs', { projectPath: '.', outputFormat: 'markdown' });
```

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## 🩺 The `/doctor` Command

The simplest way to use Backend Max. Just type `/doctor` in Claude Code.

### What it does:

1. 🧠 Scans your project to understand its intent and architecture
2. 🔗 Verifies all frontend↔backend contracts
3. 🔍 Runs all 6 audit engines
4. 📖 Generates/updates API documentation
5. 💯 Calculates your health score
6. 📋 Returns a prioritized report

### Example Output

```
🩺 Backend Max Diagnosis Complete
═══════════════════════════════════

📊 Health Score: 73/100 (↑ 5 from last run)

🚨 Critical Issues (2)
  ├─ AUTH_GAP: /api/billing/charge has no auth middleware
  │  → app/api/billing/charge/route.ts:1
  │
  └─ CONTRACT_DRIFT: Frontend calls DELETE /api/user/:id
     but backend only exposes GET, POST on /api/users
     → lib/api/users.ts:45 ↔ app/api/users/route.ts

⚠️  Warnings (5)
  ├─ VALIDATION: POST /api/posts missing input validation
  ├─ ERROR_FORMAT: 3 routes return inconsistent error shapes
  ├─ ENV_VAR: DATABASE_URL referenced but not in .env.example
  ├─ PERFORMANCE: N+1 query pattern in /api/users (line 23)
  └─ SECURITY: CORS allows * in production config

ℹ️  Info (3)
  ├─ 2 routes could benefit from response caching
  ├─ API docs regenerated (12 endpoints documented)
  └─ 1 previously fixed issue verified as resolved ✓

📖 API docs updated: .backend-doctor/api-docs.md
📒 Issue ledger updated: .backend-doctor/history/
```

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## 📁 Project Structure

Backend Max creates a `.backend-doctor/` directory in your project root:

```
.backend-doctor/
├── project-intent.json      # Understanding of your project's purpose & domains
├── api-docs.md              # Auto-generated API documentation
├── health-score.json        # Current & historical health scores
├── issues/
│   ├── current.json         # Active issues from latest run
│   └── ledger.json          # Full issue lifecycle history
├── contracts/
│   ├── frontend-calls.json  # Extracted frontend API calls
│   └── backend-routes.json  # Extracted backend route definitions
└── history/
    └── 2026-03-27.json      # Historical audit snapshots
```

> 📌 Add `.backend-doctor/` to your `.gitignore` or commit it — your choice. Committing it gives your team shared visibility into backend health.

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## ⚙️ Configuration

Create a `backend-max.config.json` in your project root to customize behavior:

```jsonc
{
  // Which audit engines to run (default: all)
  "audits": {
    "contracts": true,
    "errorHandling": true,
    "validation": true,
    "envVars": true,
    "security": true,
    "performance": true
  },

  // Paths to scan (globs)
  "include": ["app/api/**", "src/routes/**"],

  // Paths to ignore
  "exclude": ["**/*.test.ts", "**/__mocks__/**"],

  // Frontend paths for contract verification
  "frontendPaths": ["app/**", "components/**", "lib/**"],

  // Minimum severity to report: "info" | "warning" | "critical"
  "minSeverity": "info",

  // Custom environment variable file paths
  "envFiles": [".env", ".env.local", ".env.production"]
}
```

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## 🛡️ Safety & Security

Backend Max is built with a **safety-first philosophy**. Every operation — from file scanning to report generation — passes through multiple safety layers. Your code is never executed, your secrets are never stored, and all output is sanitized before it touches disk. Backend Max is designed so that even in the worst case, it cannot leak sensitive data or damage your project.

### Safety Systems

| System | What It Does | Default |
|--------|-------------|---------|
| **Path Guardian** | Validates project paths, blocks sensitive directories (.ssh, .aws, .gnupg), prevents path traversal attacks | Always on |
| **Output Sanitizer** | Detects and redacts secrets in reports — AWS keys, GitHub tokens, Stripe keys, JWTs, connection strings, private keys, Slack tokens, and 12+ more patterns | Always on |
| **Scope Limiter** | Caps file count (5,000), file size (1MB), scan depth (15 levels). Prevents memory exhaustion on large monorepos | Configurable |
| **Auto-Gitignore** | Automatically adds `.backend-doctor/` to `.gitignore` on first run. Prevents diagnostic data from being committed | On by default |
| **Report Pruning** | Auto-deletes diagnosis reports older than 30 days | Configurable |
| **Env Value Stripping** | Environment variable VALUES are never read or stored — only variable NAMES. Impossible to leak secrets through reports | Always on |
| **Write Protection** | Fix engine validates every write target: must be a source file, must be in project, must not be generated/config/lock files | Always on |

### Security Guarantees

- ✅ Backend Max NEVER reads environment variable values — only names
- ✅ Backend Max NEVER executes your code — pure static analysis
- ✅ Backend Max NEVER sends data externally — everything stays local
- ✅ All diagnostic output is scrubbed for 15+ secret patterns before writing to disk
- ✅ `.backend-doctor/` is auto-gitignored to prevent accidental commits
- ✅ File writes (fix engine) are sandboxed to source files within the project only

### Configuration

Safety limits can be tuned via `backend-max.config.json`:

```json
{
  "maxFiles": 5000,
  "maxFileSizeBytes": 1048576,
  "maxScanDepth": 15,
  "reportRetentionDays": 30,
  "autoGitignore": true
}
```

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## 🗺️ Roadmap

### Phase 1 — Foundation ✅

- [x] MCP server with stdio transport
- [x] Next.js App Router support
- [x] 6 core audit engines
- [x] Cross-boundary contract verification
- [x] Auto-generated API documentation
- [x] Health score calculation
- [x] Issue lifecycle tracking
- [x] `/doctor` slash command

### Phase 2 — Expansion ✅

- [x] Safety & sandboxing
- [x] Express.js support
- [x] CI/CD integration (GitHub Actions via SARIF)
- [x] Watch mode / incremental analysis
- [x] Auto-fix engine with code patches
- [x] tRPC support
- [x] GraphQL resolver analysis
- [x] Dependency vulnerability scanning

### Phase 3 — Intelligence 🚧

- [ ] Fastify + Hono framework support
- [ ] Multi-layer type tracing (frontend → route → service → DB)
- [ ] API versioning analysis
- [ ] Rate limiting & caching audit
- [ ] Middleware chain visualization
- [ ] OpenAPI/Swagger spec generation
- [ ] Dead code detection (unused routes/exports)
- [ ] Test coverage mapping

### Phase 4 — Ecosystem 🔮

- [ ] VS Code extension — inline diagnostics
- [ ] Monorepo support (Turborepo/Nx)
- [ ] Database query complexity analyzer
- [ ] API changelog between commits
- [ ] Webhook/event auditor
- [ ] Multi-service contract verification (microservices)

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick summary:**

1. Fork & clone
2. `npm install && npm run build`
3. Create a feature branch
4. Write your code (TypeScript strict, ESM, JSDoc comments)
5. Open a PR

<br />

<!-- ═══════════════════════════════════════════════════════════ -->

## 📄 License

[MIT](LICENSE) © 2026 Rishi Kolisetty

<br />

---

<div align="center">

**Built with 🩺 by [Rishi Kolisetty](https://github.com/rishi-kolisetty)**

*Backend Max sees what your linter can't.*

<br />

[![Star on GitHub](https://img.shields.io/badge/⭐_Star_on_GitHub-black?style=for-the-badge&logo=github)](https://github.com/rishi-kolisetty/backend-max)

</div>
