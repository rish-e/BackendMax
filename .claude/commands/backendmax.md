---
description: Run Backend Max — AI-powered backend diagnostics. Deep-dive analysis of routes, contracts, security, performance, middleware, and more.
argument-hint: <request>
---

# Backend Max — Deep Backend Diagnosis

You have access to the **Backend Max** MCP server, which provides 27 tools for backend analysis. The user's request is:

> $ARGUMENTS

## How to Handle the Request

Based on what the user asked, determine the right approach:

### If the request is a **full diagnosis** (e.g., "run a full diagnosis", "check my backend", "what's wrong with my project"):
1. Call `mcp__backend-max__init_context` with the project path to understand the project
2. Call `mcp__backend-max__run_diagnosis` with `focus: "all"` to run every audit
3. Present the results clearly:
   - Health score with visual indicator
   - Critical issues first (these need immediate attention)
   - Warnings grouped by category
   - Info items as suggestions
4. For each critical/warning issue, explain **why it matters** and suggest the fix

### If the request is about **specific areas**, use the targeted tools:
- **Routes/endpoints** → `mcp__backend-max__scan_routes`
- **Frontend↔backend contracts** → `mcp__backend-max__check_contracts`
- **Error handling** → `mcp__backend-max__audit_errors`
- **Environment variables** → `mcp__backend-max__audit_env`
- **Security** → `mcp__backend-max__audit_security`
- **Performance** → `mcp__backend-max__audit_performance`
- **Prisma/database** → `mcp__backend-max__audit_prisma`
- **Server actions** → `mcp__backend-max__audit_server_actions`
- **Dependencies/vulnerabilities** → `mcp__backend-max__scan_dependencies`
- **Rate limiting & caching** → `mcp__backend-max__audit_rate_limiting`
- **API versioning** → `mcp__backend-max__audit_versioning`
- **Middleware chains** → `mcp__backend-max__visualize_middleware`
- **Type tracing (frontend→DB)** → `mcp__backend-max__trace_types`
- **API documentation** → `mcp__backend-max__get_api_docs`
- **Issue history** → `mcp__backend-max__get_ledger`
- **Fix an issue** → `mcp__backend-max__fix_issue`
- **Fix all issues** → `mcp__backend-max__fix_all_issues`
- **What changed since last run** → `mcp__backend-max__check_changes`
- **Incremental analysis** → `mcp__backend-max__watch_diagnosis`

### If the request is to **fix issues**:
1. Run diagnosis first if no recent results exist
2. Use `mcp__backend-max__fix_issue` or `mcp__backend-max__fix_all_issues`
3. Show the generated patches and explain each fix
4. Ask if the user wants you to apply them

## Project Path Detection

Determine the project path automatically:
1. Use the current working directory if it looks like a project (has `package.json`)
2. If the user mentions a specific path, use that
3. If unclear, ask the user which project to analyze

## Response Format

Always structure your response as:

**Project:** {name} ({framework detected})
**Health Score:** {score}/100 {emoji based on score: 90+→ 80+→ 60+→ <60→}

Then present findings grouped by severity, with actionable explanations. Be specific — mention exact files, line numbers, and what to change.

If the health score is below 70, emphasize the critical items and offer to generate fixes.
