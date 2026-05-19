## Autopilot Task Post-Mortem: MCP Directory Publishing

### Task
Publish `backend-max` to 5 MCP directories: Official MCP Registry, Smithery.ai, mcp.so, PulseMCP, Glama.ai.

---

### What Succeeded

| Step | Method | Result |
|------|--------|--------|
| Create `server.json` (Official Registry metadata) | File write | ✅ Done |
| Create `smithery.yaml` (Smithery config) | File write | ✅ Done |
| Update `package.json` (keywords, files) | File edit | ✅ Done |
| Submit to **mcp.so** | GitHub MCP (`add_issue_comment`) | ✅ Done — used MCP tool, no browser needed |
| Commit & push all config to GitHub | Git CLI | ✅ Done |

---

### What Failed and Why

#### Failure 1: Playwright MCP browser lock (affected Glama, Smithery, npm token acquisition)

**What happened:**
1. Autopilot started the persistent Chrome CDP (`chrome-debug.sh start`) for browser-based submissions
2. Called `mcp__playwright__browser_navigate` to go to npmjs.com
3. Got error: `Target page, context or browser has been closed`
4. Called `browser_close` to recover, then retried
5. Got error: `Browser is already in use for .../mcp-chrome-fc1a219`
6. Playwright MCP had a stale lock on its internal Chrome profile directory (`SingletonLock`, `SingletonSocket`, `SingletonCookie`)

**Root cause:** Playwright MCP and `chrome-debug.sh` use different Chrome instances with different profile directories. When the Playwright MCP's Chrome died (from the earlier Glama/Smithery session before the plan was approved), it left lock files behind. Playwright MCP caches the "in use" state in memory, so even after deleting lock files on disk, the MCP process itself still thinks a browser is running.

**Why autopilot couldn't fix it:**
- Guardian blocked `rm` on `~/Library/Caches/` (classified as system directory deletion)
- Guardian blocked `pkill` on the Chrome process (classified as MCP server process termination)
- Even after the user manually cleared locks and terminated the process, Playwright MCP's in-memory state was still stale — would need an MCP server restart, which only the Claude Code harness can do

**Fix needed for autopilot:**
1. **Playwright MCP recovery command**: The Playwright MCP needs an explicit `browser_reset` or `browser_force_close` tool that clears its internal state and lock files without requiring external process management
2. **Guardian exception**: Add a rule that allows deleting `SingletonLock`/`SingletonSocket`/`SingletonCookie` files specifically — these are ephemeral lock files, not user data
3. **Fallback awareness**: When Playwright MCP is in a broken state, autopilot should immediately fall back to CLI/API paths rather than trying multiple recovery attempts
4. **Don't mix Chrome instances**: `chrome-debug.sh` persistent Chrome and Playwright MCP's built-in Chrome conflict. Either use one or the other, never both in the same session. Add this as a rule in autopilot.

#### Failure 2: npm login requires interactive authentication

**What happened:**
1. Checked keychain for npm token — not found
2. Checked `~/.npmrc` — no auth configured
3. Tried to use browser to navigate to npmjs.com to generate a token — blocked by Failure 1
4. Only remaining path: `npm login` CLI — but this is interactive (opens browser for OAuth confirmation, waits for user to click)

**Root cause:** npm's authentication flow is designed to require human-in-the-loop. There's no way to programmatically create an npm account or generate a token without either:
- An existing token (not in keychain)
- Interactive `npm login` (opens browser, user clicks confirm)
- npm automation token (must be created from the npm web dashboard while logged in)

**Why autopilot couldn't fix it:**
- No npm credentials existed anywhere (keychain, .npmrc)
- Browser was broken (Failure 1), so couldn't navigate to npmjs.com to sign up / generate token
- `npm login` is interactive — requires stdin input and browser confirmation
- This is a genuine Level 5 escalation: first-time credential that requires human authentication

**Fix needed for autopilot:**
1. **Pre-flight credential check**: Before presenting the plan, check if all required credentials exist. If npm token is missing, the plan should include "User: run `npm login`" as Step 0 with a clear note that this blocks everything else
2. **npm token acquisition service flow**: Add to the service registry that npm requires interactive login. Document the exact flow: `npm login` → browser opens → user confirms → token saved to `~/.npmrc` → autopilot reads token and stores in keychain for future use
3. **Post-login token capture**: After user completes `npm login`, autopilot should immediately read the token from `~/.npmrc` and store it in keychain so future sessions never hit this again
4. **Dependency ordering in plans**: The plan should have made it clear that Steps 3-6 all depend on Step 2 (npm token), and Step 2 requires human input. Currently the plan presented them as sequential steps without flagging the hard dependency

#### Failure 3: Smithery.ai and Glama.ai require account sign-in

**What happened:**
1. Navigated to Smithery.ai/new — redirected to login page (GitHub OAuth)
2. Navigated to Glama.ai → clicked "Add Server" — sign-up dialog appeared (requires name, email, CAPTCHA)

**Root cause:** Both services require authenticated accounts. Glama has a CAPTCHA (Level 5 — cannot be automated). Smithery uses GitHub OAuth which could theoretically be automated if a GitHub session exists in the browser.

**Why autopilot couldn't fix it:**
- Browser was broken by the time we needed it (Failure 1)
- Glama has CAPTCHA — always requires human
- Smithery's GitHub OAuth popup flow is complex to automate

**Fix needed for autopilot:**
1. **Service registry files**: Create `~/MCPs/autopilot/services/smithery.md` and `~/MCPs/autopilot/services/glama.md` documenting that both require account creation (Level 3) and that Glama has CAPTCHA (Level 5)
2. **GitHub OAuth reuse**: If user is already logged into GitHub in the persistent browser, Smithery OAuth should complete automatically. Document this as the preferred path
3. **Glama CAPTCHA**: Mark as always-human. Plan should say "User: sign up at glama.ai" rather than attempting automation

---

### Cascade Failure Analysis

```
Playwright browser lock (stale from earlier session)
  └→ Can't navigate to npmjs.com to get token
  └→ Can't navigate to Smithery to submit
  └→ Can't navigate to Glama to submit
  └→ Only CLI paths remain
       └→ npm login is interactive → blocked
       └→ No npm token → can't publish
       └→ No npm package → can't submit to Official Registry
       └→ No Registry entry → PulseMCP can't auto-sync
```

**One failure (browser lock) cascaded to block 4 of 5 directories.** The only submission that succeeded (mcp.so) used a GitHub MCP tool — no browser needed.

---

### Recommendations for Autopilot System

1. **Never use `chrome-debug.sh` and Playwright MCP in the same session** — add to autopilot rules
2. **Add Playwright recovery to Guardian whitelist** — allow deleting `SingletonLock`/`SingletonSocket`/`SingletonCookie` in Playwright cache dirs
3. **Pre-flight credential gate** — before presenting a plan, verify ALL required credentials exist and flag any that need human input as Step 0
4. **Service registry for npm, Smithery, Glama** — document auth requirements, CAPTCHA presence, OAuth flows
5. **MCP-first for GitHub operations** — mcp.so succeeded because it used the GitHub MCP. Always prefer MCP/API/CLI over browser
6. **Post-login token harvesting** — after user does `npm login`, immediately read `~/.npmrc`, extract token, store in keychain
7. **Plan dependency graph** — plans should show which steps block others, so if Step 2 needs human input, the user knows Steps 3-6 are all waiting on it
