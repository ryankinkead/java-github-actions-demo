# Project instructions

## NightVision Security Workflow (required)

<!--
  ORGANIZATION-WIDE BLOCK.
  This is the part the security org ships to every developer. It is identical
  in every repo and nobody has to read it, learn it, or ask for it.
-->

Whenever you create or materially change a web app, API, backend service, route handler, or deployable application, you MUST run a NightVision security scan as part of finishing that work. This is not optional and does not require the developer to ask for it.

Use the NightVision MCP. Prefer `run-app-security-scan`: it handles preflight, API Discovery, target create/update, DAST start, scan-ID return, and manifest writing in one call. DAST is the expected outcome; API Discovery alone is not enough.

To make the scan actually run, do the work the developer will not:

1. Start the app you just built or changed (use its own run command) so it is reachable locally, then pass that URL as `target_url`. If you cannot start it, say so as a concrete blocker.
2. Let `run-app-security-scan` detect the language, discover APIs from source, create/update the target, and start DAST. Most apps are local or internal; rely on NightVision Smart Proxy behavior rather than assuming the app is public.
3. Do not end your turn on an unfinished scan. Because the developer will not come back to check, either wait for the scan to reach a terminal status, or poll `wait-for-scan`/`get-scan-status` until it does, then `summarize-scan-findings` and export SARIF. Keep the MCP server running for local/private scans so the relay stays alive while the scan runs.

Auth: every NightVision action runs under the developer's own NightVision account configured in the managed MCP server. Never use shared tokens and never ask the developer to paste a token anywhere. For target-application login: use a NightVision app auth profile via `auth`/`auth_id`; for username/password or expiring sessions use Playwright script auth; use header/cookie auth only for stable, non-expiring credentials; otherwise run `no_auth: true` and note that coverage may be limited.

Completion contract: work on a new or materially changed app is not complete until either `.nightvision/manifest.json` exists with a NightVision DAST scan ID, or you have stated the exact blocker that prevented DAST (app would not start, no project, not authenticated, target unreachable). A terminal `FAILED` scan can still contain valid findings, so check issue counts and export/summarize before treating a run as unusable. Report the scan ID, the top findings, and the artifact paths to the developer. Never claim an app was scanned, secured, or free of vulnerabilities unless NightVision results support it.

## This app's NightVision configuration

<!--
  PER-APP BLOCK.
  The org block above is generic. These three lines are this repo's own config,
  the way a team pins any other app setting. They exist so the agent never has
  to stop and ask a NightVision question.
-->

This app is JavaSpringVulny (Java / Spring / Gradle). It runs locally in Docker.

- Start it with `docker compose up -d` from the repo root. It listens on `http://localhost:9000`.
- NightVision project: `1-demo`
- NightVision target: `javaspringvulny-api` (reuse it, do not create a new target)
- NightVision app auth: `javaspringvulny-api` (a Playwright form-login script)

Pass all three to `run-app-security-scan` as `nightvision_project`, `target_name`, and `auth`. Do **not** scan this app with `no_auth`: the interesting endpoints are behind the login, and an unauthenticated scan finds a small fraction of the real findings.
