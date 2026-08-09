# CVM Console (frontend)

React + TypeScript management console for CASPAR / CVM (Configuration
Vulnerability Meter). Consumes the existing `/api/v1` REST API — no business
logic lives here, only presentation and API calls.

This is a separate surface from `config_assessment/dashboard/` (the
server-rendered Jinja2+htmx dashboard), which stays running unchanged at
`/dashboard`. Both share the same backend and the same `caspar serve` process.

## Develop

```bash
npm install
npm run dev
```

Runs on `http://127.0.0.1:5173` and proxies `/api/*` to `http://127.0.0.1:8000`
(the backend, started separately via `caspar serve`). Start the backend first.

## Build

```bash
npm run build
```

Produces `dist/`, which `caspar serve` mounts at `/app` (`_mount_frontend` in
`cli/commands/serve_cmds.py`).

**`dist/` is committed to the repository**, so neither supported installation
needs Node: a native install serves the versioned bundle straight from the
clone, and Docker builds its own copy in a Node stage. The consequence is that
**editing `src/` obliges you to rebuild and commit `dist/`** — otherwise the
console users get silently lags behind the source.

Sourcemaps are off (`vite.config.ts`) because they were 2.9 MB of a 3.6 MB
build and only help someone editing this source, who can get them back with
`npm run build -- --sourcemap`. Without them the committed bundle is 752 kB.

The mount still soft-fails when `dist/` is absent — a cleaned source tree —
and `serve` reports that on startup rather than printing a URL that 404s.

Output is split into vendor chunks (`charts`, `react`, `query`) so the app
bundle stays ~83 kB and a code change doesn't invalidate the 410 kB Recharts
chunk in users' browsers.

## Test

```bash
npm test              # vitest run
npm run test:watch
npm run test:coverage
```

Vitest + Testing Library, jsdom environment. Coverage is deliberately narrow:
the tests target logic where a regression would be silent — the watch
state-resolution rules (`stateOf`, where a paused-but-beating session was a
real bug once) and preference persistence (corrupt/partial stored state).
Markup that a typecheck already covers is not tested.

## Docker

`docker/caspar/Dockerfile` builds the console in a Node stage and copies
`dist/` into the runtime image, so `/app` works from the container with no
local `npm run build`. Building from source in-image (rather than copying a
local `dist/`) is why `.dockerignore` excludes `frontend/dist` — a stale
developer build can never be baked in. `Dockerfile.slim` is untouched and
deliberately excludes the API, dashboard, and console entirely.

## Stack

- Vite + React 18 + TypeScript
- React Router v6 (client-side routing, `basename="/app"`)
- TanStack Query (all data fetching; `refetchInterval` is the mechanism
  later phases use for job/watch polling)
- CSS Modules + a hand-written token system (`src/styles/tokens.css`) —
  deliberately not Tailwind/MUI, to avoid a generic-admin-template look
- Recharts (score gauge), lucide-react (icons)

## Status

All eight pages are real and API-backed:

| Page | What it does |
|---|---|
| Dashboard | Current score, findings, attack chains, recent assessments |
| Assessment | Run a scan (upload / server path / live service), history, compare, export |
| Knowledge Base | Browse benchmarks, rules, and attack chains |
| Plugins | Installed + fetchable catalog; install runs as a background job |
| Build | Benchmark builds with a live log console |
| Watch | Start a session, live score chart, pause / resume / stop |
| Reports | Generate and download reports from stored scans |
| Settings | Theme, assessment defaults, effective server config, `doctor`, learning-loop stats |

CLI↔REST coverage is tracked in [PARITY.md](./PARITY.md) — every CLI command
is mapped to an endpoint or to a recorded reason for staying CLI-only.

## Things worth knowing

**Long-running work is job-backed, never a blocking request.** Builds (measured
at ~1h46min), plugin installs, `promote`, `refresh`, and `fetch-exploits` return
`202` + a `job_id`; the UI polls `/api/v1/jobs/{id}` and tails logs by sequence
number. Progress indicators are indeterminate on purpose — the underlying work
can't report a true completion fraction, and a fake percentage would be a lie.

**`caspar serve --reload` kills jobs and watch sessions.** Uvicorn's reloader
re-execs the process on file changes, and no thread survives that. This is a
constraint of `--reload` itself, not something the frontend can engineer
around. Use plain `caspar serve` when testing anything long-running.

**Watch lifecycle control only works for sessions this server started.** A
session started by `caspar watch` in a terminal, or one from before a server
restart, is still *visible* (liveness is derived from its heartbeat) but cannot
be paused or stopped from the console — the API answers `409` and the page
disables the controls with an explanation rather than pretending.

**Two endpoints are deliberately narrower than the CLI.** `fix` is preview-only
(the CLI's `--in-place` overwrites a live config with no backup), and
suppression files must be named explicitly (the CLI's cwd-relative default is
meaningless for a long-running server). Both are asserted by tests, not just
documented.

**Settings are read-only where they touch the server.** Theme and assessment
defaults are browser-local; database and directory paths are displayed but not
editable. Making server config writable over HTTP is a separate,
security-relevant decision. `GET /settings` reports *whether* an API key is
enforced, never its value.
