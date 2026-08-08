# CLI ↔ REST parity checklist

Every command registered in `cli/main.py` is listed here exactly once, mapped
either to a REST endpoint or to a documented reason for staying CLI-only.
"CLI-only by design" is a decision recorded here, not a gap left implicit.

The **Console page** column is a third, separate question: an endpoint can exist
and still have no UI. Everything left blank there is listed under
[Deliberately CLI-only in the console](#deliberately-cli-only-in-the-console).

Verify the REST column with:

```bash
python3 -c "
from config_assessment.api.app import create_app
spec = create_app(':memory:').openapi()
for p in sorted(spec['paths']):
    for m in sorted(spec['paths'][p]): print(m.upper().ljust(6), p)"
```

## Runtime

| CLI | REST | Console page | Notes |
|---|---|---|---|
| `scan` | `POST /scans`, `POST /scans/upload` | Assessment | Upload accepts a browser file; `POST /scans` keeps the server-path form for CI parity. |
| `scan --report/-f/-o` | `POST /scans/{id}/report` | Assessment | Report is generated from a stored scan rather than inline. |
| `scan --threshold` | `ScanRequest.threshold` → `passed_threshold` | Assessment | A CI gate can't be an HTTP status without conflating it with "the request failed", so the verdict is data. |
| `watch` | `POST /watch`, `GET /watch`, `GET /watch/{id}` | Watch | Both paths run the same `core/watch_loop.run_watch_tick`. |
| *(no CLI equivalent)* | `POST /watch/{id}/pause`, `/resume`, `/stop` | Watch | **REST is wider than the CLI here.** The CLI loop is stopped only by Ctrl-C; lifecycle control is new capability, and only works for sessions this server process owns (409 otherwise). |
| `publish` | — | — | **CLI-only by design.** Pushes a local result file to a *third-party* platform URL. The server has no business making outbound authenticated calls on a browser user's behalf. |

## Build-time

| CLI | REST | Console page | Notes |
|---|---|---|---|
| `build` | `POST /builds`, `GET /builds` | Build | Job-backed — measured at ~1h46min, far past any request timeout. |
| `plugin add` / `plugin fetch` | `POST /plugins/install`, `GET /plugins` | Plugins | Job-backed for the same reason. A bare service name is fetched first, mirroring `plugin fetch --then-install`. |
| `plugin manual` | `POST /plugins/manual` | — | The *retroactive* RAG-ingest path for an already-installed plugin. Job-backed: the manual may be a URL, and ingestion embeds the whole document. |
| `fetch-exploits` | `POST /maintenance/fetch-exploits` | — | Job-backed (network-bound over many CVEs). No page yet; drive it via `GET /jobs`. |
| `refresh` | `POST /maintenance/refresh` | — | Job-backed. `nvd_key` is accepted per-request and **never** written to `params_json`, which `GET /jobs` serves back. |

## Reporting

| CLI | REST | Console page | Notes |
|---|---|---|---|
| `targets` | `GET /targets` | Knowledge Base | |
| `report` | `POST /scans/{id}/report` | Reports | |
| `diff` | `POST /scans/{id}/diff/{other}` | Assessment → Compare | |
| `history` | `GET /scans` | Assessment → History | Filterable; same rows the CLI prints. |
| `trend` | `GET /trends` | Dashboard | |
| `explain` | `GET /knowledge/targets/{target}/rules/{rule_id}` | Knowledge Base | **No dedicated endpoint on purpose** — the knowledge router already returns the same `Misconfiguration` the CLI renders. A second contract for identical data is the duplication this phase exists to avoid. |
| `badge` | `GET /scans/{id}/badge` | — | The CLI reads a scan JSON off disk; over REST a scan is already addressable by id, so this takes the id. |

## State management

| CLI | REST | Console page | Notes |
|---|---|---|---|
| `doctor` | `GET /doctor` | Settings | Always 200 when the check *ran*. The CLI's `exit 1` has no honest HTTP equivalent — a non-200 would mean "the check failed to run", so counts carry the verdict. |
| `suppress` | `GET`/`POST`/`DELETE /suppressions` | Settings → Accepted risks | **Deliberately narrower:** `suppress_file` is required. The CLI defaults to `.caspar-suppress.json` relative to the process cwd, which for a long-running server means "wherever it was launched" — not something a browser user can reason about. The console asks for the path once and remembers it in browser preferences. `reason` is mandatory in both. |
| `fix` | `POST /fix/preview` | Assessment → Remediate | **Deliberately narrower: preview only.** `caspar fix --in-place` overwrites a real config file with no backup, and this API's auth is a no-op unless `CASPAR_API_KEY` is set. Exposing a remote file-write is a separate security decision, not an implementation detail of parity. The console renders the diff and prints the exact `caspar fix` command to run, so applying stays a deliberate act on the server. |
| `promote` | `POST /promote`, `GET /promote/stats` | Settings (stats) | Job-backed: promotion runs the LLM over every uncovered directive. |

## Serving

| CLI | REST | Notes |
|---|---|---|
| `serve` | — | **CLI-only by necessity.** It is the process that hosts the API; it cannot be one of its own endpoints. |

## Deliberately CLI-only in the console

These have working REST endpoints and are reachable from any HTTP client — they
simply have no page in the console. The console covers the day-to-day loop
(assess → review → remediate → accept risk); the operations below are
administrative or one-off, and the CLI is the better place for them. Recorded
here as a decision, not a backlog.

| Capability | Endpoint | Why not in the console |
|---|---|---|
| `promote` (trigger) | `POST /promote` | Administrative: it rewrites the knowledge base with LLM output. The *result* is visible in Settings → Learning loop; starting a run is a deliberate operator act. |
| `fetch-exploits`, `refresh` | `POST /maintenance/*` | Maintenance jobs, typically scheduled rather than hand-run. `refresh` also takes an NVD API key, which is better supplied by a shell than a browser form. |
| `plugin manual` | `POST /plugins/manual` | Retroactive RAG ingest for an already-installed plugin — a rare, per-plugin curation step. |
| `badge` | `GET /scans/{id}/badge` | Produces a Markdown snippet to paste into someone else's README; a copy button is a convenience, not a workflow. |
| Host registry detail | `GET /hosts/registry/{host_id}` | Fleet inventory detail. The Dashboard already aggregates what the console needs from it. |

Anything here can be added later without a REST change — the endpoints exist and
are covered by tests.

## Summary

- 21 leaf commands: 18 top-level (`plugin` is a group) + `plugin add` / `fetch` / `manual`.
- 19 have REST equivalents.
- 2 are CLI-only by design: `publish` (outbound third-party integration) and `serve` (hosts the API itself). `fix` is a third partial case — its read path *is* exposed while its write path is not.
- 2 endpoints are deliberately narrower than their CLI counterpart (`fix`, `suppress`); both narrowings are security-driven and asserted by tests in `tests/test_api_manage.py`.
- 3 lifecycle endpoints are deliberately *wider* (`watch` pause/resume/stop).
- 5 capabilities are REST-exposed but intentionally absent from the console, listed above.
