# Changelog

All notable changes to jabearri are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — Security fix: encoded scope traversal at all depths

### Fixed

- **Encoded scope traversal could widen the scope boundary through multiple
  distinct gaps, all now closed.**

  The original check decoded scope entries a fixed 2 passes before looking for
  `..`. Three gaps existed:

  1. **Triple-and-deeper encoding** (`%25252e%25252e`, mixed-depth variants):
     survived 2 decode passes as a residual `%2e%2e` — no literal `..` — but
     the WHATWG URL spec's dot-segment removal collapses `%2e`/`%2E` natively,
     so `normalizePath()` still widened scope at request time. Fixed by
     replacing the fixed 2-pass decode with `decodeUntilStable()`, which loops
     until the string stops changing (capped at `DECODE_MAX_PASSES` passes for
     DoS safety).

  2. **Cap-boundary residual** (encoding depth exactly `DECODE_MAX_PASSES`):
     `decodeUntilStable()` hit its cap and returned `/%2e%2e/` — still no
     literal `..`, still collapsed to `/` by `new URL().pathname`. Fixed by
     `foldEncodedDots()`, which converts residual `%2e`/`%2E` to `.` after the
     decode loop — mirroring what the URL spec does without an explicit decode
     step — before the `..` check runs.

  Both `verifyScope()` (pre-flight validation) and `normalizePath()` (runtime
  scope matching in `ProxyCore`) now apply the same two-step pipeline:
  `foldEncodedDots(decodeUntilStable(input))`. The two functions are provably
  consistent at every encoding depth, including cap-boundary residuals. Deeper
  residuals (`%252e` and beyond) are not folded — the URL spec does not
  collapse them without an explicit decode pass — and verified not to widen
  scope via URL normalization.

- **875 total tests** (720 in `test/run.js` + 81 in `test/adversarial-harness.js`
  + 74 in `test/deep-adversarial-harness.js`), including regression tests for
  triple/mixed-depth encoding, the exact cap-boundary bypass case, and a
  decode-cap DoS-safety timing check.

## [Unreleased] — Renamed to jabearri

**BREAKING CHANGE:** This project was renamed from `mozorrarri` to `jabearri` as part of the Haritzarri tool family consolidation. All environment variables, config file names, and the consent file have been renamed accordingly:

- `MOZORRARRI_CONFIG` → `JABEARRI_CONFIG`
- `MOZORRARRI_TOKEN_B` → `JABEARRI_TOKEN_B`
- `MOZORRARRI_PROXY_URL` → `JABEARRI_PROXY_URL`
- `MOZORRARRI_MAX_ENTRIES` → `JABEARRI_MAX_ENTRIES`
- `MOZORRARRI_API_KEY_HEADER` → `JABEARRI_API_KEY_HEADER`
- `MOZORRARRI_COOKIE_NAME` → `JABEARRI_COOKIE_NAME`
- `MOZORRARRI_TEST_TARGET` → `JABEARRI_TEST_TARGET`
- `mozorrarri.config.json` → `jabearri.config.json`
- `.mozorrarri_consent` → `.jabearri_consent`

If you have CI pipelines or scripts referencing the old names, update them before upgrading. The GitHub repository was renamed from `mozorrarri` to `jabearri`; the old URL redirects automatically.

Functionality is unchanged. This is a naming-only release.

## [Unreleased] — Renamed to mozorrarri

**BREAKING CHANGE:** This project was renamed from `accguard` to `mozorrarri` as part of the Haritzarri tool family. All environment variables, config file names, and the consent file have been renamed accordingly:

- `ACCGUARD_CONFIG` → `MOZORRARRI_CONFIG`
- `ACCGUARD_TOKEN_B` → `MOZORRARRI_TOKEN_B`
- `ACCGUARD_PROXY_URL` → `MOZORRARRI_PROXY_URL`
- `ACCGUARD_MAX_ENTRIES` → `MOZORRARRI_MAX_ENTRIES`
- `ACCGUARD_API_KEY_HEADER` → `MOZORRARRI_API_KEY_HEADER`
- `ACCGUARD_COOKIE_NAME` → `MOZORRARRI_COOKIE_NAME`
- `ACCGUARD_TEST_TARGET` → `MOZORRARRI_TEST_TARGET`
- `accguard.config.json` → `mozorrarri.config.json`
- `.accguard_consent` → `.mozorrarri_consent`

If you have CI pipelines or scripts referencing the old names, update them before upgrading. The GitHub repository was renamed from `accguard` to `mozorrarri`; the old URL redirects automatically.

Functionality is unchanged. This is a naming-only release.

## [0.10.1] — 2026-06-13

### Added

- **`jabearri run -- <command>` wrapper mode.** jabearri can now wrap your test
  command directly — starts the proxy, injects `HTTP_PROXY` into the child
  process environment, waits for the command to exit, then replays automatically.
  No manual coordination or second terminal required. `JABEARRI_TOKEN_B` is
  explicitly removed from the child environment so Bob's token is never exposed
  to test code, browser drivers, or CI logs.
- **Exit-code disambiguation message.** When the wrapped command exits non-zero
  AND jabearri finds confirmed findings, the terminal prints a clear note
  distinguishing both failure causes and the report path.
- **MongoDB ObjectID extraction.** 24-character hex strings containing at least
  one letter (`a–f`) are now recognized as `objectid` resource IDs. Previously
  these fell through `extractResourceIds` entirely, causing MongoDB-backed API
  endpoints (crAPI vehicles, etc.) to be silently skipped from replay.
- **708 automated tests.**

### Fixed

- Version strings unified across all source files, CLI banner, report metadata,
  and documentation.
- Wrapper `shell: true` replaced with `shell: false` and explicit Windows `.cmd`
  resolution for `npm`/`npx`/`yarn`. Eliminates Node.js DEP0190 deprecation
  warning from wrapper output.

### Validation

- Validated `jabearri run -- <command>` against OWASP Juice Shop.
- Confirmed deterministic cross-user replay findings on `/rest/basket/:id`
  endpoints with reproducible evidence.
- Documented boundary: session-scoped endpoints without URL-level resource IDs
  are observed but not replayed as BOLA candidates.
- Added VAmPI boundary validation: Flask/JWT traffic is captured correctly,
  while plain-word path identifiers (`/users/v1/name1`) are intentionally not
  replayed as BOLA candidates. Zero findings on a clean run — correct behavior,
  honestly reported.

[0.10.1]: https://github.com/rodrigo-areyzaga/jabearri/releases/tag/v0.10.1

## [0.10.0] — 2026-06-11

v0.10.0 adds a privacy-preserving **Exposure Summary** and audit-ready evidence
metadata for confirmed authorization findings. jabearri still does one thing —
prove cross-user authorization regressions. This release makes the proof
clearer, safer, and harder to misread. Detection behavior is unchanged.

### Added

- **Exposure Summary** for confirmed broken-access-control findings. Inspects
  the replay response body (already in memory) and records sanitized field
  paths, content type, body size, conservative classification signals, and the
  evidence hash. Runs only on confirmed BOLA findings with JSON bodies; never
  affects pass/fail.
- **Classification signals** (field-name-based, conservative): `possible_pii`,
  `possible_location`, `resource_identifier`, `possible_financial`,
  `possible_secret`. Signals are a hint, never a verdict.
- **Evidence metadata** on every finding: `findingId` (stable `AG-<ts>-<seq>`
  reference), `evidence` block (semantic + raw hashes, `matchedHash`,
  `matchType`), `request` metadata, `recordedAt`, and `replayedAt`.
- **Report privacy and integrity sections**: top-level `privacy`
  (`rawTokensStored`/`rawBodiesStored`/`rawValuesStored: false`) and `integrity`
  (schema id, detection primitive, retention policies) so the trust model is
  visible in the artifact itself.
- **Key sanitization**: dynamic or sensitive JSON object keys (email, UUID,
  token, long numeric, high-entropy, control characters) are replaced with inert
  placeholders (`[email-key]`, `[uuid-key]`, `[token-like-key]`, `[numeric-key]`,
  `[dynamic-key]`, `[unsafe-key]`) before being stored as field-path segments.
  Schema field names are kept unchanged.
- **Sanitization disclosure**: `sanitizedFieldPaths`, `sanitizedKeyTypes`, and
  `sanitizedKeySegments` honestly report when and how much sanitization occurred,
  so path deduplication never makes a report look more precise than the data.
- **Pre-parse body-size ceiling** (1 MB). Oversized responses skip exposure
  analysis with a `skipped: true, reason: "body-too-large"` summary; the
  confirmed finding is still reported.
- **`docs/report-schema.md`** documenting the full report structure, both
  Exposure Summary shapes, and the sanitization placeholder table.
- **CHANGELOG.md** (this file).

### Changed

- Reporter "Why flagged" wording now branches on `matchType` and the actual
  evidence-hash prefix. A big-int JSON match proved by raw bytes is described as
  raw-byte hashing rather than incorrectly claiming JSON normalisation.
- `matchType` and the evidence hash now derive from a single pair of booleans,
  so `exposureSummary.summaryGeneratedFromHash === evidence.matchedHash` holds
  by construction.
- Architecture diagram (`docs/architecture.svg`) and README architecture section
  updated to show the Exposure Summary flow and raw-body-discarded annotation.
- `SECURITY.md` documents the Exposure Summary privacy model and adds an explicit
  note that request paths, `resourceIds`, and `curl` are preserved verbatim for
  reproducibility and are **not** sanitized.
- Test suite expanded from 209 to 657 passing tests, including integration
  coverage for Cookie, API key, Token-scheme, and scheme-less authentication
  mechanisms alongside the existing Bearer tests.

### Fixed

- Depth-cap off-by-one: with `MAX_DEPTH = 12`, traversal stored paths 13 segments
  deep. The deepest stored path is now exactly 12 segments.
- **Resource-ID candidate filter** (`extractResourceIds`): version-only path
  segments (`v1`, `v2`, `v10`) were extracted as integer resource IDs, and
  hyphenated route names (`order-history`) were treated as slug resource IDs.
  Both caused false positive findings on shared global endpoints. The function
  now skips API version markers, treats slugs as resource IDs only when they
  embed a digit or appear under a collection parent, and extracts query-string
  IDs only from id-like parameter keys (`id`, `orderId`, `userId`, etc.).

### Security

- Exposure Summary never stores raw response bodies, raw field values, or raw
  tokens. Field-path segments derived from sensitive keys are sanitized.
- URL/path privacy is a documented boundary: sensitive data placed in a URL by
  the target API (email, token, identifier) is preserved verbatim in `path`,
  `resourceIds`, and `curl` for reproduction. Reports are security artifacts.

## [0.9.2] — earlier

- Authorization regression testing from real authenticated traffic.
- Live proxy capture, second-user replay, SHA-256 hash comparison.
- Twelve rounds of adversarial assessment; 85+ attack vectors; zero open findings.

[0.10.0]: https://github.com/rodrigo-areyzaga/jabearri/releases/tag/v0.10.0
[0.9.2]: https://github.com/rodrigo-areyzaga/jabearri/releases/tag/v0.9.2
