# accguard

**Session-aware access control proxy for local test environments.**

Sits between your test suite and your app. Watches authenticated requests. After your tests complete, replays them with a second user's token to confirm access control is actually enforced.

---

## Legal notice

> **You must only use accguard against systems you own or have explicit written permission to test.**
>
> Unauthorized use may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), or equivalent laws in your jurisdiction. accguard only operates against localhost and private network addresses. Any attempt to point it at a public IP address will be blocked at startup.

---

## How it works

1. You run accguard alongside your existing test suite
2. Your tests run normally — accguard silently records every authenticated API request
3. When tests finish, accguard replays each request using a second user's token
4. Any endpoint that returns real data to the wrong user is reported as a confirmed finding

No changes to your test code. No new testing concepts. One config file.

---

## Setup

```bash
# No install step yet — run directly with node
node src/cli.js
```

Create `accguard.config.json` in your project root:

```json
{
  "target": "http://localhost:3000",
  "port": 8877,
  "scope": ["/api/"],
  "exclude": ["/api/health", "/api/public/"],
  "outputFile": "accguard-report.json"
}
```

---

## Running with your tests

```bash
# Terminal 1 — start accguard
node src/cli.js

# Terminal 2 — run your tests with the proxy set
HTTP_PROXY=http://127.0.0.1:8877 npm test

# When tests finish, Ctrl+C accguard — it will replay and report
```

Provide a second user's token to enable replay:

```bash
ACCGUARD_TOKEN_B="session-token-of-another-user" node src/cli.js
```

---

## CI integration (GitHub Actions example)

```yaml
- name: Start app
  run: npm start &

- name: Start accguard
  run: node src/cli.js &
  env:
    ACCGUARD_TOKEN_B: ${{ secrets.TEST_USER_B_TOKEN }}

- name: Run tests
  run: HTTP_PROXY=http://127.0.0.1:8877 npm test

- name: Flush accguard
  run: curl -s -X POST http://127.0.0.1:8877/--flush
  # accguard exits with code 1 if findings exist — fails the CI step
```

---

## Running the test suite

```bash
node test/run.js
```

The test suite starts a fake vulnerable app with a deliberate IDOR bug and confirms accguard detects it.

---

## What accguard does NOT do

- Intercept HTTPS traffic (no certificate injection, ever)
- Modify requests in any way
- Store request bodies, response bodies, or raw tokens
- Connect to any public IP address
- Run as a persistent background daemon
- Scan ports or discover hosts

---

## Configuration reference

| Field        | Required | Description |
|---|---|---|
| `target`     | yes | URL of your local app |
| `scope`      | yes | Path prefixes to record (e.g. `["/api/"]`) |
| `exclude`    | no  | Path prefixes to always skip |
| `port`       | no  | Proxy port (default: 8877) |
| `outputFile` | no  | JSON report path (default: `accguard-report.json`) |

---

## Environment variables

| Variable             | Description |
|---|---|
| `ACCGUARD_TOKEN_B`   | Second user's session token for replay |
| `ACCGUARD_CONFIG`    | Path to config file (default: `./accguard.config.json`) |
