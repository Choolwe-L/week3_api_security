# Week 3 — OWASP ZAP Automated Scan Report

**Project:** Fitness API Security Assessment & Hardening Framework (JPR Solutions internship)
**Week 3 focus:** Automated Vulnerability Scanning (DAST) with OWASP ZAP
**Date:** 2026-11-07
**Tester:** Choolwe-L

---

## 1. Objective

Use an automated **Dynamic Application Security Testing (DAST)** tool — **OWASP ZAP
(Zed Attack Proxy)** — to discover common vulnerabilities in the Fitness API, as
required by the Week 3 brief:

- Install and configure OWASP ZAP.
- Proxy API traffic through ZAP to build a site map.
- Perform an automated active scan against the API endpoints.
- Analyze the scan report and prioritize findings.

## 2. Scope & target

| Item | Value |
|------|-------|
| Target | `http://127.0.0.1:5000` (Fitness API, Week 1 build) |
| Ownership | Locally-owned, authorized lab target only |
| Tooling | OWASP ZAP **2.17.0** (headless/daemon), scan rules `ascanrules` 78 / `pscanrules` 70 |
| Scan type | Spider + automated **active scan** (DAST) + passive scan |
| Endpoints tested | `/`, `/api/register`, `/api/login`, `/api/users/{id}`, `/api/workouts`, `/api/search` |

> The Week 3 brief supplied no external target, so the project's own deliberately
> vulnerable Fitness API (built in Week 1) was run locally and used as the
> authorized target. ZAP's active scanner sends real attack payloads and was only
> ever pointed at this locally-owned instance.

## 3. Method

1. **Install & configure ZAP.** ZAP 2.17.0 was run headless in daemon mode with a
   local API key, bound to `127.0.0.1` only (`-silent`, so no telemetry / add-on
   auto-update traffic).
2. **Proxy API traffic to build the site map.** Because the API is a headless REST
   service (nothing links to the endpoints), every endpoint — including `POST`
   bodies for register / login / workout creation — was replayed through ZAP's
   proxy so the endpoints appear in ZAP's Sites tree.
3. **Spider.** ZAP spidered the root to pick up anything linked.
4. **Active scan (DAST).** ZAP's active scanner attacked every mapped endpoint and
   parameter (injection, XSS, header checks, etc.) while the passive scanner
   inspected all responses.
5. **Report & prioritize.** Reports were exported in HTML, JSON and Markdown; the
   JSON was parsed into a risk-ordered findings list
   (`deliverables/03_ZAP_Findings_Prioritized.md`).

Everything is reproducible via `scripts/run_zap_scan.sh` (see the README).

## 4. Results — summary of alerts

| Risk | Count |
|------|-------|
| **High** | 1 |
| **Medium** | 1 |
| **Low** | 3 |
| **Informational** | 4 |
| **Total** | 9 |

### Findings (highest risk first)

| # | Risk | Confidence | Alert | CWE | Instances |
|---|------|-----------|-------|-----|-----------|
| 1 | **High** | Low* | SQL Injection | 89 | 3 |
| 2 | Medium | High | Content Security Policy (CSP) Header Not Set | 693 | 5 |
| 3 | Low | Low | Cross Site Scripting Weakness (Persistent in JSON Response) | 79 | 5 |
| 4 | Low | High | Server Leaks Version Information via `Server` header | 497 | 4 |
| 5 | Low | Medium | X-Content-Type-Options Header Missing | 693 | 5 |
| 6 | Info | High | Authentication Request Identified | — | 1 |
| 7 | Info | Medium | Information Disclosure — Sensitive Information in URL | 598 | 1 |
| 8 | Info | Medium | Session Management Response Identified | — | 1 |
| 9 | Info | Medium | User Agent Fuzzer | — | 5 |

\* ZAP rates the SQLi confidence "Low", but it was **manually confirmed** (see §5) —
this is a true positive, not a false alarm.

## 5. Priority finding — SQL Injection (High, CWE-89)

ZAP flagged SQL Injection on **3 instances**, including:

- `GET /api/search?activity='`
- `POST /api/login` (two injection points)

This matches the intentional weakness in the Week 1 code, where queries are built
by string formatting:

```python
query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
...
query = "SELECT * FROM workouts WHERE activity LIKE '%%%s%%'" % activity
```

**Manual confirmation (authentication bypass):**

```bash
curl -s -X POST http://127.0.0.1:5000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin'"'"' -- ","password":"anything"}'
# -> {"message":"login ok","token":"token-3","user_id":3}   (logged in as admin, no password)
```

**Impact:** full authentication bypass, and read access to the `users` table
(usernames, plaintext passwords, roles) via the injectable endpoints.

**Remediation (for Week 4+ hardening):** use parameterized queries
(`db.execute("... WHERE username = ? AND password = ?", (username, password))`),
never string formatting; store password **hashes** (bcrypt/argon2), not plaintext;
apply least-privilege DB access.

## 6. Other notable findings

- **CSP header not set (Medium):** no `Content-Security-Policy` on any response —
  add a restrictive CSP (and, for a JSON API, ensure responses are not rendered as HTML).
- **Persistent XSS in JSON response (Low):** user-controlled values are reflected
  into responses; combined with a missing `X-Content-Type-Options: nosniff` and the
  default content type this is worth fixing — set `nosniff` and an explicit
  `application/json` content type.
- **Server version leak (Low):** the `Server` header exposes the Werkzeug/Python
  version — suppress it in production.
- **Sensitive information in URL (Info):** credentials/identifiers passed in query
  strings get logged — prefer POST bodies / headers for secrets.

## 7. Deliverables produced this week

- `zap/reports/zap_fitness_api_report.html` — official ZAP automated scan report (HTML).
- `zap/reports/zap_fitness_api_report.json` / `.md` — machine-readable + Markdown reports.
- `deliverables/03_ZAP_Findings_Prioritized.md` — prioritized vulnerability list.
- `scripts/run_zap_scan.sh`, `scripts/analyze_report.py`, `zap/zap-automation.yaml` —
  reproducible automation.

## 8. Next steps (Week 4 preview)

The High/Medium findings feed directly into the hardening work: parameterize all
SQL, hash passwords, add security headers (CSP, `nosniff`, `X-Frame-Options`),
suppress the server banner, and re-scan to confirm the alerts clear.
