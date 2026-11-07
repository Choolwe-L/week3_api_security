# Week 3 — Automated Vulnerability Scanning with OWASP ZAP

Deliverables for **Week 3** of the *Fitness API Security Assessment & Hardening
Framework* internship (JPR Solutions). This week introduces **DAST** (Dynamic
Application Security Testing): using **OWASP ZAP** to automatically discover
vulnerabilities in the Fitness API.

> **Note on the target:** As in previous weeks, the brief supplied no live target
> API only the task description and reference links. So the project's own
> deliberately-vulnerable **Fitness API** (built in Week 1) is run locally on
> `http://127.0.0.1:5000` and used as the **authorized, locally-owned target**.
> All scanning is performed against that instance only.

## What's here

| Path | Description |
|------|-------------|
| `deliverables/Week3_ZAP_Scan_Report.md` | Human-readable summary of the scan, methodology, and ZAP findings. |
| `deliverables/03_ZAP_Findings_Prioritized.md` | Prioritized vulnerability list (risk-ordered) generated from the raw ZAP report. |
| `zap/reports/zap_fitness_api_report.html` | **Official OWASP ZAP automated scan report** (HTML). |
| `zap/reports/zap_fitness_api_report.json` | Raw ZAP report (JSON) the machine-readable evidence. |
| `zap/reports/zap_fitness_api_report.md` | ZAP report (Markdown). |
| `zap/zap-automation.yaml` | ZAP Automation Framework plan (declarative equivalent of the scan). |
| `scripts/run_zap_scan.sh` | Runner: starts ZAP headless, proxies API traffic, spiders, active-scans, exports reports. |
| `scripts/analyze_report.py` | Parses the ZAP JSON into the prioritized findings list. |
| `target_app/app.py` | The Week 1 vulnerable Fitness API (the local scan target). |

## Method (matches the Week 3 brief)

1. **Install & configure OWASP ZAP** ZAP 2.17.0 run headless (daemon mode).
2. **Proxy API traffic through ZAP to build a site map** every known API
   endpoint (incl. `POST` bodies) is replayed through ZAP's proxy so the REST
   endpoints appear in the site tree (they are not discoverable by spidering
   alone, since nothing links to them).
3. **Automated active scan** ZAP's active scanner (DAST) attacks the mapped
   endpoints (injection, etc.) while the passive scanner inspects every
   response.
4. **Analyze & prioritize** the raw report is parsed and findings are ordered
   by risk.

## Reproduce the scan

```bash
# 1. Start the vulnerable target (Week 1 app) on 127.0.0.1:5000
cd target_app
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python3 app.py            # or: flask --app app run

# 2. In another terminal, run the automated ZAP scan
#    (point ZAP_SH at your zap.sh; on Kali after `apt install zaproxy` it is on PATH)
ZAP_SH=/path/to/zap.sh TARGET=http://127.0.0.1:5000 ./scripts/run_zap_scan.sh

# 3. Build the prioritized findings list from the raw report
python3 scripts/analyze_report.py zap/reports/zap_fitness_api_report.json
```

Open `zap/reports/zap_fitness_api_report.html` in a browser for the full report.

## Scope / ethics

All scanning targets a **locally-run API you own** (`127.0.0.1:5000`). OWASP ZAP's
active scanner sends real attack payloads **only run it against systems you are
explicitly authorized to test.** Do not point these scripts at third-party hosts.
