#!/usr/bin/env bash
#
# run_zap_scan.sh — Week 3 automated DAST scan of the Fitness API with OWASP ZAP.
#
# What it does (matches the Week 3 brief):
#   1. Starts ZAP headless as a daemon with a local API key.
#   2. Proxies real API traffic (all known endpoints, incl. POST bodies)
#      through ZAP so the site map / site tree is populated.
#   3. Runs the ZAP spider, then an automated ACTIVE scan (DAST).
#   4. Exports HTML, JSON and Markdown scan reports.
#
# Scope: the locally-owned, deliberately vulnerable Fitness API at
# http://127.0.0.1:5000. Only run against targets you are authorized to test.
#
# Usage:
#   ZAP_SH=/path/to/zap.sh TARGET=http://127.0.0.1:5000 ./scripts/run_zap_scan.sh
set -euo pipefail

TARGET="${TARGET:-http://127.0.0.1:5000}"
ZAP_SH="${ZAP_SH:-zap.sh}"
ZAP_PORT="${ZAP_PORT:-8090}"
ZAP_PROXY="http://127.0.0.1:${ZAP_PORT}"
APIKEY="${APIKEY:-week3scan}"
OUTDIR="${OUTDIR:-zap/reports}"
mkdir -p "$OUTDIR"

api() { curl -s "${ZAP_PROXY}/JSON/$1" --data-urlencode "apikey=${APIKEY}" "${@:2}"; }

echo "[*] Starting ZAP daemon on port ${ZAP_PORT} ..."
# -silent: no callhome / telemetry / add-on update checks (much faster, offline-safe startup)
"$ZAP_SH" -daemon -silent -host 127.0.0.1 -port "$ZAP_PORT" \
  -config api.key="$APIKEY" \
  -config api.addrs.addr.name=127.0.0.1 -config api.addrs.addr.regex=false \
  -config start.checkForUpdates=0 \
  > zap/zap-daemon.log 2>&1 &
ZAP_PID=$!
trap 'echo "[*] Shutting down ZAP"; api core/action/shutdown >/dev/null 2>&1 || kill $ZAP_PID 2>/dev/null || true' EXIT

echo "[*] Waiting for ZAP API to come up (first run installs add-ons, can take ~3 min) ..."
UP=0
for i in $(seq 1 150); do
  if curl -s "${ZAP_PROXY}/JSON/core/view/version/?apikey=${APIKEY}" | grep -q version; then
    echo "[+] ZAP is up: $(curl -s "${ZAP_PROXY}/JSON/core/view/version/?apikey=${APIKEY}")"
    UP=1
    break
  fi
  sleep 2
done
if [ "$UP" -ne 1 ]; then
  echo "[!] ZAP API never came up — aborting. Last daemon log lines:"
  tail -5 zap/zap-daemon.log 2>/dev/null
  exit 1
fi

echo "[*] Proxying API traffic through ZAP to build the site map ..."
px=(--proxy "$ZAP_PROXY" -s -o /dev/null)
curl "${px[@]}" "${TARGET}/"
# auth
curl "${px[@]}" -X POST "${TARGET}/api/register" -H 'Content-Type: application/json' \
  -d '{"username":"zapuser","password":"ZapPass123","email":"zap@fit.local"}'
curl "${px[@]}" -X POST "${TARGET}/api/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}'
# object access (IDOR surface)
for id in 1 2 3; do curl "${px[@]}" "${TARGET}/api/users/${id}"; done
# workouts (GET list, GET by user_id, POST create)
curl "${px[@]}" "${TARGET}/api/workouts"
curl "${px[@]}" "${TARGET}/api/workouts?user_id=1"
curl "${px[@]}" -X POST "${TARGET}/api/workouts" -H 'Content-Type: application/json' \
  -d '{"user_id":1,"activity":"Running","duration_min":30,"calories":300,"notes":"zap"}'
# search (injection surface)
curl "${px[@]}" "${TARGET}/api/search?activity=Running"

echo "[*] Spidering ${TARGET} ..."
SCANID=$(api spider/action/scan/ --data-urlencode "url=${TARGET}" | grep -oP '"scan":"\K[0-9]+')
while :; do
  st=$(api spider/view/status/ --data-urlencode "scanId=${SCANID}" | grep -oP '"status":"\K[0-9]+')
  [ "${st:-0}" -ge 100 ] && break; sleep 2
done
echo "[+] Spider complete."

echo "[*] Waiting for passive scan to drain ..."
while :; do
  rec=$(api pscan/view/recordsToScan/ | grep -oP '"recordsToScan":"\K[0-9]+')
  [ "${rec:-0}" -le 0 ] && break; sleep 2
done

echo "[*] Running ACTIVE scan (DAST) ..."
ASID=$(api ascan/action/scan/ --data-urlencode "url=${TARGET}" --data-urlencode "recurse=true" | grep -oP '"scan":"\K[0-9]+')
while :; do
  st=$(api ascan/view/status/ --data-urlencode "scanId=${ASID}" | grep -oP '"status":"\K[0-9]+')
  echo "    active scan ${st:-0}%"
  [ "${st:-0}" -ge 100 ] && break; sleep 5
done
echo "[+] Active scan complete."

echo "[*] Generating reports ..."
WD="$(pwd)"
api reports/action/generate/ \
  --data-urlencode "title=Fitness API — OWASP ZAP Automated Scan (Week 3)" \
  --data-urlencode "template=traditional-html" \
  --data-urlencode "reportDir=${WD}/${OUTDIR}" \
  --data-urlencode "reportFileName=zap_fitness_api_report.html" >/dev/null
api reports/action/generate/ \
  --data-urlencode "title=Fitness API — OWASP ZAP Automated Scan (Week 3)" \
  --data-urlencode "template=traditional-json" \
  --data-urlencode "reportDir=${WD}/${OUTDIR}" \
  --data-urlencode "reportFileName=zap_fitness_api_report.json" >/dev/null
api reports/action/generate/ \
  --data-urlencode "title=Fitness API — OWASP ZAP Automated Scan (Week 3)" \
  --data-urlencode "template=traditional-md" \
  --data-urlencode "reportDir=${WD}/${OUTDIR}" \
  --data-urlencode "reportFileName=zap_fitness_api_report.md" >/dev/null

echo "[+] Done. Reports in ${OUTDIR}/"
ls -la "${OUTDIR}/"
