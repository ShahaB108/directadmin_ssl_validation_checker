#!/usr/bin/env bash
# DirectAdmin bulk SSL issuance
# TechSupp / sh.rahimpour

OUTPUT_DIR="/var/www/html"
TIMESTAMP=$(date '+%Y%m%d')
OUTPUT_FILE="${OUTPUT_DIR}/ssl_report.html"
LE_SCRIPT="/usr/local/directadmin/scripts/letsencrypt.sh"
DA_TASK_QUEUE="/usr/local/directadmin/data/task.queue"
DA_TASK_QUEUE_CB="/usr/local/directadmin/data/task.queue.cb"
DA_DATA="/usr/local/directadmin/data/users"
SSL_TIMEOUT=6
CERT_RENEW_THRESHOLD=604800   # 7 days
ISSUANCE_DELAY=3

SUCCESS_LIST=()
FAILED_LIST=()
SKIPPED_SSL_LIST=()
SKIPPED_IP_LIST=()

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# ── Preflight ─────────────────────────────────────────────────────────────────

[ "$EUID" -ne 0 ] && { echo "Run as root."; exit 1; }

for dep in dig ip awk grep openssl ping; do
    command -v "$dep" &>/dev/null || { echo "Missing dependency: $dep"; exit 1; }
done

[ -f "$LE_SCRIPT" ] || { echo "letsencrypt.sh not found: $LE_SCRIPT"; exit 1; }
[ -d "$OUTPUT_DIR" ] || { echo "Output dir not found: $OUTPUT_DIR"; exit 1; }

da config-set dns_ttl 0
systemctl reload directadmin

# ── Server IP ─────────────────────────────────────────────────────────────────

SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
[ -z "$SERVER_IP" ] && SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
[ -z "$SERVER_IP" ] && SERVER_IP=$(hostname -I | awk '{print $1}')
[ -z "$SERVER_IP" ] && { echo "Cannot determine server IP"; exit 1; }

log "Hostname:  $(hostname)"
log "Server IP: $SERVER_IP"

# ── DNS check ─────────────────────────────────────────────────────────────────
# Returns 0 if any resolved IP matches the server IP

points_here() {
    local domain="$1"

    # dig — returns all A records
    local ips
    ips=$(dig +short +time=5 +tries=2 A "$domain" 2>/dev/null \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)

    # ping fallback — libc resolver, parse "(IP)" from first line
    if [ -z "$ips" ]; then
        ips=$(ping -c1 -W1 "$domain" 2>/dev/null \
            | grep -oE '\([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\)' \
            | tr -d '()' | head -1 || true)
    fi

    [ -z "$ips" ] && return 1
    echo "$ips" | grep -qF "$SERVER_IP"
}

# ── SSL / cert check ──────────────────────────────────────────────────────────
# Returns 0 if domain already has a valid non-expiring cert

cert_ok() {
    local domain="$1" username="$2"
    local cert_file="/usr/local/directadmin/data/users/${username}/domains/${domain}.cert"

    # Fast path: cert file on disk
    if [ -s "$cert_file" ]; then
        if openssl x509 -noout -checkend "$CERT_RENEW_THRESHOLD" -in "$cert_file" 2>/dev/null; then
            return 0
        fi
    fi

    # Slow path: live SSL check
    local output
    output=$(echo | timeout "$SSL_TIMEOUT" openssl s_client \
        -connect "${domain}:443" -servername "$domain" 2>&1)
    echo "$output" | grep -q "Verify return code: 0 (ok)" || return 1
    echo "$output" | openssl x509 -noout -checkend "$CERT_RENEW_THRESHOLD" 2>/dev/null
}

# ── Clear DA task queue ───────────────────────────────────────────────────────

log "Clearing DirectAdmin task queue..."
if [ -f "$DA_TASK_QUEUE" ]; then
    cp "$DA_TASK_QUEUE" "/tmp/task.queue.bak.${TIMESTAMP}" 2>/dev/null || true
    > "$DA_TASK_QUEUE"
    log "task.queue cleared"
else
    log "Warning: $DA_TASK_QUEUE not found"
fi
[ -f "$DA_TASK_QUEUE_CB" ] && { > "$DA_TASK_QUEUE_CB"; log "task.queue.cb cleared"; }

# ── Scan domains ──────────────────────────────────────────────────────────────

[ -d "$DA_DATA" ] || { log "ERROR: $DA_DATA not found"; exit 1; }

user_count=0
domain_count=0
issued_count=0

log "Scanning $DA_DATA ..."

for user_dir in "${DA_DATA}"/*/; do
    [ -d "$user_dir" ] || continue
    username=$(basename "$user_dir")
    domains_dir="${user_dir}domains"
    [ -d "$domains_dir" ] || continue
    user_count=$((user_count + 1))

    shopt -s nullglob
    conf_files=("${domains_dir}"/*.conf)
    shopt -u nullglob
    [ ${#conf_files[@]} -eq 0 ] && continue

    for conf_file in "${conf_files[@]}"; do
        [ -f "$conf_file" ] || continue
        domain=$(basename "$conf_file" .conf)
        domain_count=$((domain_count + 1))

        # Step 1: Does domain resolve to this server?
        if ! points_here "$domain"; then
            resolved=$(dig +short +time=3 +tries=1 A "$domain" 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
            SKIPPED_IP_LIST+=("$domain|$username|${resolved:-no A record}")
            log "SKIP IP   $domain → ${resolved:-no A record}"
            continue
        fi

        # Step 2: Does it already have a valid cert?
        if cert_ok "$domain" "$username"; then
            SKIPPED_SSL_LIST+=("$domain|$username|cert valid")
            log "SKIP SSL  $domain"
            continue
        fi

        # Step 3: Issue SSL
        [ "$issued_count" -gt 0 ] && sleep "$ISSUANCE_DELAY"

        log "Requesting SSL: $domain (user: $username)"
        cmd_output=$("$LE_SCRIPT" request "$domain" 2048 2>&1) && cmd_exit=0 || cmd_exit=$?
        issued_count=$((issued_count + 1))

        if [ "$cmd_exit" -eq 0 ]; then
            SUCCESS_LIST+=("$domain|$username|Issued OK")
            log "SUCCESS   $domain"
        else
            err=$(echo "$cmd_output" \
                | grep -i "error\|could not\|failed\|timeout" 2>/dev/null \
                | grep -v "^#" | tail -2 | tr '\n' ' ' || true)
            [ -z "$err" ] && err=$(echo "$cmd_output" | tail -2 | tr '\n' ' ')
            FAILED_LIST+=("$domain|$username|${err:0:200}")
            log "FAILED    $domain — $err"
        fi
    done
done

log "Scan complete: $user_count users, $domain_count domains"

# ── HTML report ───────────────────────────────────────────────────────────────

log "Writing report: $OUTPUT_FILE"

total_success=${#SUCCESS_LIST[@]}
total_failed=${#FAILED_LIST[@]}
total_skip_ssl=${#SKIPPED_SSL_LIST[@]}
total_skip_ip=${#SKIPPED_IP_LIST[@]}

render_rows() {
    local css_class="$1" label="$2"
    shift 2
    local entry domain user note
    for entry in "$@"; do
        IFS='|' read -r domain user note <<< "$entry"
        echo "    <tr><td class=\"badge ${css_class}\">${label}</td><td>${domain}</td><td>${user}</td><td>${note}</td></tr>"
    done
}

{
cat << 'HTMLSTART'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
HTMLSTART

echo "<title>SSL Report — $(date '+%Y-%m-%d %H:%M')</title>"

cat << 'HTMLSTYLE'
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 24px; font-size: 14px; }
  h1 { color: #58a6ff; margin-bottom: 18px; font-size: 20px; letter-spacing: 1px; }
  .meta { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 14px 18px; margin-bottom: 18px; line-height: 2.2; }
  .meta span { color: #8b949e; }
  .pills { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
  .pill { padding: 5px 14px; border-radius: 20px; font-size: 13px; font-weight: bold; }
  .p-ok  { background:#0d4429; color:#3fb950; border:1px solid #3fb950; }
  .p-err { background:#3d0c0c; color:#f85149; border:1px solid #f85149; }
  .p-ssl { background:#1c2128; color:#8b949e; border:1px solid #30363d; }
  .p-ip  { background:#2d1f00; color:#d29922; border:1px solid #d29922; }
  table { width:100%; border-collapse:collapse; }
  thead tr { background:#161b22; }
  th { padding:9px 14px; text-align:left; color:#8b949e; border-bottom:1px solid #30363d; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }
  td { padding:7px 14px; border-bottom:1px solid #21262d; vertical-align:top; word-break:break-word; }
  tr:hover td { background:#161b22; }
  .badge { border-radius:4px; padding:2px 8px; font-size:12px; font-weight:bold; white-space:nowrap; }
  .SUCCESS  { background:#0d4429; color:#3fb950; }
  .FAILED   { background:#3d0c0c; color:#f85149; }
  .SKIP_SSL { background:#1c2128; color:#8b949e; }
  .SKIP_IP  { background:#2d1f00; color:#d29922; }
  .section-hdr td { background:#161b22; color:#58a6ff; font-weight:bold; font-size:12px; padding:5px 14px; letter-spacing:.5px; }
</style>
</head>
<body>
HTMLSTYLE

echo "<h1>&#x1F512; DirectAdmin SSL Report</h1>"
echo "<div class=\"meta\">"
echo "  <span>Generated:</span> $(date '+%Y-%m-%d %H:%M:%S') &nbsp;&nbsp;"
echo "  <span>Server IP:</span> ${SERVER_IP} &nbsp;&nbsp;"
echo "  <span>Users:</span> ${user_count} &nbsp;&nbsp;"
echo "  <span>Domains:</span> ${domain_count}"
echo "</div>"
echo "<div class=\"pills\">"
echo "  <div class=\"pill p-ok\">&#x2713; Issued: ${total_success}</div>"
echo "  <div class=\"pill p-err\">&#x2717; Failed: ${total_failed}</div>"
echo "  <div class=\"pill p-ssl\">&#x23E9; Has SSL: ${total_skip_ssl}</div>"
echo "  <div class=\"pill p-ip\">&#x26A0; IP mismatch: ${total_skip_ip}</div>"
echo "</div>"

cat << 'HTMLTABLE'
<table>
  <thead>
    <tr><th>Status</th><th>Domain</th><th>User</th><th>Note</th></tr>
  </thead>
  <tbody>
HTMLTABLE

if [ "$total_success" -gt 0 ]; then
    echo "    <tr class=\"section-hdr\"><td colspan=\"4\">&#x2713; ISSUED</td></tr>"
    render_rows "SUCCESS" "ISSUED" "${SUCCESS_LIST[@]}"
fi
if [ "$total_failed" -gt 0 ]; then
    echo "    <tr class=\"section-hdr\"><td colspan=\"4\">&#x2717; FAILED</td></tr>"
    render_rows "FAILED" "FAILED" "${FAILED_LIST[@]}"
fi
if [ "$total_skip_ip" -gt 0 ]; then
    echo "    <tr class=\"section-hdr\"><td colspan=\"4\">&#x26A0; IP MISMATCH</td></tr>"
    render_rows "SKIP_IP" "IP" "${SKIPPED_IP_LIST[@]}"
fi
if [ "$total_skip_ssl" -gt 0 ]; then
    echo "    <tr class=\"section-hdr\"><td colspan=\"4\">&#x23E9; HAS VALID SSL</td></tr>"
    render_rows "SKIP_SSL" "HAS SSL" "${SKIPPED_SSL_LIST[@]}"
fi

if [ "$((total_success + total_failed + total_skip_ssl + total_skip_ip))" -eq 0 ]; then
    echo "    <tr><td colspan=\"4\" style=\"text-align:center;padding:20px;color:#8b949e;\">No domain conf files found under ${DA_DATA}</td></tr>"
fi

cat << 'HTMLEND'
  </tbody>
</table>
</body>
</html>
HTMLEND
} > "$OUTPUT_FILE"

log "Rerwiting Configs..."

da build rewrite_confs

log "🏁 Done. Issued: $total_success | Failed: $total_failed | Has SSL: $total_skip_ssl | IP mismatch: $total_skip_ip"
log "🏁 Report: $OUTPUT_FILE"
log "🏁 Link: $(hostname)/ssl_report.html"
