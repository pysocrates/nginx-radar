#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./config.env.example
[[ -f "$SCRIPT_DIR/config.env.example" ]] && source "$SCRIPT_DIR/config.env.example"
# shellcheck source=./config.env
[[ -f "$SCRIPT_DIR/config.env" ]] && source "$SCRIPT_DIR/config.env"
# shellcheck source=./parsers/ip.sh
source "$SCRIPT_DIR/parsers/ip.sh"
# shellcheck source=./parsers/endpoints.sh
source "$SCRIPT_DIR/parsers/endpoints.sh"
# shellcheck source=./parsers/scanners.sh
source "$SCRIPT_DIR/parsers/scanners.sh"
# shellcheck source=./parsers/status.sh
source "$SCRIPT_DIR/parsers/status.sh"
# shellcheck source=./parsers/fail2ban.sh
source "$SCRIPT_DIR/parsers/fail2ban.sh"
# shellcheck source=./parsers/errorlog.sh
source "$SCRIPT_DIR/parsers/errorlog.sh"

declare -A ip_counts=()
declare -A network_counts=()
declare -A endpoint_counts=()
declare -A user_agent_counts=()
declare -A method_counts=()
declare -A status_counts=()
declare -A status_path_counts=()
declare -A status_families=()
declare -A scanner_counts=()
declare -A ip_windows=()
declare -A burst_alert_state=()
declare -A seen_ip_first_seen=()
declare -A fail2ban_action_counts=()
declare -A fail2ban_jail_counts=()
declare -A fail2ban_ip_counts=()
declare -A live_connection_counts=()
declare -A live_connection_state_counts=()
declare -A live_connection_flow_counts=()
declare -A error_signal_counts=()
declare -A fail2ban_current_bans_by_jail=()
declare -a scanner_events=()
declare -a fail2ban_events=()
declare -a error_events=()
declare -a alert_events=()
declare -a ufw_rules=()
declare -a snapshot_buffer=()
declare -a new_ip_events=()
declare -a process_memory_rows=()

request_timestamps=""
NGINX_LINES_PROCESSED=0
FAIL2BAN_LINES_PROCESSED=0
ERROR_LINES_PROCESSED=0
response_size_total=0
response_size_samples=0
tls_handshake_error_count=0
REFRESH_SECONDS="${REFRESH_SECONDS:-2}"
TOP_N="${TOP_N:-5}"
BURST_WINDOW_SECONDS="${BURST_WINDOW_SECONDS:-2}"
BURST_THRESHOLD="${BURST_THRESHOLD:-10}"
SNAPSHOT_POLL_SECONDS="${SNAPSHOT_POLL_SECONDS:-15}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-1}"
ENABLE_ERROR_LOG="${ENABLE_ERROR_LOG:-1}"
ENABLE_UFW="${ENABLE_UFW:-1}"
ENABLE_SS="${ENABLE_SS:-1}"
ENABLE_SYSTEM_METRICS="${ENABLE_SYSTEM_METRICS:-1}"
ENABLE_FAIL2BAN_STATUS="${ENABLE_FAIL2BAN_STATUS:-1}"
FAIL2BAN_CLIENT_PREFIX="${FAIL2BAN_CLIENT_PREFIX:-}"
NGINX_FD_PREFIX="${NGINX_FD_PREFIX:-}"
UFW_PREFIX="${UFW_PREFIX:-}"
PS_PREFIX="${PS_PREFIX:-}"
SYSTEM_LOAD_AVG="n/a"
SYSTEM_MEMORY_USAGE="n/a"
FAIL2BAN_ACTIVE_JAILS=0
FAIL2BAN_CURRENT_BANS=0
FAIL2BAN_TOTAL_BANS=0
SNAPSHOT_COLLECTING=0
SNAPSHOT_LAST_APPLIED="never"
SSH_KEY_PATH=""
NGINX_OPEN_FDS="n/a"
PYTHON_THREAD_COUNT="n/a"
GUNICORN_PROCESS_COUNT="n/a"
SCREEN_INITIALIZED=0
CURSOR_HIDDEN=0
WRAP_DISABLED=0
RESIZE_PENDING=0
declare -a SSH_ARGS=()

expand_path() {
    local value="$1"
    printf '%s\n' "${value/#\~/$HOME}"
}

configure_ssh_args() {
    SSH_ARGS=()
    SSH_KEY_PATH=""

    if [[ -n "${KEY:-}" ]]; then
        SSH_KEY_PATH=$(expand_path "$KEY")
        SSH_ARGS=(-i "$SSH_KEY_PATH")
    fi
}

show_config_help() {
    printf 'Missing remote configuration.\n' >&2
    printf 'Copy %s/config.env.example to %s/config.env and set SERVER.\n' "$SCRIPT_DIR" "$SCRIPT_DIR" >&2
}

validate_runtime_config() {
    local missing=()

    if [[ -z "${SERVER:-}" || "$SERVER" == "user@example-host" ]]; then
        missing+=("SERVER")
    fi

    if [[ -z "${LOG:-}" ]]; then
        missing+=("LOG")
    fi

    if (( ENABLE_ERROR_LOG == 1 )) && [[ -z "${ERROR_LOG:-}" ]]; then
        missing+=("ERROR_LOG")
    fi

    if (( ENABLE_FAIL2BAN == 1 )) && [[ -z "${FAIL2BAN_LOG:-}" ]]; then
        missing+=("FAIL2BAN_LOG")
    fi

    if (( ${#missing[@]} > 0 )); then
        printf 'Missing config values: %s\n' "${missing[*]}" >&2
        show_config_help
        exit 1
    fi
}

trim_text() {
    awk '{$1=$1; print}' <<<"$1"
}

append_recent() {
    local array_name="$1"
    local entry="$2"
    local limit="$3"
    declare -n target="$array_name"

    target+=("$entry")
    if (( ${#target[@]} > limit )); then
        target=("${target[@]: -limit}")
    fi
}

add_alert() {
    append_recent alert_events "$1" "${RECENT_ALERTS:-8}"
}

fit_cell() {
    local text="$1"
    local width="$2"

    if (( width < 4 )); then
        printf '%-*.*s' "$width" "$width" "$text"
        return
    fi

    if (( ${#text} > width )); then
        printf '%-*s' "$width" "${text:0:width-3}..."
    else
        printf '%-*s' "$width" "$text"
    fi
}

repeat_char() {
    local char="$1"
    local count="$2"
    local result=""

    (( count < 0 )) && count=0

    while (( count > 0 )); do
        result+="$char"
        ((count--))
    done

    printf '%s' "$result"
}

render_box() {
    local source_name="$1"
    local width="$2"
    local out_name="$3"
    declare -n source="$source_name"
    declare -n out="$out_name"
    local title filler line

    title="${source[0]-}"
    filler=$(repeat_char "-" "$(( width - ${#title} - 3 ))")

    out=("+- ${title} ${filler}+")

    for line in "${source[@]:1}"; do
        out+=("| $(fit_cell "$line" "$width") |")
    done

    out+=("+$(repeat_char "-" "$(( width + 2 ))")+")
}

print_box_row() {
    local left_name="$1"
    local center_name="$2"
    local right_name="$3"
    declare -n left="$left_name"
    declare -n center="$center_name"
    declare -n right="$right_name"
    local max_lines=0
    local i
    local left_blank center_blank right_blank

    (( ${#left[@]} > max_lines )) && max_lines=${#left[@]}
    (( ${#center[@]} > max_lines )) && max_lines=${#center[@]}
    (( ${#right[@]} > max_lines )) && max_lines=${#right[@]}
    left_blank=$(printf '%*s' "${#left[0]}" '')
    center_blank=$(printf '%*s' "${#center[0]}" '')
    right_blank=$(printf '%*s' "${#right[0]}" '')

    for (( i=0; i<max_lines; i++ )); do
        printf '%s  %s  %s\n' \
            "${left[i]-$left_blank}" \
            "${center[i]-$center_blank}" \
            "${right[i]-$right_blank}"
    done
    printf '\n'
}

print_two_box_row() {
    local left_name="$1"
    local right_name="$2"
    declare -n left="$left_name"
    declare -n right="$right_name"
    local max_lines=0
    local i
    local left_blank right_blank

    (( ${#left[@]} > max_lines )) && max_lines=${#left[@]}
    (( ${#right[@]} > max_lines )) && max_lines=${#right[@]}
    left_blank=$(printf '%*s' "${#left[0]}" '')
    right_blank=$(printf '%*s' "${#right[0]}" '')

    for (( i=0; i<max_lines; i++ )); do
        printf '%s  %s\n' \
            "${left[i]-$left_blank}" \
            "${right[i]-$right_blank}"
    done
    printf '\n'
}

build_overview_section() {
    local out_name="$1"
    local rpm="$2"
    local new_ips="$3"
    local avg_size="$4"
    declare -n out="$out_name"

    out=(
        "Overview"
        "Server: $SERVER"
        "Rate: $rpm req/min | New IPs/m: $new_ips | Avg bytes: $avg_size | TLS errs: $tls_handshake_error_count"
        "Load: $SYSTEM_LOAD_AVG | Mem: $SYSTEM_MEMORY_USAGE | nginx fd: $NGINX_OPEN_FDS | UFW deny: ${#ufw_rules[@]} | F2B current: $FAIL2BAN_CURRENT_BANS"
        "Snapshot: $SNAPSHOT_LAST_APPLIED | Updated: $(date '+%Y-%m-%d %H:%M:%S')"
        "Access: $LOG ($NGINX_LINES_PROCESSED) | Error: $ERROR_LOG ($ERROR_LINES_PROCESSED) | Fail2Ban: $FAIL2BAN_LOG ($FAIL2BAN_LINES_PROCESSED)"
    )
}

current_terminal_columns() {
    local cols

    cols=$(tput cols 2>/dev/null || printf '%s' "${COLUMNS:-120}")
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=120
    (( cols < 40 )) && cols=40
    printf '%s\n' "$cols"
}

current_terminal_lines() {
    local lines

    lines=$(tput lines 2>/dev/null || printf '%s' "${LINES:-40}")
    [[ "$lines" =~ ^[0-9]+$ ]] || lines=40
    (( lines < 12 )) && lines=12
    printf '%s\n' "$lines"
}

split_three_widths() {
    local total="$1"
    local first_name="$2"
    local second_name="$3"
    local third_name="$4"
    local weight1="$5"
    local weight2="$6"
    local weight3="$7"
    declare -n first="$first_name"
    declare -n second="$second_name"
    declare -n third="$third_name"
    local weight_sum=$(( weight1 + weight2 + weight3 ))

    first=$(( total * weight1 / weight_sum ))
    second=$(( total * weight2 / weight_sum ))
    third=$(( total - first - second ))
}

clip_dashboard_height() {
    local text="$1"
    local max_lines="$2"
    local notice="... truncated; enlarge terminal or reduce TOP_N"
    local -a lines=()

    mapfile -t lines <<<"$text"

    if (( ${#lines[@]} <= max_lines )); then
        printf '%s' "$text"
        return
    fi

    if (( max_lines <= 1 )); then
        printf '%s' "$notice"
        return
    fi

    lines=("${lines[@]:0:max_lines-1}")
    lines+=("$notice")
    printf '%s\n' "${lines[@]}"
}

normalize_dashboard_width() {
    local text="$1"
    local width="$2"
    local -a lines=()
    local line

    mapfile -t lines <<<"$text"

    for line in "${lines[@]}"; do
        printf '%s\n' "$(fit_cell "$line" "$width")"
    done
}

build_ranked_section() {
    local out_name="$1"
    local title="$2"
    local array_name="$3"
    local limit="$4"
    local header="$5"
    local format_string="$6"
    local empty_message="$7"
    declare -n out="$out_name"
    declare -n source="$array_name"
    local rows
    local key value

    out=("$title" "$header")

    if (( ${#source[@]} == 0 )); then
        out+=("$empty_message")
        return
    fi

    rows=$(
        for key in "${!source[@]}"; do
            printf '%s\t%s\n' "$key" "${source[$key]}"
        done | LC_ALL=C sort -t $'\t' -k2,2nr -k1,1 | head -n "$limit"
    )

    while IFS=$'\t' read -r key value; do
        [[ -z "${key:-}" ]] && continue
        out+=("$(printf "$format_string" "$key" "$value")")
    done <<<"$rows"
}

build_status_section() {
    local out_name="$1"
    local rpm="$2"
    local new_ips="$3"
    local avg_size="$4"
    declare -n out="$out_name"
    local rows
    local key value

    out=(
        "Traffic Summary"
        "$(printf '%-14s %6s' "Metric" "Value")"
        "$(printf '%-14s %6s' "req/min" "$rpm")"
        "$(printf '%-14s %6s' "new ips/m" "$new_ips")"
        "$(printf '%-14s %6s' "avg bytes" "$avg_size")"
        "$(printf '%-14s %6s' "tls errs" "$tls_handshake_error_count")"
        "$(printf '%-14s %6s' "2xx" "${status_families[2xx]:-0}")"
        "$(printf '%-14s %6s' "3xx" "${status_families[3xx]:-0}")"
        "$(printf '%-14s %6s' "4xx" "${status_families[4xx]:-0}")"
        "$(printf '%-14s %6s' "5xx" "${status_families[5xx]:-0}")"
        "$(printf '%-14s %6s' "400" "${status_counts[400]:-0}")"
        "$(printf '%-14s %6s' "444" "${status_counts[444]:-0}")"
        "$(printf '%-14s %6s' "499" "${status_counts[499]:-0}")"
        ""
        "$(printf '%-14s %6s' "err signal" "Hits")"
    )

    if (( ${#error_signal_counts[@]} == 0 )); then
        out+=("error log quiet")
        return
    fi

    rows=$(
        for key in "${!error_signal_counts[@]}"; do
            printf '%s\t%s\n' "$key" "${error_signal_counts[$key]}"
        done | LC_ALL=C sort -t $'\t' -k2,2nr -k1,1 | head -n 4
    )

    while IFS=$'\t' read -r key value; do
        [[ -z "${key:-}" ]] && continue
        out+=("$(printf '%-14s %6s' "$key" "$value")")
    done <<<"$rows"
}

build_method_section() {
    local out_name="$1"
    declare -n out="$out_name"
    local rows
    local method count

    out=(
        "Methods + Nginx"
        "$(printf '%-10s %6s' "Method" "Hits")"
    )

    if (( ${#method_counts[@]} == 0 )); then
        out+=("waiting for data")
    else
        rows=$(
            for method in "${!method_counts[@]}"; do
                printf '%s\t%s\n' "$method" "${method_counts[$method]}"
            done | LC_ALL=C sort -t $'\t' -k2,2nr -k1,1 | head -n 5
        )

        while IFS=$'\t' read -r method count; do
            [[ -z "${method:-}" ]] && continue
            out+=("$(printf '%-10s %6s' "$method" "$count")")
        done <<<"$rows"
    fi

    out+=("")
    out+=("$(printf '%-10s %6s' "nginx fd" "$NGINX_OPEN_FDS")")
}

build_protection_section() {
    local out_name="$1"
    declare -n out="$out_name"
    local rows
    local jail count
    local displayed=0

    out=(
        "Protection + F2B"
        "$(printf '%-16s %5s' "Signal" "Value")"
        "$(printf '%-16s %5s' "UFW deny" "${#ufw_rules[@]}")"
        "$(printf '%-16s %5s' "F2B jails" "$FAIL2BAN_ACTIVE_JAILS")"
        "$(printf '%-16s %5s' "F2B current" "$FAIL2BAN_CURRENT_BANS")"
        "$(printf '%-16s %5s' "F2B total" "$FAIL2BAN_TOTAL_BANS")"
        ""
    )

    if (( ${#fail2ban_current_bans_by_jail[@]} > 0 )); then
        rows=$(
            for jail in "${!fail2ban_current_bans_by_jail[@]}"; do
                printf '%s\t%s\n' "$jail" "${fail2ban_current_bans_by_jail[$jail]}"
            done | LC_ALL=C sort -t $'\t' -k2,2nr -k1,1 | head -n 3
        )

        while IFS=$'\t' read -r jail count; do
            [[ -z "${jail:-}" ]] && continue
            out+=("$(printf '%-16s %5s' "$jail" "$count")")
        done <<<"$rows"
        out+=("")
    fi

    if (( ${#ufw_rules[@]} == 0 )); then
        out+=("no active UFW deny rules")
        return
    fi

    out+=("UFW rules")
    for rule in "${ufw_rules[@]}"; do
        out+=("$rule")
        ((displayed++))
        if (( displayed >= 4 )); then
            break
        fi
    done
}

build_recent_section() {
    local out_name="$1"
    local title="$2"
    local array_name="$3"
    local empty_message="$4"
    declare -n out="$out_name"
    declare -n source="$array_name"
    local i

    out=("$title" "")

    if (( ${#source[@]} == 0 )); then
        out+=("$empty_message")
        return
    fi

    for (( i=${#source[@]}-1; i>=0; i-- )); do
        out+=("${source[i]}")
    done
}

shorten_tcp_state() {
    case "$1" in
        ESTAB) printf 'ESTAB\n' ;;
        SYN-SENT) printf 'SYNSNT\n' ;;
        SYN-RECV) printf 'SYNRCV\n' ;;
        FIN-WAIT-1) printf 'FIN1\n' ;;
        FIN-WAIT-2) printf 'FIN2\n' ;;
        TIME-WAIT) printf 'TWAIT\n' ;;
        CLOSE-WAIT) printf 'CLWAIT\n' ;;
        LAST-ACK) printf 'LACK\n' ;;
        CLOSING) printf 'CLOSNG\n' ;;
        CLOSED) printf 'CLOSED\n' ;;
        LISTEN) printf 'LISTEN\n' ;;
        *) printf '%s\n' "$1" ;;
    esac
}

build_live_tcp_section() {
    local out_name="$1"
    declare -n out="$out_name"
    local state_rows connection_rows
    local key value ip state shown=0

    out=(
        "TCP Snapshot"
    )

    if (( ${#live_connection_counts[@]} == 0 )); then
        out+=("waiting for data")
        return
    fi

    if (( ${#live_connection_state_counts[@]} > 0 )); then
        out+=("State totals")
        state_rows=$(
            for key in "${!live_connection_state_counts[@]}"; do
                printf '%s\t%s\n' "$key" "${live_connection_state_counts[$key]}"
            done | LC_ALL=C sort -t $'\t' -k2,2nr -k1,1 | head -n 3
        )

        while IFS=$'\t' read -r key value; do
            [[ -z "${key:-}" ]] && continue
            out+=("$(printf '%-15s %4s' "$(shorten_tcp_state "$key")" "$value")")
            ((shown++))
        done <<<"$state_rows"

        if (( shown > 0 )); then
            out+=("")
        fi
    fi

    out+=("$(printf '%-15s %-7s %4s' "Peer IP" "State" "Cnt")")

    connection_rows=$(
        for key in "${!live_connection_counts[@]}"; do
            printf '%s\t%s\n' "$key" "${live_connection_counts[$key]}"
        done | LC_ALL=C sort -t $'\t' -k2,2nr -k1,1 | head -n "$TOP_N"
    )

    while IFS=$'\t' read -r key value; do
        [[ -z "${key:-}" ]] && continue
        ip="${key%%|*}"
        state="${key#*|}"
        out+=("$(printf '%-15s %-7s %4s' "$ip" "$(shorten_tcp_state "$state")" "$value")")
    done <<<"$connection_rows"
}

build_connection_flow_section() {
    local out_name="$1"
    declare -n out="$out_name"
    local rows
    local key value local_endpoint peer_endpoint state

    out=(
        "Connection Paths"
        "$(printf '%-30s %-30s %-7s %4s' "Source" "Destination" "State" "Cnt")"
    )

    if (( ${#live_connection_flow_counts[@]} == 0 )); then
        out+=("waiting for data")
        return
    fi

    rows=$(
        for key in "${!live_connection_flow_counts[@]}"; do
            printf '%s\t%s\n' "$key" "${live_connection_flow_counts[$key]}"
        done | LC_ALL=C sort -t $'\t' -k2,2nr -k1,1 | head -n "$TOP_N"
    )

    while IFS=$'\t' read -r key value; do
        [[ -z "${key:-}" ]] && continue
        local_endpoint="${key%%|*}"
        key="${key#*|}"
        peer_endpoint="${key%%|*}"
        state="${key#*|}"
        out+=("$(printf '%-30s %-30s %-7s %4s' "$local_endpoint" "$peer_endpoint" "$(shorten_tcp_state "$state")" "$value")")
    done <<<"$rows"
}

format_rss_kb() {
    local rss_kb="$1"

    [[ "$rss_kb" =~ ^[0-9]+$ ]] || {
        printf '%s\n' "$rss_kb"
        return
    }

    if (( rss_kb >= 1048576 )); then
        printf '%sG\n' "$(( (rss_kb + 524288) / 1048576 ))"
    elif (( rss_kb >= 1024 )); then
        printf '%sM\n' "$(( (rss_kb + 512) / 1024 ))"
    else
        printf '%sK\n' "$rss_kb"
    fi
}

build_process_watch_section() {
    local out_name="$1"
    declare -n out="$out_name"
    local row

    out=(
        "Process Watch"
        "$(printf '%-16s %6s | %-17s %6s' "python threads" "$PYTHON_THREAD_COUNT" "gunicorn procs" "$GUNICORN_PROCESS_COUNT")"
        "$(printf '%-8s %-5s %6s %s' "PID" "%MEM" "RSS" "Command")"
    )

    if (( ${#process_memory_rows[@]} == 0 )); then
        out+=("waiting for data")
        return
    fi

    for row in "${process_memory_rows[@]}"; do
        out+=("$row")
    done
}

render_dashboard() {
    local rpm
    local new_ips
    local avg_size
    local dashboard
    local terminal_cols
    local terminal_lines
    local overview_width
    local summary_row_total
    local summary_left_width
    local summary_center_width
    local summary_right_width
    local source_row_total
    local source_left_width
    local source_center_width
    local source_right_width
    local events_row_total
    local events_left_width
    local events_center_width
    local events_right_width
    local detail_row_total
    local detail_left_width
    local detail_right_width
    local -a overview_section=()
    local -a ip_section=()
    local -a network_section=()
    local -a live_tcp_section=()
    local -a process_watch_section=()
    local -a connection_flow_section=()
    local -a endpoint_section=()
    local -a agent_section=()
    local -a method_section=()
    local -a status_section=()
    local -a status_path_section=()
    local -a protection_section=()
    local -a scanner_section=()
    local -a error_section=()
    local -a alert_section=()
    local -a overview_box=()
    local -a status_box=()
    local -a protection_box=()
    local -a tcp_box=()
    local -a process_watch_box=()
    local -a connection_flow_box=()
    local -a ip_box=()
    local -a network_box=()
    local -a endpoint_box=()
    local -a agent_box=()
    local -a method_box=()
    local -a status_path_box=()
    local -a alert_box=()
    local -a scanner_box=()
    local -a error_box=()

    rpm=$(current_request_rate)
    new_ips=$(current_new_ip_rate)
    avg_size=$(current_average_response_size)
    terminal_cols=$(current_terminal_columns)
    terminal_lines=$(current_terminal_lines)
    overview_width=$(( terminal_cols - 4 ))
    summary_row_total=$(( terminal_cols - 16 ))
    split_three_widths "$summary_row_total" summary_left_width summary_center_width summary_right_width 24 30 30
    source_row_total=$(( terminal_cols - 16 ))
    split_three_widths "$source_row_total" source_left_width source_center_width source_right_width 24 24 36
    events_row_total=$(( terminal_cols - 16 ))
    split_three_widths "$events_row_total" events_left_width events_center_width events_right_width 28 28 28
    detail_row_total=$(( terminal_cols - 10 ))
    detail_left_width=$(( detail_row_total * 1 / 3 ))
    detail_right_width=$(( detail_row_total - detail_left_width ))

    if (( terminal_cols < 60 )); then
        dashboard=$(
            printf 'NGINX RADAR\n'
            printf '====================================\n'
            printf 'Terminal too narrow (%s cols)\n' "$terminal_cols"
            printf 'Widen the window to at least 60 columns.\n'
            printf 'Snapshot: %s\n' "$SNAPSHOT_LAST_APPLIED"
        )
        dashboard=$(clip_dashboard_height "$dashboard" "$(( terminal_lines - 1 ))")

        if [[ -t 1 ]]; then
            if (( SCREEN_INITIALIZED == 0 || RESIZE_PENDING == 1 )); then
                printf '\033[?25l\033[?7l\033[H\033[2J'
                SCREEN_INITIALIZED=1
                CURSOR_HIDDEN=1
                WRAP_DISABLED=1
                RESIZE_PENDING=0
            else
                printf '\033[H'
            fi
            printf '%s' "$dashboard"
            printf '\033[J'
        else
            printf '%s' "$dashboard"
        fi
        return
    fi

    build_overview_section overview_section "$rpm" "$new_ips" "$avg_size"
    build_ranked_section ip_section "Top IPs" ip_counts "$TOP_N" "$(printf '%-15s %6s' "IP" "Hits")" '%-15s %6s' "waiting for data"
    build_ranked_section network_section "Top Networks" network_counts "$TOP_N" "$(printf '%-16s %5s' "/24" "Hits")" '%-16s %5s' "waiting for data"
    build_live_tcp_section live_tcp_section
    build_process_watch_section process_watch_section
    build_connection_flow_section connection_flow_section
    build_ranked_section endpoint_section "Top Endpoints" endpoint_counts "$TOP_N" "$(printf '%-36s %6s' "Path" "Hits")" '%-36s %6s' "waiting for data"
    build_ranked_section agent_section "Top Agents" user_agent_counts "$TOP_N" "$(printf '%-28s %6s' "Agent" "Hits")" '%-28s %6s' "waiting for data"
    build_method_section method_section
    build_status_section status_section "$rpm" "$new_ips" "$avg_size"
    build_ranked_section status_path_section "Top Status Paths" status_path_counts "$TOP_N" "$(printf '%-32s %6s' "Status Path" "Hits")" '%-32s %6s' "waiting for data"
    build_protection_section protection_section
    build_recent_section scanner_section "Recent Scanners" scanner_events "none"
    build_recent_section error_section "Recent Error Log" error_events "none"
    build_recent_section alert_section "Recent Alerts" alert_events "none"
    render_box overview_section "$overview_width" overview_box
    render_box status_section "$summary_left_width" status_box
    render_box protection_section "$summary_center_width" protection_box
    render_box live_tcp_section "$summary_right_width" tcp_box
    render_box process_watch_section "$overview_width" process_watch_box
    render_box connection_flow_section "$overview_width" connection_flow_box
    render_box ip_section "$source_left_width" ip_box
    render_box network_section "$source_center_width" network_box
    render_box agent_section "$source_right_width" agent_box
    render_box endpoint_section "$overview_width" endpoint_box
    render_box method_section "$detail_left_width" method_box
    render_box status_path_section "$detail_right_width" status_path_box
    render_box alert_section "$events_left_width" alert_box
    render_box scanner_section "$events_center_width" scanner_box
    render_box error_section "$events_right_width" error_box

    dashboard=$(
        printf 'NGINX RADAR\n'
        printf '====================================\n'
        printf '%s\n' "${overview_box[@]}"
        printf '\n'
        print_box_row status_box protection_box tcp_box
        printf '\n'
        printf '%s\n' "${endpoint_box[@]}"
        printf '\n'
        print_box_row ip_box network_box agent_box
        printf '\n'
        print_two_box_row method_box status_path_box
        printf '\n'
        print_box_row alert_box scanner_box error_box
        printf '\n'
        printf '%s\n' "${process_watch_box[@]}"
        printf '\n'
        printf '%s\n' "${connection_flow_box[@]}"
    )
    dashboard=$(clip_dashboard_height "$dashboard" "$(( terminal_lines - 1 ))")
    dashboard=$(normalize_dashboard_width "$dashboard" "$terminal_cols")

    if [[ -t 1 ]]; then
        if (( SCREEN_INITIALIZED == 0 || RESIZE_PENDING == 1 )); then
            printf '\033[?25l\033[?7l\033[H\033[2J'
            SCREEN_INITIALIZED=1
            CURSOR_HIDDEN=1
            WRAP_DISABLED=1
            RESIZE_PENDING=0
        else
            printf '\033[H'
        fi
        printf '%s' "$dashboard"
        printf '\033[J'
    else
        printf '%s' "$dashboard"
    fi
}

on_winch() {
    RESIZE_PENDING=1
}

parse_socket_ip() {
    local endpoint="$1"

    if [[ "$endpoint" == \[*\]:* ]]; then
        endpoint="${endpoint#\[}"
        endpoint="${endpoint%%\]:*}"
        printf '%s\n' "$endpoint"
        return
    fi

    if [[ "$endpoint" == *:* ]]; then
        printf '%s\n' "${endpoint%:*}"
        return
    fi

    printf '%s\n' "$endpoint"
}

parse_ufw_snapshot_line() {
    local line="$1"
    local out_name="$2"
    declare -n out="$out_name"
    local cleaned rule to from

    cleaned=$(sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' <<<"$line")
    cleaned=$(trim_text "$cleaned")

    if [[ "$cleaned" =~ ^\[[[:space:]]*([0-9]+)\][[:space:]]*(.+)[[:space:]]+((DENY|REJECT)([[:space:]]+(IN|OUT))?)[[:space:]]+(.+)$ ]]; then
        rule="${BASH_REMATCH[1]}"
        to=$(trim_text "${BASH_REMATCH[2]}")
        from=$(trim_text "${BASH_REMATCH[7]}")
    else
        return
    fi

    [[ -z "$to" || -z "$from" ]] && return
    out+=("$(printf '#%-3s %-18s %s' "$rule" "$from" "$to")")
}

parse_ss_snapshot_line() {
    local line="$1"
    local out_name="$2"
    local state_counts_name="$3"
    local flow_counts_name="$4"
    declare -n out="$out_name"
    declare -n state_counts="$state_counts_name"
    declare -n flow_counts="$flow_counts_name"
    local state local_endpoint peer_endpoint ip key flow_key

    [[ -z "$line" ]] && return
    [[ "$line" == State* || "$line" == Recv-Q* ]] && return

    state=$(awk '{print $1}' <<<"$line")
    local_endpoint=$(awk '{print $(NF-1)}' <<<"$line")
    peer_endpoint=$(awk '{print $NF}' <<<"$line")
    ip=$(parse_socket_ip "$peer_endpoint")

    [[ -z "$ip" || -z "$state" || -z "$local_endpoint" || -z "$peer_endpoint" ]] && return

    key="${ip}|${state}"
    flow_key="${local_endpoint}|${peer_endpoint}|${state}"
    ((out["$key"]++))
    ((state_counts["$state"]++))
    ((flow_counts["$flow_key"]++))
}

parse_uptime_snapshot_line() {
    local line="$1"
    local out_name="$2"
    declare -n out="$out_name"

    if [[ "$line" =~ load\ average[s]?:[[:space:]]*([0-9.]+),[[:space:]]*([0-9.]+),[[:space:]]*([0-9.]+) ]]; then
        out="${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"
    fi
}

parse_free_snapshot_line() {
    local line="$1"
    local out_name="$2"
    declare -n out="$out_name"
    local total used percent

    [[ "$line" == Mem:* ]] || return

    total=$(awk '{print $2}' <<<"$line")
    used=$(awk '{print $3}' <<<"$line")

    [[ -z "$total" || "$total" == 0 ]] && return
    percent=$(( used * 100 / total ))
    out="${used}/${total}MB (${percent}%)"
}

parse_nginx_fd_snapshot_line() {
    local line="$1"
    local out_name="$2"
    declare -n out="$out_name"

    if [[ "$line" =~ fds=([^[:space:]]+) ]]; then
        out="${BASH_REMATCH[1]}"
    fi
}

parse_process_memory_snapshot_line() {
    local line="$1"
    local out_name="$2"
    declare -n out="$out_name"
    local user pid cpu mem vsz rss tty stat start time command

    [[ -z "$line" || "$line" == USER* ]] && return

    read -r user pid cpu mem vsz rss tty stat start time command <<<"$line"

    [[ "$pid" =~ ^[0-9]+$ ]] || return
    [[ -n "$command" ]] || command="(unknown)"
    out+=("$(printf '%-8s %-5s %6s %s' "$pid" "$mem" "$(format_rss_kb "$rss")" "$command")")
}

parse_python_thread_snapshot_line() {
    local line="$1"
    local out_name="$2"
    declare -n out="$out_name"

    if [[ "$line" =~ threads=([0-9]+) ]]; then
        out="${BASH_REMATCH[1]}"
    fi
}

parse_gunicorn_snapshot_line() {
    local line="$1"
    local out_name="$2"
    declare -n out="$out_name"

    if [[ "$line" =~ workers=([0-9]+) ]]; then
        out="${BASH_REMATCH[1]}"
    fi
}

parse_fail2ban_top_line() {
    local line="$1"
    local out_name="$2"
    declare -n out="$out_name"

    if [[ "$line" =~ Number\ of\ jail:[[:space:]]*([0-9]+) ]]; then
        out="${BASH_REMATCH[1]}"
    fi
}

parse_fail2ban_jail_line() {
    local jail="$1"
    local line="$2"
    local bans_name="$3"
    local current_name="$4"
    local total_name="$5"
    declare -n bans_ref="$bans_name"
    declare -n current_ref="$current_name"
    declare -n total_ref="$total_name"
    local count

    if [[ "$line" =~ Currently\ banned:[[:space:]]*([0-9]+) ]]; then
        count="${BASH_REMATCH[1]}"
        bans_ref["$jail"]="$count"
        ((current_ref += count))
    fi

    if [[ "$line" =~ Total\ banned:[[:space:]]*([0-9]+) ]]; then
        ((total_ref += BASH_REMATCH[1]))
    fi
}

apply_snapshot_buffer() {
    local current_section=""
    local jail=""
    local line
    local new_load="$SYSTEM_LOAD_AVG"
    local new_mem="$SYSTEM_MEMORY_USAGE"
    local new_nginx_open_fds="n/a"
    local new_python_thread_count="n/a"
    local new_gunicorn_process_count="n/a"
    local new_active_jails="n/a"
    local new_current_bans="n/a"
    local new_total_bans="n/a"
    local new_current_bans_count=0
    local new_total_bans_count=0
    local nginx_fd_seen=0
    local fail2ban_top_seen=0
    local fail2ban_jail_stats_seen=0
    local -a new_ufw_rules=()
    local -a new_process_memory_rows=()
    local -A new_live_connection_counts=()
    local -A new_live_connection_state_counts=()
    local -A new_live_connection_flow_counts=()
    local -A new_fail2ban_current_bans_by_jail=()

    for line in "${snapshot_buffer[@]}"; do
        if [[ "$line" == __SECTION__:* ]]; then
            current_section="${line#__SECTION__:}"
            continue
        fi

        case "$current_section" in
            UFW)
                parse_ufw_snapshot_line "$line" new_ufw_rules
                ;;
            SS)
                parse_ss_snapshot_line "$line" new_live_connection_counts new_live_connection_state_counts new_live_connection_flow_counts
                ;;
            UPTIME)
                parse_uptime_snapshot_line "$line" new_load
                ;;
            FREE)
                parse_free_snapshot_line "$line" new_mem
                ;;
            NGINXFD)
                [[ "$line" =~ fds=([^[:space:]]+) ]] && nginx_fd_seen=1
                parse_nginx_fd_snapshot_line "$line" new_nginx_open_fds
                ;;
            PSMEM)
                parse_process_memory_snapshot_line "$line" new_process_memory_rows
                ;;
            PSTHREADS)
                parse_python_thread_snapshot_line "$line" new_python_thread_count
                ;;
            GUNICORN)
                parse_gunicorn_snapshot_line "$line" new_gunicorn_process_count
                ;;
            F2BTOP)
                [[ "$line" =~ Number\ of\ jail:[[:space:]]*([0-9]+) ]] && fail2ban_top_seen=1
                parse_fail2ban_top_line "$line" new_active_jails
                ;;
            JAIL:*)
                jail="${current_section#JAIL:}"
                if [[ "$line" =~ (Currently|Total)\ banned:[[:space:]]*([0-9]+) ]]; then
                    fail2ban_jail_stats_seen=1
                fi
                parse_fail2ban_jail_line "$jail" "$line" new_fail2ban_current_bans_by_jail new_current_bans_count new_total_bans_count
                ;;
        esac
    done

    if (( fail2ban_top_seen == 1 )); then
        if [[ "$new_active_jails" == "0" ]]; then
            new_current_bans=0
            new_total_bans=0
        elif (( fail2ban_jail_stats_seen == 0 )); then
            new_current_bans="n/a"
            new_total_bans="n/a"
        else
            new_current_bans="$new_current_bans_count"
            new_total_bans="$new_total_bans_count"
        fi
    fi

    if (( nginx_fd_seen == 0 )); then
        new_nginx_open_fds="n/a"
    fi

    ufw_rules=("${new_ufw_rules[@]}")
    process_memory_rows=("${new_process_memory_rows[@]}")
    live_connection_counts=()
    for line in "${!new_live_connection_counts[@]}"; do
        live_connection_counts["$line"]="${new_live_connection_counts[$line]}"
    done

    live_connection_state_counts=()
    for line in "${!new_live_connection_state_counts[@]}"; do
        live_connection_state_counts["$line"]="${new_live_connection_state_counts[$line]}"
    done

    live_connection_flow_counts=()
    for line in "${!new_live_connection_flow_counts[@]}"; do
        live_connection_flow_counts["$line"]="${new_live_connection_flow_counts[$line]}"
    done

    fail2ban_current_bans_by_jail=()
    for line in "${!new_fail2ban_current_bans_by_jail[@]}"; do
        fail2ban_current_bans_by_jail["$line"]="${new_fail2ban_current_bans_by_jail[$line]}"
    done

    SYSTEM_LOAD_AVG="$new_load"
    SYSTEM_MEMORY_USAGE="$new_mem"
    NGINX_OPEN_FDS="$new_nginx_open_fds"
    PYTHON_THREAD_COUNT="$new_python_thread_count"
    GUNICORN_PROCESS_COUNT="$new_gunicorn_process_count"
    FAIL2BAN_ACTIVE_JAILS="$new_active_jails"
    FAIL2BAN_CURRENT_BANS="$new_current_bans"
    FAIL2BAN_TOTAL_BANS="$new_total_bans"
    SNAPSHOT_LAST_APPLIED="$(date '+%Y-%m-%d %H:%M:%S')"
}

process_nginx_line() {
    local line="$1"
    local ip path status method agent size now

    ip=$(extract_ip "$line")
    path=$(extract_path "$line")
    status=$(extract_status "$line")
    method=$(extract_method "$line")
    agent=$(extract_user_agent "$line")
    size=$(extract_response_size "$line")

    [[ -z "$ip" ]] && return

    ((NGINX_LINES_PROCESSED++))
    now=$(date +%s)

    record_ip_hit "$ip"
    record_network_hit "$ip"
    record_new_ip_seen "$ip" "$now"
    record_endpoint_hit "$path"
    record_method_hit "$method"
    record_user_agent_hit "$agent"
    record_status_hit "$status"
    record_status_path_hit "$status" "$path"
    record_response_size "$size"
    record_request_rate_hit "$now"
    record_burst_hit "$ip" "$now"

    if is_suspicious_path "$path"; then
        record_scanner_hit "$ip" "$path"
    fi
}

process_fail2ban_line() {
    local line="$1"

    ((FAIL2BAN_LINES_PROCESSED++))
    record_fail2ban_event "$line"
}

process_nginx_error_line() {
    local line="$1"

    ((ERROR_LINES_PROCESSED++))
    record_error_log_line "$line"
}

process_snapshot_payload() {
    local payload="$1"

    if [[ "$payload" == "__SNAPSHOT_BEGIN__" ]]; then
        snapshot_buffer=()
        SNAPSHOT_COLLECTING=1
        return
    fi

    if [[ "$payload" == "__SNAPSHOT_END__" ]]; then
        SNAPSHOT_COLLECTING=0
        apply_snapshot_buffer
        return
    fi

    if (( SNAPSHOT_COLLECTING == 1 )); then
        snapshot_buffer+=("$payload")
    fi
}

process_tagged_line() {
    local tagged_line="$1"
    local source payload

    source="${tagged_line%%|*}"
    payload="${tagged_line#*|}"

    if [[ "$tagged_line" != *'|'* ]]; then
        source="nginx"
        payload="$tagged_line"
    fi

    case "$source" in
        nginx)
            process_nginx_line "$payload"
            ;;
        fail2ban)
            process_fail2ban_line "$payload"
            ;;
        nginx_error)
            process_nginx_error_line "$payload"
            ;;
        snapshot)
            process_snapshot_payload "$payload"
            ;;
    esac
}

build_snapshot_remote_command() {
    local command=""
    local fail2ban_client_cmd="fail2ban-client"
    local nginx_fd_count_cmd='ls -1 "/proc/$pid/fd" 2>/dev/null | wc -l'
    local ufw_cmd="ufw"
    local ps_cmd="ps"

    if [[ -n "$FAIL2BAN_CLIENT_PREFIX" ]]; then
        fail2ban_client_cmd="${FAIL2BAN_CLIENT_PREFIX} fail2ban-client"
    fi

    if [[ -n "$NGINX_FD_PREFIX" ]]; then
        nginx_fd_count_cmd="${NGINX_FD_PREFIX} sh -c 'ls -1 \"/proc/\$1/fd\" 2>/dev/null | wc -l' sh \"\$pid\""
    fi

    if [[ -n "$UFW_PREFIX" ]]; then
        ufw_cmd="${UFW_PREFIX} ufw"
    fi

    if [[ -n "$PS_PREFIX" ]]; then
        ps_cmd="${PS_PREFIX} ps"
    fi

    command+="export PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$PATH\"; "
    command+="printf '__SNAPSHOT_BEGIN__\n'; "

    if (( ENABLE_UFW == 1 )); then
        command+="printf '__SECTION__:UFW\n'; ${ufw_cmd} status numbered 2>/dev/null || true; "
    fi

    if (( ENABLE_SS == 1 )); then
        command+="printf '__SECTION__:SS\n'; ss -tn 2>/dev/null || true; "
    fi

    if (( ENABLE_SYSTEM_METRICS == 1 )); then
        command+="printf '__SECTION__:UPTIME\n'; uptime 2>/dev/null || true; "
        command+="printf '__SECTION__:FREE\n'; free -m 2>/dev/null || true; "
        command+="printf '__SECTION__:NGINXFD\n'; pid=\$(pgrep -o nginx 2>/dev/null || true); if [ -z \"\$pid\" ]; then printf 'pid=none fds=n/a\n'; else fd_count=\$(${nginx_fd_count_cmd}); if [[ \"\$fd_count\" =~ ^[0-9]+$ ]]; then printf 'pid=%s fds=%s\n' \"\$pid\" \"\$fd_count\"; else printf 'pid=%s fds=n/a\n' \"\$pid\"; fi; fi; "
        command+="printf '__SECTION__:PSMEM\n'; ${ps_cmd} aux --sort=-%mem 2>/dev/null | head -n $(( TOP_N + 1 )) || true; "
        command+="printf '__SECTION__:PSTHREADS\n'; ${ps_cmd} -eLf 2>/dev/null | awk '/python/ && \$0 !~ /awk/ {count++} END {printf \"threads=%d\\n\", count+0}' || true; "
        command+="printf '__SECTION__:GUNICORN\n'; ${ps_cmd} -eo comm=,args= 2>/dev/null | awk '/gunicorn/ {count++} END {printf \"workers=%d\\n\", count+0}' || true; "
    fi

    if (( ENABLE_FAIL2BAN_STATUS == 1 )); then
        command+="printf '__SECTION__:F2BTOP\n'; ${fail2ban_client_cmd} status 2>/dev/null || true; "
        command+="for jail in \$(${fail2ban_client_cmd} status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do "
        command+="printf '__SECTION__:JAIL:%s\n' \"\$jail\"; "
        command+="${fail2ban_client_cmd} status \"\$jail\" 2>/dev/null || true; "
        command+="done; "
    fi

    command+="printf '__SNAPSHOT_END__\n';"
    printf '%s\n' "$command"
}

start_remote_tail_stream() {
    local tag="$1"
    local fifo_path="$2"
    local remote_command="$3"

    (
        ssh "${SSH_ARGS[@]}" "$SERVER" "$remote_command" 2>/dev/null | while IFS= read -r line; do
            printf '%s|%s\n' "$tag" "$line"
        done
    ) >"$fifo_path" &
    stream_pids+=("$!")
}

start_remote_poll_stream() {
    local tag="$1"
    local fifo_path="$2"
    local interval="$3"
    local remote_command="$4"

    (
        while true; do
            ssh "${SSH_ARGS[@]}" "$SERVER" "$remote_command" 2>/dev/null | while IFS= read -r line; do
                printf '%s|%s\n' "$tag" "$line"
            done
            sleep "$interval"
        done
    ) >"$fifo_path" &
    stream_pids+=("$!")
}

cleanup() {
    local pid

    for pid in "${stream_pids[@]-}"; do
        kill "$pid" 2>/dev/null || true
    done

    [[ -n "${stream_fifo:-}" ]] && rm -f "$stream_fifo"
}

start_streams() {
    local snapshot_command

    configure_ssh_args
    stream_fifo="$(mktemp -u "$SCRIPT_DIR/.radar-stream.XXXXXX")"
    mkfifo "$stream_fifo"

    start_remote_tail_stream "nginx" "$stream_fifo" "tail -f '$LOG'"

    if (( ENABLE_ERROR_LOG == 1 )); then
        start_remote_tail_stream "nginx_error" "$stream_fifo" "tail -f '$ERROR_LOG'"
    fi

    if (( ENABLE_FAIL2BAN == 1 )); then
        start_remote_tail_stream "fail2ban" "$stream_fifo" "tail -f '$FAIL2BAN_LOG'"
    fi

    if (( ENABLE_UFW == 1 || ENABLE_SS == 1 || ENABLE_SYSTEM_METRICS == 1 || ENABLE_FAIL2BAN_STATUS == 1 )); then
        snapshot_command=$(build_snapshot_remote_command)
        start_remote_poll_stream "snapshot" "$stream_fifo" "$SNAPSHOT_POLL_SECONDS" "$snapshot_command"
    fi
}

on_exit() {
    cleanup
    if [[ -t 1 && "$CURSOR_HIDDEN" == 1 ]]; then
        printf '\033[?25h'
    fi
    if [[ -t 1 && "$WRAP_DISABLED" == 1 ]]; then
        printf '\033[?7h'
    fi
    printf '\nStopping nginx-radar\n'
}

main() {
    local last_render now tagged_line
    local active
    local pid
    declare -ga stream_pids=()

    trap on_exit EXIT
    trap 'exit 0' INT TERM
    trap on_winch WINCH

    if [[ "${1:-}" == "--stdin" ]]; then
        last_render=$(date +%s)
        render_dashboard

        while IFS= read -r tagged_line; do
            process_tagged_line "$tagged_line"
            now=$(date +%s)
            if (( now - last_render >= REFRESH_SECONDS )); then
                render_dashboard
                last_render="$now"
            fi
        done

        add_alert "Input stream ended"
        render_dashboard
        return
    fi

    validate_runtime_config
    start_streams
    exec 3<>"$stream_fifo"
    last_render=$(date +%s)
    render_dashboard

    while true; do
        if IFS= read -r -t 1 tagged_line <&3; then
            process_tagged_line "$tagged_line"
        else
            active=0
            for pid in "${stream_pids[@]}"; do
                if kill -0 "$pid" 2>/dev/null; then
                    active=1
                    break
                fi
            done

            if (( active == 0 )); then
                add_alert "All log streams ended"
                render_dashboard
                break
            fi
        fi

        now=$(date +%s)
        if (( now - last_render >= REFRESH_SECONDS )); then
            render_dashboard
            last_render="$now"
        fi
    done
}

main "$@"
