#!/usr/bin/env bash

extract_ip() {
    awk '{print $1}' <<<"$1"
}

record_ip_hit() {
    local ip="$1"
    ((ip_counts["$ip"]++))
}

extract_network_cidr24() {
    local ip="$1"

    if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}$ ]]; then
        printf '%s.%s.%s.0/24\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    fi
}

record_network_hit() {
    local ip="$1"
    local network

    network=$(extract_network_cidr24 "$ip")
    [[ -z "$network" ]] && return
    ((network_counts["$network"]++))
}

record_request_rate_hit() {
    local now="$1"
    local window=60
    local kept=()
    local ts

    for ts in ${request_timestamps:-}; do
        if (( now - ts < window )); then
            kept+=("$ts")
        fi
    done

    kept+=("$now")
    request_timestamps="${kept[*]}"
}

current_request_rate() {
    local now
    local kept=()
    local ts

    now=$(date +%s)

    for ts in ${request_timestamps:-}; do
        if (( now - ts < 60 )); then
            kept+=("$ts")
        fi
    done

    request_timestamps="${kept[*]}"
    printf '%s\n' "${#kept[@]}"
}

record_new_ip_seen() {
    local ip="$1"
    local now="$2"

    if [[ -z "${seen_ip_first_seen[$ip]-}" ]]; then
        seen_ip_first_seen["$ip"]="$now"
        new_ip_events+=("${now}|${ip}")
    fi
}

current_new_ip_rate() {
    local now
    local kept=()
    local entry ts ip

    now=$(date +%s)

    for entry in "${new_ip_events[@]-}"; do
        ts="${entry%%|*}"
        ip="${entry#*|}"
        if (( now - ts < 60 )); then
            kept+=("${ts}|${ip}")
        fi
    done

    new_ip_events=("${kept[@]}")
    printf '%s\n' "${#kept[@]}"
}

record_burst_hit() {
    local ip="$1"
    local now="$2"
    local window="${BURST_WINDOW_SECONDS:-2}"
    local threshold="${BURST_THRESHOLD:-10}"
    local entries="${ip_windows[$ip]-}"
    local kept=()
    local ts

    for ts in $entries; do
        if (( now - ts < window )); then
            kept+=("$ts")
        fi
    done

    kept+=("$now")
    ip_windows["$ip"]="${kept[*]}"

    if (( ${#kept[@]} > threshold )); then
        if [[ -z "${burst_alert_state[$ip]-}" ]]; then
            burst_alert_state["$ip"]=1
            add_alert "BURST DETECTED  IP: $ip  Window: ${window}s  Hits: ${#kept[@]}"
        fi
    else
        unset 'burst_alert_state[$ip]'
    fi
}
