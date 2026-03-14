#!/usr/bin/env bash

extract_error_client_ip() {
    local line="$1"

    if [[ "$line" =~ client:[[:space:]]*([0-9]{1,3}(\.[0-9]{1,3}){3}) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    fi
}

extract_error_signal() {
    local line="$1"

    case "$line" in
        *"client sent invalid"*|*"invalid host in request"*|*"client intended to send too large"*)
            printf 'client\n'
            ;;
        *"SSL_do_handshake()"*|*"SSL handshaking to upstream"*|*"wrong version number"*)
            printf 'ssl\n'
            ;;
        *"upstream timed out"*|*"timed out"*|*"Connection timed out"*)
            printf 'timeout\n'
            ;;
        *"no live upstreams"*|*"connect() failed"*|*"upstream prematurely closed connection"*|*"upstream sent too big header"*)
            printf 'upstream\n'
            ;;
        *"limiting requests"*|*"limiting connections"*)
            printf 'limit\n'
            ;;
        *)
            printf 'other\n'
            ;;
    esac
}

record_error_log_line() {
    local line="$1"
    local signal ip entry

    signal=$(extract_error_signal "$line")
    ip=$(extract_error_client_ip "$line")

    ((error_signal_counts["$signal"]++))
    if [[ "$line" == *"SSL"* || "$line" == *"handshake"* || "$signal" == "ssl" ]]; then
        ((tls_handshake_error_count++))
    fi

    entry="$signal"
    [[ -n "$ip" ]] && entry+="  $ip"
    append_recent error_events "$entry" "${RECENT_ERRORS:-8}"
}
