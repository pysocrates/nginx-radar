#!/usr/bin/env bash

extract_request() {
    awk -F'"' '{print $2}' <<<"$1"
}

extract_path() {
    local request

    request=$(extract_request "$1")
    awk '{print $2}' <<<"$request"
}

extract_method() {
    local request

    request=$(extract_request "$1")
    awk '{print $1}' <<<"$request"
}

extract_user_agent() {
    local agent

    agent=$(awk -F'"' '{print $6}' <<<"$1")
    [[ -n "$agent" && "$agent" != "-" ]] && printf '%s\n' "$agent" || printf '(none)\n'
}

extract_response_size() {
    awk '{print $10}' <<<"$1"
}

record_endpoint_hit() {
    local path="$1"

    [[ -z "$path" ]] && return
    ((endpoint_counts["$path"]++))
}

record_method_hit() {
    local method="$1"

    [[ -z "$method" ]] && method="UNKNOWN"
    ((method_counts["$method"]++))
}

record_user_agent_hit() {
    local agent="$1"

    [[ -z "$agent" ]] && agent="(none)"
    ((user_agent_counts["$agent"]++))
}

record_status_path_hit() {
    local status="$1"
    local path="$2"
    local key

    [[ ! "$status" =~ ^[45][0-9]{2}$ ]] && return
    [[ -z "$path" ]] && return

    key="$status $path"
    ((status_path_counts["$key"]++))
}

record_response_size() {
    local size="$1"

    [[ ! "$size" =~ ^[0-9]+$ ]] && return

    ((response_size_total += size))
    ((response_size_samples++))
}

current_average_response_size() {
    if (( response_size_samples == 0 )); then
        printf '0B\n'
        return
    fi

    printf '%sB\n' "$(( response_size_total / response_size_samples ))"
}
