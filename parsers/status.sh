#!/usr/bin/env bash

extract_status() {
    awk '{print $9}' <<<"$1"
}

record_status_hit() {
    local status="$1"
    local family

    [[ ! "$status" =~ ^[0-9]{3}$ ]] && return

    ((status_counts["$status"]++))
    family="${status:0:1}xx"
    ((status_families["$family"]++))
}
