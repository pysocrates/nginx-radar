#!/usr/bin/env bash

SCANNER_REGEX='(\.(php|asp|jsp|cfm|cgi)([/?#]|$)|(^|/)(admin|wp-admin)([/?#]|$)|(^|/)\.(env|git)([/?#]|$))'

is_suspicious_path() {
    local path="$1"
    [[ "$path" =~ $SCANNER_REGEX ]]
}

record_scanner_hit() {
    local ip="$1"
    local path="$2"
    local key="${ip}|${path}"

    ((scanner_counts["$key"]++))
    append_recent scanner_events "$ip  $path" "${RECENT_SCANNERS:-8}"
    add_alert "SCANNER DETECTED  IP: $ip  PATH: $path"
}
