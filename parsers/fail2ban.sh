#!/usr/bin/env bash

extract_fail2ban_action() {
    local line="$1"

    if [[ "$line" =~ \]\ ([A-Za-z]+)[[:space:]]+([0-9]{1,3}(\.[0-9]{1,3}){3})$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    fi
}

extract_fail2ban_ip() {
    local line="$1"

    if [[ "$line" =~ ([0-9]{1,3}(\.[0-9]{1,3}){3})$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    fi
}

extract_fail2ban_jail() {
    local line="$1"

    if [[ "$line" =~ \[([[:alnum:]_.:-]+)\][[:space:]]+[A-Za-z]+[[:space:]]+[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    fi
}

record_fail2ban_event() {
    local line="$1"
    local action jail ip entry

    action=$(extract_fail2ban_action "$line")
    jail=$(extract_fail2ban_jail "$line")
    ip=$(extract_fail2ban_ip "$line")

    [[ -z "$action" ]] && return

    ((fail2ban_action_counts["$action"]++))
    [[ -n "$jail" ]] && ((fail2ban_jail_counts["$jail"]++))
    [[ -n "$ip" ]] && ((fail2ban_ip_counts["$ip"]++))

    entry="$action"
    [[ -n "$jail" ]] && entry+=" [$jail]"
    [[ -n "$ip" ]] && entry+=" $ip"

    append_recent fail2ban_events "$entry" "${RECENT_FAIL2BAN:-8}"

    case "$action" in
        Ban|Banned)
            add_alert "FAIL2BAN BAN  ${jail:+[$jail] }${ip:-unknown ip}"
            ;;
        Unban|Unbanned)
            add_alert "FAIL2BAN UNBAN  ${jail:+[$jail] }${ip:-unknown ip}"
            ;;
    esac
}
