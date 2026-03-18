# nginx-radar

`nginx-radar` is a local Bash dashboard for watching nginx traffic over SSH.
It tails remote logs, aggregates requests in memory, and refreshes a terminal view with the traffic and security signals that usually matter first.

Nothing is installed on the server. The tool runs locally and executes ordinary SSH commands against the remote host.

## What It Shows

- top IPs and `/24` networks
- top endpoints and user agents
- live TCP peer counts plus full connection source/destination paths
- per-process memory watch plus python thread and gunicorn process counts
- request rate, new IP rate, and average response size
- status code totals and top 4xx/5xx paths
- suspicious probe hits like `.php`, `/.env`, and `/wp-admin`
- burst alerts when one IP exceeds the configured short window
- optional error-log, Fail2Ban, UFW, TCP, and host-metric panels

## Requirements

- Bash 4+ on your local machine
- SSH access to the server
- read access to nginx logs on the server

Optional remote commands used by the extra panels:

- `ufw`
- `ss`
- `uptime`
- `free`
- `ps`
- `fail2ban-client`

If those are missing, disable the related toggles in `config.env`.

## Quick Start

```bash
cp config.env.example config.env
chmod +x radar.sh
```

Edit `config.env`:

```bash
SERVER="ubuntu@example-host"
KEY=""
LOG="/var/log/nginx/access.log"
ERROR_LOG="/var/log/nginx/error.log"
FAIL2BAN_LOG="/var/log/fail2ban.log"
FAIL2BAN_CLIENT_PREFIX=""
NGINX_FD_PREFIX=""
UFW_PREFIX=""
PS_PREFIX=""
```

Then run:

```bash
./radar.sh
```

`KEY=""` means `ssh` will use your normal SSH agent and `~/.ssh/config`.
If you want a dedicated key file, set `KEY` to a local path like `~/.ssh/my-key.pem`.

## Config Notes

`config.env.example` is the committed template.
`config.env` is ignored by Git and is meant for machine-specific values.

Most useful settings:

- `SERVER`: SSH target in `user@host` format
- `KEY`: optional SSH private key path
- `LOG`: nginx access log path
- `ERROR_LOG`: nginx error log path
- `FAIL2BAN_LOG`: Fail2Ban log path
- `FAIL2BAN_CLIENT_PREFIX`: optional prefix for `fail2ban-client`, for example `sudo -n`
- `NGINX_FD_PREFIX`: optional prefix for nginx fd inspection, for example `sudo -n`
- `UFW_PREFIX`: optional prefix for `ufw`, for example `sudo -n`
- `PS_PREFIX`: optional prefix for `ps`, for example `sudo -n`
- `REFRESH_SECONDS`: dashboard redraw interval
- `TOP_N`: number of top rows to show per ranked panel, default `5`
- `BURST_WINDOW_SECONDS`: short burst window
- `BURST_THRESHOLD`: request count threshold for burst alerts

Feature toggles:

- `ENABLE_ERROR_LOG=0` if you do not want nginx error log parsing
- `ENABLE_FAIL2BAN=0` if the host does not have Fail2Ban logs
- `ENABLE_UFW=0` if the host does not use UFW
- `ENABLE_SS=0` if you do not want live TCP connection counts
- `ENABLE_SYSTEM_METRICS=0` if you do not want `uptime`, `free`, `ps`, or nginx fd stats
- `ENABLE_FAIL2BAN_STATUS=0` if `fail2ban-client` is unavailable

If `fail2ban-client status` requires sudo on the server, set:

```bash
FAIL2BAN_CLIENT_PREFIX="sudo -n"
```

That requires passwordless sudo for `fail2ban-client`; `-n` makes the snapshot fail fast instead of hanging on a prompt.

If nginx fd inspection needs sudo, set:

```bash
NGINX_FD_PREFIX="sudo -n"
```

That lets the snapshot count `/proc/<nginx-pid>/fd` without changing the rest of the metric collection.

If `ufw status numbered` needs sudo, set:

```bash
UFW_PREFIX="sudo -n"
```

That allows the dashboard to read numbered UFW rules without prompting.

If the process watch commands need sudo, set:

```bash
PS_PREFIX="sudo -n"
```

That allows the dashboard to read the `ps`-based memory, thread, and gunicorn counts without prompting.

## Remote Commands

In normal remote mode, `nginx-radar` uses SSH to run commands such as:

- `tail -f /var/log/nginx/access.log`
- `tail -f /var/log/nginx/error.log`
- `tail -f /var/log/fail2ban.log`
- `ufw status numbered`
- `ss -tn state established`
- `uptime`
- `free -m`
- `ps aux --sort=-%mem | head -n 6`
- `ps -eLf | awk '/python/ && $0 !~ /awk/ {count++} END {print count+0}'`
- `ps -eo comm=,args= | awk '/gunicorn/ {count++} END {print count+0}'`
- `fail2ban-client status`

If your SSH user cannot read those logs directly, you have three practical options:

- use a user with access to the log files
- grant read access via group membership or ACLs
- disable the unavailable panels in `config.env`

## Local Testing

You can exercise the parser and dashboard without SSH:

```bash
./radar.sh --stdin
```

Example:

```bash
cat <<'EOF' | ./radar.sh --stdin
127.0.0.1 - - [13/Mar/2026:16:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8.5.0"
127.0.0.1 - - [13/Mar/2026:16:00:01 +0000] "GET /wp-admin HTTP/1.1" 404 153 "-" "curl/8.5.0"
EOF
```

For mixed local input, prefix lines by source:

- `nginx|...`
- `nginx_error|...`
- `fail2ban|...`
- `snapshot|...`

Example snapshot payload:

```text
snapshot|__SNAPSHOT_BEGIN__
snapshot|__SECTION__:UFW
snapshot|[ 1] Anywhere DENY IN 172.233.178.66
snapshot|__SNAPSHOT_END__
```

## Scanner Rules

Requests matching these patterns are flagged as suspicious:

- `.php`
- `.asp`
- `.jsp`
- `.cfm`
- `.cgi`
- `/admin`
- `/wp-admin`
- `/.env`
- `/.git`

## Common Issues

`Missing config values: SERVER`

- copy `config.env.example` to `config.env`
- set `SERVER` to a real SSH target

No data appears

- confirm nginx is writing to the configured access log
- confirm the SSH user can read the log path
- verify the configured key or SSH agent works outside the script

Panels stay empty for UFW, Fail2Ban, or metrics

- the remote host may not have those tools
- set the matching `ENABLE_*` toggle to `0`

`UFW deny` shows `0` even though `ufw status numbered` has active rules

- the remote `ufw status numbered` command may require sudo
- set `UFW_PREFIX="sudo -n"` in `config.env`
- confirm your SSH user has passwordless sudo for `ufw`

Permission denied on logs

- use a user with access, or disable the unavailable streams

## Repo Notes

- `config.env` is ignored by Git
- temporary FIFO files are ignored by Git
- `LICENSE` is MIT
