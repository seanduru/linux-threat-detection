
#!/bin/bash

# SSH Threat Detection
# Detect 3+ failed SSH logins from one IP within 10 minutes.

set -euo pipefail

THRESHOLD=3
WINDOW=600

STATE_DIR="/var/lib/ssh-threat-detection"
STATE_FILE="$STATE_DIR/processed-events"
ALERT_STATE="$STATE_DIR/last-alerted"
ALERT_LOG="/var/log/ssh-threat-alerts.log"

mkdir -p "$STATE_DIR"
touch "$STATE_FILE" "$ALERT_STATE"

# Prevent two copies of the script running simultaneously.
exec 9>"$STATE_DIR/detection.lock"
flock -x 9

# Collect structured SSH authentication failures.
CURRENT_EVENTS=$(
    journalctl -u ssh --since "10 minutes ago" \
        -o json --no-pager |
    jq -r '
        select(.MESSAGE | startswith("Failed password")) |
        select(.__CURSOR != null and .__REALTIME_TIMESTAMP != null) |
        [.__CURSOR, .__REALTIME_TIMESTAMP,
         (.MESSAGE | capture(" from (?<ip>[^ ]+) port ").ip)] |
        @tsv
    '
)

TEMP_FILE=$(mktemp)
trap 'rm -f "$TEMP_FILE"' EXIT

# Merge journal events with previously stored events.
printf '%s\n%s\n' "$CURRENT_EVENTS" "$(cat "$STATE_FILE")" |
    awk -F '\t' 'NF == 3' |
    sort -u > "$TEMP_FILE"

# Remove events older than 10 minutes.
NOW=$(date +%s)
CUTOFF=$(( (NOW - WINDOW) * 1000000 ))

awk -F '\t' -v cutoff="$CUTOFF" \
    '$2 >= cutoff' "$TEMP_FILE" > "$STATE_FILE"

# Check each IP against the detection threshold.
awk -F '\t' '{print $3}' "$STATE_FILE" |
    sort | uniq -c |
    while read -r COUNT IP; do

        if [ "$COUNT" -ge "$THRESHOLD" ]; then

            # Identify the newest event for this IP.
            LATEST_CURSOR=$(
                awk -F '\t' -v ip="$IP" \
                    '$3 == ip {print $2 "\t" $1}' "$STATE_FILE" |
                sort -n |
                tail -n 1 |
                cut -f 2
            )

            # Find the last event already alerted on.
            PREVIOUS_CURSOR=$(
                awk -F '\t' -v ip="$IP" \
                    '$1 == ip {cursor=$2} END {print cursor}' \
                    "$ALERT_STATE"
            )

            # Alert only when a newer event exists.
            if [ "$LATEST_CURSOR" != "$PREVIOUS_CURSOR" ]; then

                echo "$(date '+%Y-%m-%d %H:%M:%S') [ALERT] $IP has $COUNT failed SSH login attempts" |
                    tee -a "$ALERT_LOG"

                printf '%s\t%s\n' "$IP" "$LATEST_CURSOR" \
                    >> "$ALERT_STATE"
            fi
        fi
    done
