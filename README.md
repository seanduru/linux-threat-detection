# Linux Threat Detection and Security Automation

## Overview
Built an automated Linux security monitoring system to detect repeated SSH authentication failures, correlate events by source IP, and generate persistent security alerts.

## Technologies
Ubuntu Linux, Bash, auditd, systemd journal, jq, cron, SSH, Git

## Detection Architecture
1. Collect SSH authentication events from the systemd journal.
2. Parse structured JSON logs using jq.
3. Extract source IP addresses, timestamps, and journal cursors.
4. Detect three or more failed SSH logins within ten minutes.
5. Generate timestamped security alerts.
6. Track processed events to suppress duplicate alerts.
7. Execute detection automatically every minute using cron.

## Security Monitoring
Configured auditd to monitor changes to sensitive Linux identity files and investigated authentication activity using journalctl and ausearch.

## Validation
Performed controlled failed SSH authentication attempts against localhost.

Verified:
* Detection of three failed authentication attempts
* Detection of additional failures from the same IP
* Automatic execution through cron
* Persistent alert logging
* Duplicate alert suppression
* Bash syntax validation

## Example Detection
2026-11-15 17:58:01 [ALERT] 127.0.0.1 has 6 failed SSH login attempts

The IP address 127.0.0.1 represents localhost and was used for controlled testing.

## Limitations
This is an educational security engineering lab rather than a production detection platform. Future improvements could include centralized logging, notification delivery, additional detection rules, and more extensive testing.
