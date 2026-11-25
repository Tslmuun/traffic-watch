# traffic-watch

Outbound traffic watchdog for Linux servers. Watches how much data a server
sends out and emails an alert when it spikes — the classic sign that an
application was compromised and the host is being used to flood (DDoS).

Uptime checks only tell you a site is up. They cannot see a host quietly
pushing tens of terabytes out. This script can: it was written after a real
breach in which a web app vulnerability turned a server into a UDP flooder
(~44 TB out in 6 days) while every uptime check stayed green.

## Features

- **Multi-window cumulative thresholds** (5 / 15 / 30 / 60 minutes). A
  slow-but-steady flood that stays under the 5-minute limit is still
  caught by the longer windows. Example: 2 GB every 5 minutes never trips
  the 5-minute limit, but reaches 24 GB in 60 minutes and trips the
  60-minute limit.
- **Email retries + pending queue.** If sending fails, it retries, and if
  it still fails the alert is saved to a queue file and retried on the
  next run — an alert is never silently lost because the mail server was
  briefly down.
- **All real interfaces.** Monitors every interface except loopback and
  docker/veth (which would double-count container traffic). IPv6 shares
  the same NIC as IPv4, so it is already included in that interface's
  counters; multi-NIC hosts are covered too.
- **Reboot-safe.** After a reboot the kernel byte counters reset to zero.
  The script detects that (changed boot time, or a counter going
  backwards), clears the window history and starts fresh instead of
  firing a false alert.
- **Traffic history.** Every check appends a row to a CSV
  (`traffic-watch-history.csv`) with time, total bytes, delta, rate and
  per-interface counters — useful for analysing an incident afterwards.
- **Detailed alerts.** Each email names the host, detection time,
  interfaces, every triggered window with its traffic size, threshold,
  how far over it went, and the average rate in Mbps.

## Requirements

- Python 3 (standard library only, no extra packages)
- An SMTP server the host can reach (any provider works), plus a mailbox
  to send from and an address to alert

## Deployment

### 1. Copy the script

```bash
cp traffic-watch.py /root/traffic-watch.py
chmod 755 /root/traffic-watch.py
```

### 2. Create the config

Copy the example and fill in your own mailbox and password. The file
holds a password, so keep it readable only by root.

```bash
cp traffic-watch.conf.example /root/traffic-watch.conf
chmod 600 /root/traffic-watch.conf
# edit SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS / ALERT_TO
```

### 3. Test the mail channel

This sends one test email so you can confirm the alert path works
before relying on it.

```bash
python3 /root/traffic-watch.py --test
```

You should receive a message titled `[流量报警-测试] <hostname> 看门狗发信测试`.
If it does not arrive, check the SMTP settings and whether the mail
server accepted the login; the script prints send errors to stderr.

### 4. Schedule it

Run every 5 minutes. The command below adds the job without duplicating
it if you run it again.

```bash
(crontab -l 2>/dev/null | grep -v traffic-watch; \
  echo "*/5 * * * * /usr/bin/python3 /root/traffic-watch.py") | crontab -
```

### 5. Verify it is running

After the next 5-minute boundary, the state and history files should
exist and the state file's timestamp should be recent:

```bash
ls -l /root/traffic-watch-state.json /root/traffic-watch-history.csv
cat /root/traffic-watch-history.csv   # one row per check
```

## Configuration (`/root/traffic-watch.conf`)

| Key | Default | Meaning |
| --- | --- | --- |
| `SMTP_HOST` / `SMTP_PORT` | `mail.example.com` / `465` | SMTP server (SSL) |
| `SMTP_USER` / `SMTP_PASS` | | Mailbox used to send alerts |
| `SMTP_PASS` | | (see above) |
| `ALERT_TO` | | Where alerts go |
| `THRESHOLD_5MIN_GB` | `5` | Alert if > 5 GB out in 5 min |
| `THRESHOLD_15MIN_GB` | `8` | Alert if > 8 GB out in 15 min |
| `THRESHOLD_30MIN_GB` | `12` | Alert if > 12 GB out in 30 min |
| `THRESHOLD_60MIN_GB` | `20` | Alert if > 20 GB out in 60 min |
| `COOLDOWN_MIN` | `60` | At most one alert per hour |
| `RETRY_COUNT` / `RETRY_DELAY_SEC` | `3` / `5` | Mail send retries |
| `HISTORY_FILE` | `/root/traffic-watch-history.csv` | Traffic history CSV |
| `HISTORY_MAX_LINES` | `10000` | History rows kept (~35 days) |
| `PENDING_MAX` | `20` | Queued alerts kept |

Thresholds are cumulative per window. Tune them to the host: a quiet
personal server rarely sends more than a few hundred MB in 5 minutes,
so the defaults have a wide margin. A host that legitimately serves
large downloads should raise them. If a host regularly sends more than
the 5-minute limit for a legitimate reason, raise that limit rather
than disabling the check — the longer windows are the safety net for
slow floods.

## How it works

Every run (every 5 minutes) the script:

1. Reads the transmit byte counters of all real interfaces from
   `/proc/net/dev` (loopback and docker/veth excluded) and sums them.
2. Appends a sample (time, total bytes) to the state file and a row to
   the history CSV.
3. Compares the total against the sample from the start of each window
   (5 / 15 / 30 / 60 minutes ago). Any window over its threshold is
   collected.
4. If any window triggered and no alert was sent within the cooldown,
   it sends one email listing every triggered window, then retries any
   alerts that previously failed to send.

A reboot is detected by a changed boot time (`/proc/stat`) or by the
byte counter going backwards; the window history is cleared and no
alert is sent for that run.

## Files

| Path | Purpose |
| --- | --- |
| `/root/traffic-watch.py` | The watchdog |
| `/root/traffic-watch.conf` | Config (0600 — holds the mailbox password) |
| `/root/traffic-watch-state.json` | Rolling samples for the windows |
| `/root/traffic-watch-pending.json` | Alerts that failed to send (retried next run) |
| `/root/traffic-watch-history.csv` | Traffic history log |

## Troubleshooting

- **No test email arrives:** run with `--test` and read stderr. Common
  causes are a wrong SMTP password, the mail server refusing the login,
  or the host being unable to reach the SMTP port. Confirm the mailbox
  works from another client first.
- **Alert emails stop after a while:** check whether the pending queue
  (`/root/traffic-watch-pending.json`) is growing — that means sends are
  failing and being retried. Fix the mail path; the queue flushes itself
  on the next successful run.
- **False alert after a reboot:** should not happen — a reboot clears
  the history. If one fires right after a reboot, check that the state
  file was writable.
- **History file grows:** it is trimmed to `HISTORY_MAX_LINES` rows
  automatically. Raise the limit if you want a longer record.
- **A host that legitimately pushes a lot:** raise the thresholds for
  that host in its own config file; do not remove the cron job, or a
  real flood on that host will go unnoticed.

## Notes

- The script only *reads* `/proc/net/dev` and sends mail. It never blocks
  traffic or kills anything — the alert is a heads-up for a human to act on.
- A single alert email can list several triggered windows at once; the
  cooldown keeps a continuing flood from spamming the inbox.
- If the mail server is down for a long time, the pending queue is capped
  (`PENDING_MAX`) so it cannot grow without limit.
- Keep `/root/traffic-watch.conf` at 0600. It is the only file that holds
  a credential; the script and this README contain no passwords, keys,
  real addresses or hostnames.

## License

MIT
