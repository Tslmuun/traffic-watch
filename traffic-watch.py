#!/usr/bin/env python3
"""Outbound traffic watchdog (v2).

Monitors outbound traffic on all real network interfaces and alerts by email
when it exceeds thresholds. Designed to catch a compromised host flooding
outbound traffic (e.g. a DDoS bot), which uptime checks cannot see.

Features:
- Multi-window cumulative thresholds (5/15/30/60 min), so a slow-but-steady
  flood that stays under the 5-minute limit is still caught by longer windows.
- Email send retries + a persistent pending queue: a failed send is retried
  on the next run instead of being lost.
- Monitors every real interface (loopback and docker/veth interfaces are
  excluded), so IPv6 and multi-NIC traffic are not missed. IPv6 shares the
  same NIC as IPv4, so it is already included in that interface's counters.
- Reboot-safe: a counter reset (or a changed boot time) clears the window
  history instead of producing a false alert.
- Traffic history is logged to a CSV for later analysis.
- Alert emails include interface, window, traffic size, average rate,
  detection time and how far over the threshold it went.

Run every 5 minutes via cron:
    */5 * * * * /usr/bin/python3 /root/traffic-watch.py

Config: /root/traffic-watch.conf (0600)
State:  /root/traffic-watch-state.json
Pending alerts: /root/traffic-watch-pending.json
History: /root/traffic-watch-history.csv (path is configurable)
Usage: traffic-watch.py [--test]  (--test sends a test alert email)
"""
import csv
import json
import os
import smtplib
import ssl
import sys
import time
from datetime import datetime, timezone
from email.message import EmailMessage

CONF = "/root/traffic-watch.conf"
STATE_FILE = "/root/traffic-watch-state.json"
PENDING_FILE = "/root/traffic-watch-pending.json"

DEFAULTS = {
    "SMTP_HOST": "mail.example.com",
    "SMTP_PORT": "465",
    "SMTP_USER": "alerts@example.com",
    "SMTP_PASS": "",
    "ALERT_TO": "you@example.com",
    # Cumulative outbound thresholds per window (GB in that window).
    "THRESHOLD_5MIN_GB": "5",
    "THRESHOLD_15MIN_GB": "8",
    "THRESHOLD_30MIN_GB": "12",
    "THRESHOLD_60MIN_GB": "20",
    "COOLDOWN_MIN": "60",
    "RETRY_COUNT": "3",
    "RETRY_DELAY_SEC": "5",
    "HISTORY_FILE": "/root/traffic-watch-history.csv",
    "HISTORY_MAX_LINES": "10000",
    "PENDING_MAX": "20",
}

# Interfaces that never carry internet-bound traffic (or would double-count it).
EXCLUDE_PREFIXES = ("lo", "docker0", "br-", "veth")


def load_conf():
    cfg = dict(DEFAULTS)
    if os.path.exists(CONF):
        with open(CONF) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


def read_interfaces():
    """Return {iface: tx_bytes} for every real (non-excluded) interface."""
    out = {}
    with open("/proc/net/dev") as f:
        for line in f:
            parts = line.split(":")
            if len(parts) != 2:
                continue
            iface = parts[0].strip()
            if any(iface == p or iface.startswith(p) for p in EXCLUDE_PREFIXES):
                continue
            fields = parts[1].split()
            if len(fields) >= 9:
                out[iface] = int(fields[8])  # TX bytes
    return out


def get_boot_time():
    """Boot time (seconds since epoch) from /proc/stat, or 0 if unknown."""
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime"):
                    return int(line.split()[1])
    except Exception:
        pass
    return 0


def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                st = json.load(f)
            st.setdefault("boot_time", 0)
            st.setdefault("samples", [])
            st.setdefault("last_alert", 0)
            return st
        except Exception:
            pass
    return {"boot_time": 0, "samples": [], "last_alert": 0}


def save_state(st):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, STATE_FILE)


def load_pending():
    if os.path.exists(PENDING_FILE):
        try:
            with open(PENDING_FILE) as f:
                items = json.load(f)
            if isinstance(items, list):
                return items
        except Exception:
            pass
    return []


def save_pending(items):
    tmp = PENDING_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(items, f)
    os.replace(tmp, PENDING_FILE)


def send_mail_once(cfg, subject, body):
    msg = EmailMessage()
    msg["From"] = cfg["SMTP_USER"]
    msg["To"] = cfg["ALERT_TO"]
    msg["Subject"] = subject
    msg.set_content(body)
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(cfg["SMTP_HOST"], int(cfg["SMTP_PORT"]),
                          context=ctx, timeout=30) as s:
        s.login(cfg["SMTP_USER"], cfg["SMTP_PASS"])
        s.send_message(msg)


def send_mail(cfg, subject, body):
    """Send with retries. Returns True on success, False after all retries."""
    retries = int(cfg["RETRY_COUNT"])
    delay = float(cfg["RETRY_DELAY_SEC"])
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            send_mail_once(cfg, subject, body)
            return True
        except Exception as e:
            last_err = e
            print(f"mail attempt {attempt}/{retries} failed: {e}", file=sys.stderr)
            if attempt < retries:
                time.sleep(delay)
    print(f"mail failed after {retries} attempts: {last_err}", file=sys.stderr)
    return False


def queue_pending(cfg, subject, body, now):
    items = load_pending()
    items.append({"subject": subject, "body": body, "queued_at": now,
                  "attempts": 0})
    # Bound the queue so a long mail outage cannot grow it without limit.
    max_n = int(cfg["PENDING_MAX"])
    if len(items) > max_n:
        items = items[-max_n:]
        print(f"pending queue trimmed to {max_n}", file=sys.stderr)
    save_pending(items)


def flush_pending(cfg):
    """Retry any alerts that previously failed to send. Returns count sent."""
    items = load_pending()
    if not items:
        return 0
    remaining = []
    sent = 0
    for it in items:
        it["attempts"] = it.get("attempts", 0) + 1
        if send_mail(cfg, it["subject"], it["body"]):
            sent += 1
        else:
            remaining.append(it)
    save_pending(remaining)
    return sent


def append_history(cfg, now, total_tx, delta, elapsed, ifaces):
    path = cfg["HISTORY_FILE"]
    is_new = not os.path.exists(path)
    rate_mbps = (delta * 8 / elapsed / 1e6) if elapsed > 0 else 0.0
    ts = datetime.fromtimestamp(now, tz=timezone.utc).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z")
    iface_str = ";".join(f"{k}={v}" for k, v in sorted(ifaces.items()))
    try:
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if is_new:
                w.writerow(["time", "total_tx_bytes", "delta_bytes",
                            "elapsed_sec", "rate_mbps", "interfaces"])
            w.writerow([ts, total_tx, delta, round(elapsed, 1),
                        round(rate_mbps, 2), iface_str])
        # Trim: keep only the most recent HISTORY_MAX_LINES data rows.
        max_lines = int(cfg["HISTORY_MAX_LINES"])
        with open(path) as f:
            lines = f.readlines()
        if len(lines) > max_lines + 1:
            with open(path, "w") as f:
                f.writelines([lines[0]] + lines[-(max_lines):])
    except Exception as e:
        print(f"history write failed: {e}", file=sys.stderr)


def fmt_gb(nbytes):
    return f"{nbytes / (1024 ** 3):.2f} GB"


def build_alert_body(hostname, now, ifaces, triggered, total_tx):
    dt = datetime.fromtimestamp(now, tz=timezone.utc).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z")
    lines = [
        f"服务器 {hostname} 外发流量异常，请立即检查。",
        "",
        f"检测时间：{dt}",
        f"监控网卡：{', '.join(sorted(ifaces))}（已排除 lo 与 docker/veth）",
        f"当前累计外发：{fmt_gb(total_tx)}",
        "",
        "触发的窗口：",
    ]
    for t in triggered:
        lines.append(
            f"  - {t['label']}：外发 {fmt_gb(t['delta'])}，"
            f"阈值 {fmt_gb(t['threshold'])}，"
            f"超标 {fmt_gb(t['delta'] - t['threshold'])}"
            f"（{t['delta'] / t['threshold']:.1f} 倍），"
            f"平均速率 {t['rate_mbps']:.1f} Mbps"
        )
    lines += [
        "",
        "可能原因：应用被入侵后对外发包（DDoS 木马）、异常备份或大文件外传。",
        "建议：查看各容器/进程的网络占用，确认是否有未知进程在外发流量。",
    ]
    return "\n".join(lines) + "\n"


def main():
    cfg = load_conf()
    hostname = os.uname().nodename
    now = time.time()

    if "--test" in sys.argv:
        send_mail(cfg, f"[流量报警-测试] {hostname} 看门狗发信测试",
                  f"这是 {hostname} 上流量看门狗的测试邮件，说明发信通道正常。\n")
        print("test mail sent")
        return

    # First, retry anything that failed to send on an earlier run.
    flushed = flush_pending(cfg)
    if flushed:
        print(f"flushed {flushed} pending alert(s)")

    ifaces = read_interfaces()
    total_tx = sum(ifaces.values())
    boot_time = get_boot_time()
    st = load_state()

    # Reboot / counter reset: boot time changed, or the counter went backwards.
    last_tx = st["samples"][-1][1] if st["samples"] else None
    rebooted = False
    if st["boot_time"] and boot_time and boot_time != st["boot_time"]:
        rebooted = True
    if last_tx is not None and total_tx < last_tx:
        rebooted = True
    if rebooted:
        print("counter reset (reboot) detected; clearing window history")
        st["samples"] = []
        st["boot_time"] = boot_time
        # Record the new baseline in history with a zero delta.
        append_history(cfg, now, total_tx, 0, 0, ifaces)
        save_state(st)
        return

    # Record this sample.
    prev_tx = st["samples"][-1][1] if st["samples"] else total_tx
    prev_ts = st["samples"][-1][0] if st["samples"] else now
    elapsed = max(now - prev_ts, 1)
    delta = max(total_tx - prev_tx, 0)
    st["samples"].append([now, total_tx])
    # Keep ~70 minutes of samples (covers the 60-minute window).
    st["samples"] = [s for s in st["samples"] if s[0] >= now - 70 * 60]
    st["boot_time"] = boot_time
    append_history(cfg, now, total_tx, delta, elapsed, ifaces)

    # Evaluate each window: delta vs the sample at (or just before) its start.
    windows = [
        ("5 分钟", 5 * 60, float(cfg["THRESHOLD_5MIN_GB"]) * (1024 ** 3)),
        ("15 分钟", 15 * 60, float(cfg["THRESHOLD_15MIN_GB"]) * (1024 ** 3)),
        ("30 分钟", 30 * 60, float(cfg["THRESHOLD_30MIN_GB"]) * (1024 ** 3)),
        ("60 分钟", 60 * 60, float(cfg["THRESHOLD_60MIN_GB"]) * (1024 ** 3)),
    ]
    triggered = []
    for label, span, threshold in windows:
        start = now - span
        # Most recent sample at or before the window start.
        base = None
        for ts, tx in st["samples"]:
            if ts <= start:
                base = tx
            else:
                break
        if base is None:
            continue  # not enough history for this window yet
        wdelta = total_tx - base
        if wdelta > threshold:
            triggered.append({
                "label": label,
                "delta": wdelta,
                "threshold": threshold,
                "rate_mbps": wdelta * 8 / span / 1e6,
            })

    cooldown = float(cfg["COOLDOWN_MIN"]) * 60
    if triggered and (now - st.get("last_alert", 0)) > cooldown:
        subject = f"[流量报警] {hostname} 外发流量异常"
        body = build_alert_body(hostname, now, ifaces, triggered, total_tx)
        if send_mail(cfg, subject, body):
            st["last_alert"] = now
            print("alert sent")
        else:
            queue_pending(cfg, subject, body, now)
            print("alert queued for retry (mail failed)")

    save_state(st)


if __name__ == "__main__":
    main()
