#!/usr/bin/env python3
"""
mt5_watcher.py — MT5 → REMI trade sync
Watches a MT5 CSV/report file and pushes new trades to REMI server.

Usage:
    python3 mt5_watcher.py --file "/path/to/mt5_export.csv" [--demo]

Config (edit section below or pass env vars):
    REMI_SERVER   : https://remi-server.onrender.com
    REMI_SECRET   : your app secret (from Info.plist REMI_APP_SECRET)
    POLL_INTERVAL : seconds between checks (default 30)

CSV format expected (MT5 "History" tab → right-click → Save as Report):
    Time,Symbol,Type,Volume,Price,S/L,T/P,Time,Price,Profit,Balance
    (or the MT5 detailed statement HTML converted to CSV)
"""

import os, sys, csv, json, time, hashlib, argparse, logging, urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ─── Config ───────────────────────────────────────────────────────────────────
SERVER   = os.getenv("REMI_SERVER",   "https://remi-server.onrender.com")
SECRET   = os.getenv("REMI_SECRET",   "")                 # set this!
INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))
SEEN_FILE = Path.home() / ".remi_mt5_seen.json"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [MT5→REMI] %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger()

# ─── Seen trades persistence ──────────────────────────────────────────────────

def load_seen() -> set:
    try:
        return set(json.loads(SEEN_FILE.read_text()))
    except Exception:
        return set()

def save_seen(seen: set):
    SEEN_FILE.write_text(json.dumps(list(seen)))

# ─── MT5 CSV parsing ──────────────────────────────────────────────────────────

def parse_mt5_csv(path: str) -> list[dict]:
    """Parse MT5 'Account History' CSV (closed trades only)."""
    trades = []
    try:
        with open(path, newline='', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    trade = parse_row(row)
                    if trade:
                        trades.append(trade)
                except Exception:
                    continue
    except Exception as e:
        log.error(f"Erreur lecture CSV: {e}")
    return trades

def parse_row(row: dict) -> dict | None:
    """Map a MT5 CSV row to REMI TradeRecord fields."""
    # MT5 exports vary; handle both 'Ticket' and 'Order' column names
    symbol    = (row.get("Symbol") or row.get("Symbole") or "").strip()
    type_str  = (row.get("Type") or "").strip().lower()
    profit_str = row.get("Profit") or row.get("Bénéfice") or "0"
    commission_str = row.get("Commission") or "0"
    swap_str  = row.get("Swap") or "0"
    lots_str  = row.get("Volume") or row.get("Lots") or "0"
    open_time = row.get("Time") or row.get("Open Time") or row.get("Heure")  or ""
    close_time = row.get("Time.1") or row.get("Close Time") or row.get("Heure.1") or open_time
    open_price = row.get("Price") or row.get("Open Price") or "0"
    close_price = row.get("Price.1") or row.get("Close Price") or "0"

    if not symbol or type_str in ("balance", "deposit", "withdrawal", "credit"):
        return None

    profit = float(profit_str.replace(",", ".").replace(" ", "") or 0)
    commission = float(commission_str.replace(",", ".").replace(" ", "") or 0)
    swap   = float(swap_str.replace(",", ".").replace(" ", "") or 0)
    lots   = float(lots_str.replace(",", ".").replace(" ", "") or 0.01)

    # Generate stable ID from key fields
    raw_id = f"{symbol}:{open_time}:{close_time}:{profit}"
    trade_id = hashlib.sha256(raw_id.encode()).hexdigest()[:16]

    direction = "sell" if "sell" in type_str or type_str == "short" else "buy"

    # Infer session from open time
    session = "unknown"
    try:
        hour = int(open_time[11:13]) if len(open_time) > 12 else 0
        if 7 <= hour < 12:  session = "london"
        elif 12 <= hour < 17: session = "newyork"
        elif 17 <= hour < 22: session = "asia"
        else: session = "overnight"
    except Exception:
        pass

    return {
        "id":          trade_id,
        "symbol":      symbol,
        "direction":   direction,
        "openTime":    open_time,
        "closeTime":   close_time,
        "lots":        lots,
        "openPrice":   float(open_price.replace(",", ".").replace(" ", "") or 0),
        "closePrice":  float(close_price.replace(",", ".").replace(" ", "") or 0),
        "profit":      profit,
        "commission":  commission,
        "swap":        swap,
        "isDemo":      False,
        "closeType":   "manual",
        "session":     session,
        "notes":       "",
        "setup":       "",
    }

# ─── HTTP push ────────────────────────────────────────────────────────────────

def push_trades(trades: list[dict]) -> bool:
    if not trades:
        return True
    if not SECRET:
        log.error("REMI_SECRET non configuré — impossible d'envoyer les trades")
        return False
    payload = json.dumps({"trades": trades}).encode()
    req = urllib.request.Request(
        f"{SERVER}/api/trades/push",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-app-secret": SECRET,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            log.info(f"✅ {result.get('received')} trade(s) envoyé(s) (queue: {result.get('queued')})")
            return True
    except Exception as e:
        log.error(f"Erreur push: {e}")
        return False

# ─── Main loop ────────────────────────────────────────────────────────────────

def watch(file_path: str, demo: bool = False):
    log.info(f"Surveillance de: {file_path}")
    log.info(f"Serveur: {SERVER}  |  Intervalle: {INTERVAL}s  |  Demo: {demo}")
    if not SECRET:
        log.warning("⚠️  REMI_SECRET non défini. Export: export REMI_SECRET='votre_secret'")

    seen = load_seen()

    while True:
        try:
            trades = parse_mt5_csv(file_path)
            new_trades = [t for t in trades if t["id"] not in seen]

            if new_trades:
                log.info(f"{len(new_trades)} nouveau(x) trade(s) détecté(s)")
                for t in new_trades:
                    t["isDemo"] = demo

                # Push in batches of 50
                for i in range(0, len(new_trades), 50):
                    batch = new_trades[i:i+50]
                    if push_trades(batch):
                        for t in batch:
                            seen.add(t["id"])
                        save_seen(seen)
            else:
                log.debug("Aucun nouveau trade")
        except KeyboardInterrupt:
            log.info("Arrêt.")
            break
        except Exception as e:
            log.error(f"Erreur: {e}")

        time.sleep(INTERVAL)

# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MT5 → REMI trade sync")
    parser.add_argument("--file",     required=True, help="Chemin vers le CSV MT5")
    parser.add_argument("--demo",     action="store_true", help="Marquer les trades comme démo")
    parser.add_argument("--interval", type=int, default=INTERVAL, help="Secondes entre checks")
    args = parser.parse_args()

    INTERVAL = args.interval
    watch(args.file, demo=args.demo)
