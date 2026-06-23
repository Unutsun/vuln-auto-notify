"""notify — alerts.json を読み、未通知分だけ Power Automate(Teams) へ POST する。

契約: README.yaml の contracts.notify_payload。
冪等: sent_ledger に通知済み alert_key を記録し、再実行で再送しない。
疎結合: Python は Webhook URL に JSON を POST するだけ。カード整形はPower Automate(GUI)側。
dry_run: 実通知せず送信予定だけ返す（台帳も更新しない）。
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Callable

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402


# ── 純粋関数（テスト対象） ────────────────────────────────

def build_payload(alert: dict) -> dict[str, Any]:
    """alert(契約) → Power Automate へ送る JSON(契約 notify_payload)。"""
    asset = alert.get("asset", {})
    vuln = alert.get("vuln", {})
    cve_ids = vuln.get("cve_ids") or []
    return {
        "schema_version": 1,
        "alert_key": alert.get("alert_key"),
        "app_name": asset.get("display_name"),
        "product": asset.get("display_name"),  # 表示用。詳細製品は reason 参照
        "owner": asset.get("owner"),
        "title": vuln.get("title"),
        "cve": cve_ids[0] if cve_ids else "",
        "cvss_score": vuln.get("cvss_score"),
        "severity": vuln.get("cvss_severity"),
        "confidence": alert.get("confidence"),
        "reason": alert.get("match_reason"),
        "link": vuln.get("link"),
    }


def ledger_keys(ledger: dict | None) -> set[str]:
    return {e.get("alert_key") for e in (ledger or {}).get("sent", [])}


def filter_unsent(alerts: list[dict], sent: set[str]) -> list[dict]:
    return [a for a in alerts if a.get("alert_key") not in sent]


# ── ネットワーク ────────────────────────────────────────

def http_post(url: str, payload: dict, timeout: int = 30) -> bool:
    resp = requests.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    return True


# ── オーケストレーション ────────────────────────────────

def run(config_path: str = "config.yaml", dry_run: bool | None = None,
        limit: int | None = None,
        poster: Callable[[str, dict], bool] = http_post) -> dict:
    cfg = common.load_config(config_path)
    common.load_dotenv()  # .env から TEAMS_WEBHOOK_URL 等を読み込む
    logger = common.get_logger("notify", cfg)
    ncfg = cfg.get("notify", {})
    if dry_run is None:
        dry_run = bool(ncfg.get("dry_run", False))

    alerts = (common.read_json(cfg["match"]["output"], default={}) or {}).get("items", [])
    ledger_path = ncfg.get("ledger_file", "state/sent_ledger.json")
    ledger = common.read_json(ledger_path, default={"schema_version": 1, "sent": []}) or {"schema_version": 1, "sent": []}
    sent = ledger_keys(ledger)

    to_send = filter_unsent(alerts, sent)
    if limit is not None and limit >= 0:
        to_send = to_send[:limit]  # テスト用: 先頭N件だけ送る
    logger.info("alerts=%d 通知済=%d 送信対象=%d dry_run=%s limit=%s",
                len(alerts), len(sent), len(to_send), dry_run, limit)

    if dry_run:
        for a in to_send:
            logger.info("[DRY] %s", a.get("alert_key"))
        return {"would_send": [a.get("alert_key") for a in to_send], "sent": 0, "dry_run": True}

    url = os.environ.get(ncfg.get("webhook_url_env", "TEAMS_WEBHOOK_URL"))
    if not url:
        logger.error("Webhook URL未設定（環境変数 %s）。送信中止。", ncfg.get("webhook_url_env"))
        return {"sent": 0, "error": "webhook_url_missing", "pending": len(to_send)}

    sent_count = 0
    for a in to_send:
        key = a.get("alert_key")
        try:
            poster(url, build_payload(a))
            ledger["sent"].append({"alert_key": key, "sent_at": common_today(), "status": "ok"})
            sent_count += 1
        except Exception as e:  # noqa: BLE001  個別失敗で全体を止めない
            logger.error("送信失敗 %s: %s", key, e)

    common.write_json(ledger_path, ledger)
    logger.info("送信 %d件 / 台帳更新: %s", sent_count, ledger_path)
    return {"sent": sent_count, "pending": len(to_send) - sent_count}


def common_today() -> str:
    import datetime as dt
    return dt.date.today().isoformat()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="alerts.json を Power Automate(Teams) へ通知")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--dry-run", action="store_true", help="送信せず予定のみ表示")
    ap.add_argument("--limit", type=int, default=None, help="先頭N件だけ送る（動作確認用）")
    args = ap.parse_args(argv)
    run(args.config, dry_run=True if args.dry_run else None, limit=args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
