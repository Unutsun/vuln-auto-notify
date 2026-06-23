"""run_all — fetch_vulns → load_assets → match → notify を順に実行する薄いオーケストレータ。

Windowsタスクスケジューラから1日1回呼ぶ想定:
    python src/run_all.py
各段は中間JSON(契約)経由で疎結合なので、--skip-fetch 等で部分実行も可能。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402
import fetch_vulns
import load_assets
import match
import notify


def run(config_path: str = "config.yaml", dry_run: bool | None = None,
        skip_fetch: bool = False) -> dict:
    cfg = common.load_config(config_path)
    logger = common.get_logger("run_all", cfg)

    if skip_fetch:
        logger.info("fetch_vulns スキップ（既存 vulns.json を使用）")
    else:
        logger.info("== fetch_vulns ==")
        fetch_vulns.run(config_path)

    logger.info("== load_assets ==")
    load_assets.run(config_path)

    logger.info("== match ==")
    alerts = match.run(config_path)

    logger.info("== notify ==")
    result = notify.run(config_path, dry_run=dry_run)

    logger.info("完了: alerts=%d notify=%s", len(alerts.get("items", [])), result)
    return {"alerts": len(alerts.get("items", [])), "notify": result}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="脆弱性自動通知パイプライン一括実行")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--dry-run", action="store_true", help="通知は送信せず予定のみ")
    ap.add_argument("--skip-fetch", action="store_true", help="MyJVN取得を省略し既存vulns.jsonを使う")
    args = ap.parse_args(argv)
    run(args.config, dry_run=True if args.dry_run else None, skip_fetch=args.skip_fetch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
