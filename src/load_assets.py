"""load_assets — 資産管理ツールのエクスポートCSVを assets.json に正規化する。

契約: README.yaml の contracts.assets_json。
方針(疎結合): 列の位置に依存せず config.assets.column_map のヘッダ名で写像。
  - display_name のみ必須。未マップ列は捨てず extra に保持。
  - 文字コードは自動判定(Shift_JIS/CP932 と UTF-8 の両対応)。
  - 必須欠損・不備行はエラーで全体停止せず、警告ログ＋スキップ。
ここでは突合しない（責務分離）。
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

# column_map のキー＝論理フィールド（出力スキーマの固定列）
LOGICAL_FIELDS = ["asset_id", "display_name", "raw_product", "version", "owner", "department"]

# CSV読込は common に集約（重複排除）。後方互換のため別名で公開。
decode_bytes = common.decode_csv_bytes
parse_csv_text = common.parse_csv_text


# ── 純粋関数（テスト対象） ────────────────────────────────

def _clean(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def map_row(raw: dict[str, str], column_map: dict[str, str], index: int) -> dict[str, Any] | None:
    """1行をヘッダ名マッピングで論理フィールドへ。display_name欠損なら None(=スキップ)。"""
    mapped: dict[str, Any] = {}
    for field in LOGICAL_FIELDS:
        header = column_map.get(field)
        mapped[field] = _clean(raw.get(header)) if header else None

    if not mapped.get("display_name"):
        return None  # 唯一の必須が無い → スキップ

    if not mapped.get("asset_id"):
        mapped["asset_id"] = f"ROW-{index}"  # 無ければ行番号で採番

    # column_map に無い列は捨てず extra に保持
    used_headers = {h for h in column_map.values() if h}
    mapped["extra"] = {k: v for k, v in raw.items() if k not in used_headers and k is not None}
    return mapped


def map_rows(rows: list[dict[str, str]], column_map: dict[str, str]) -> tuple[list[dict], list[int]]:
    """全行を写像。戻り値: (採用アイテム, スキップした行番号)。"""
    items: list[dict] = []
    skipped: list[int] = []
    for i, raw in enumerate(rows, start=1):
        item = map_row(raw, column_map, i)
        if item is None:
            skipped.append(i)
        else:
            items.append(item)
    return items, skipped


# ── オーケストレーション ────────────────────────────────

def run(config_path: str = "config.yaml", csv_override: str | None = None,
        out_override: str | None = None) -> dict:
    cfg = common.load_config(config_path)
    logger = common.get_logger("load_assets", cfg)
    acfg = cfg.get("assets", {})
    csv_path = csv_override or acfg.get("csv_path")
    out_path = out_override or acfg.get("output", "data/assets.json")
    column_map = acfg.get("column_map", {})
    encoding = acfg.get("encoding", "auto")

    data = common.resolve(csv_path).read_bytes()
    text = decode_bytes(data, encoding)
    rows = parse_csv_text(text)
    items, skipped = map_rows(rows, column_map)

    if skipped:
        logger.warning("display_name欠損でスキップした行: %s", skipped)
    logger.info("CSV %d行 → 採用 %d件 / スキップ %d件", len(rows), len(items), len(skipped))

    out = {
        "schema_version": 1,
        "source_file": Path(csv_path).name,
        "loaded_at": dt.date.today().isoformat(),
        "items": items,
    }
    common.write_json(out_path, out)
    logger.info("出力: %s", out_path)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="資産管理ツールのCSVを assets.json に正規化")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--csv", help="入力CSVの上書き")
    ap.add_argument("--out", help="出力先の上書き")
    args = ap.parse_args(argv)
    run(args.config, csv_override=args.csv, out_override=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
