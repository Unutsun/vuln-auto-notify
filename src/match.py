"""match — vulns.json × assets.json を product_aliases 経由で突合し alerts.json を出力。

契約: README.yaml の contracts.alerts_json。
突合ロジック（確度）:
  high   = alias.cpe_prefix が vuln.cpe に前方一致（最も確実）
  medium = alias の正式ベンダー＋正式製品名が vuln.vendor/product に一致
  low    = alias の正式製品名のみ vuln.product に一致（ベンダー不一致/不明）
名寄せ表で「対象外」の社内呼称に当たる資産は突合対象から除外（SaaS等）。
1資産が複数aliasに対応してよい（例: 1つの社内アプリ→tomcat と log4j）。
同一(asset,vuln)に複数当たった場合は最高確度を採用し根拠を併記。
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


# ── 純粋関数（テスト対象） ────────────────────────────────

def norm(s: str | None) -> str:
    return (s or "").strip().lower()


def load_aliases(rows: list[dict[str, str]]) -> tuple[list[dict], set[str]]:
    """aliasCSV行 → (有効aliasリスト, 対象外の社内呼称(正規化)集合)。"""
    aliases: list[dict] = []
    excluded: set[str] = set()
    for r in rows:
        name = (r.get("社内呼称") or "").strip()
        if not name:
            continue
        if (r.get("対象外") or "").strip():
            excluded.add(norm(name))
            continue
        aliases.append({
            "name": name,
            "name_norm": norm(name),
            "vendor": norm(r.get("正式ベンダー")),
            "product": norm(r.get("正式製品名")),
            "cpe_prefix": norm(r.get("cpe_prefix")),
        })
    return aliases, excluded


def aliases_for_asset(asset: dict, aliases: list[dict]) -> list[dict]:
    """資産の display_name / raw_product に一致する alias を返す。"""
    keys = {norm(asset.get("display_name")), norm(asset.get("raw_product"))}
    keys.discard("")
    return [a for a in aliases if a["name_norm"] in keys]


def match_alias_vuln(alias: dict, vuln: dict) -> tuple[str, str, str] | None:
    """1つの alias と 1件の vuln を突合。(confidence, matched_on, reason) か None。"""
    pref = alias["cpe_prefix"]
    if pref:
        for c in vuln.get("cpe", []) or []:
            cl = norm(c)
            if cl == pref or cl.startswith(pref + ":"):
                return ("high", "cpe", f"cpe_prefix '{alias['cpe_prefix']}' が vuln.cpe '{c}' に前方一致")
    av, ap = alias["vendor"], alias["product"]
    vv, vp = norm(vuln.get("vendor")), norm(vuln.get("product"))
    if av and ap and vv == av and vp == ap:
        return ("medium", "product", f"正式名 '{av}:{ap}' が vuln.vendor/product に一致")
    if ap and vp and ap == vp:
        return ("low", "alias_name", f"製品名 '{ap}' が vuln.product '{vp}' に一致（ベンダー不一致/不明）")
    return None


def build_alerts(vulns: list[dict], assets: list[dict],
                 aliases: list[dict], excluded: set[str],
                 min_confidence: str = "low") -> list[dict]:
    min_rank = CONFIDENCE_RANK.get(min_confidence, 1)
    # (asset_id, vuln_id) → 採用alert（最高確度）
    best: dict[tuple[str, str], dict] = {}
    for asset in assets:
        keys = {norm(asset.get("display_name")), norm(asset.get("raw_product"))}
        if keys & excluded:
            continue  # 対象外（SaaS等）
        asset_aliases = aliases_for_asset(asset, aliases)
        if not asset_aliases:
            continue
        for vuln in vulns:
            for alias in asset_aliases:
                hit = match_alias_vuln(alias, vuln)
                if not hit:
                    continue
                conf, matched_on, reason = hit
                if CONFIDENCE_RANK[conf] < min_rank:
                    continue
                k = (str(asset.get("asset_id")), str(vuln.get("vuln_id")))
                prev = best.get(k)
                full_reason = f"[{alias['name']}] {reason}"
                if prev is None or CONFIDENCE_RANK[conf] > CONFIDENCE_RANK[prev["confidence"]]:
                    best[k] = {
                        "alert_key": f"{asset.get('asset_id')}|{vuln.get('vuln_id')}",
                        "asset": {
                            "asset_id": asset.get("asset_id"),
                            "display_name": asset.get("display_name"),
                            "owner": asset.get("owner"),
                        },
                        "vuln": {
                            "vuln_id": vuln.get("vuln_id"),
                            "cve_ids": vuln.get("cve_ids", []),
                            "title": vuln.get("title"),
                            "cvss_score": vuln.get("cvss_score"),
                            "cvss_severity": vuln.get("cvss_severity"),
                            "link": vuln.get("link"),
                        },
                        "confidence": conf,
                        "matched_on": matched_on,
                        "match_reason": full_reason,
                    }
                elif full_reason not in prev["match_reason"]:
                    prev["match_reason"] += f" / {full_reason}"
    # 安定した並び: 確度降順 → CVSS降順
    return sorted(
        best.values(),
        key=lambda a: (-CONFIDENCE_RANK[a["confidence"]], -(a["vuln"]["cvss_score"] or 0)),
    )


# ── オーケストレーション ────────────────────────────────

def run(config_path: str = "config.yaml", out_override: str | None = None) -> dict:
    cfg = common.load_config(config_path)
    logger = common.get_logger("match", cfg)
    mcfg = cfg.get("match", {})

    vulns = (common.read_json(cfg["fetch"]["output"], default={}) or {}).get("items", [])
    assets = (common.read_json(cfg["assets"]["output"], default={}) or {}).get("items", [])
    alias_rows = common.read_csv_rows(mcfg["aliases_path"])
    aliases, excluded = load_aliases(alias_rows)

    alerts = build_alerts(vulns, assets, aliases, excluded,
                          min_confidence=mcfg.get("min_confidence", "low"))
    logger.info("vulns=%d assets=%d aliases=%d → alerts=%d",
                len(vulns), len(assets), len(aliases), len(alerts))

    out = {"schema_version": 1, "generated_at": dt.date.today().isoformat(), "items": alerts}
    common.write_json(out_override or mcfg.get("output", "data/alerts.json"), out)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="vulns × assets を突合し alerts.json を出力")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    run(args.config, out_override=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
