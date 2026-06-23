"""fetch_vulns — MyJVN API から脆弱性情報を取得し vulns.json に正規化出力する。

契約: README.yaml の contracts.vulns_json。
設計: ネットワーク取得(fetch_page)と XMLパース(parse_overview_xml)を分離し、
      パーサは固定XMLフィクスチャ単体でテストできるようにしている。

MyJVN API:
  https://jvndb.jvn.jp/myjvn?method=getVulnOverviewList&feed=hnd
  - maxCountItem 最大50 / startItem でページング
  - レスポンスは RDF/RSS XML、item に title/link/sec:identifier/sec:cpe/sec:cvss/dcterms:issued
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

API_BASE = "https://jvndb.jvn.jp/myjvn"
PAGE_SIZE = 50  # API上限
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


# ── 純粋関数（テスト対象） ────────────────────────────────

def _local(tag: str) -> str:
    """'{namespace}tag' → 'tag'。名前空間URIの差異に依存せず要素名で判定する。"""
    return tag.rsplit("}", 1)[-1]


def cpe_to_vendor_product(cpe: str) -> tuple[str | None, str | None]:
    """'cpe:/a:apache:log4j:2.14.1' → ('apache', 'log4j')。解析不能なら (None, None)。"""
    if not cpe:
        return None, None
    body = cpe.split("cpe:/", 1)[-1]          # 'a:apache:log4j:2.14.1'
    parts = body.split(":")
    vendor = parts[1] if len(parts) > 1 and parts[1] else None
    product = parts[2] if len(parts) > 2 and parts[2] else None
    return vendor, product


def extract_cve_ids(*texts: str | None) -> list[str]:
    """与えた文字列群から CVE-ID を抽出（重複排除・出現順）。"""
    found: list[str] = []
    for t in texts:
        if not t:
            continue
        for m in CVE_RE.findall(t):
            mu = m.upper()
            if mu not in found:
                found.append(mu)
    return found


def _date_only(s: str | None) -> str | None:
    """'2026-06-08T12:00:00+09:00' → '2026-06-08'。"""
    if not s:
        return None
    return s[:10]


def _pick_cvss(cvss_nodes: list[ET.Element]) -> tuple[float | None, str | None]:
    """複数の sec:cvss から代表値を選ぶ。CVSS v3系を優先、無ければ最大スコア。"""
    best_score: float | None = None
    best_sev: str | None = None
    best_is_v3 = False
    for node in cvss_nodes:
        ver = node.get("version", "")
        raw = node.get("score")
        try:
            score = float(raw) if raw not in (None, "") else None
        except ValueError:
            score = None
        sev = node.get("severity")
        is_v3 = ver.startswith("3")
        # v3優先。同条件ならスコア大を採用。
        if best_score is None:
            best_score, best_sev, best_is_v3 = score, sev, is_v3
        elif is_v3 and not best_is_v3:
            best_score, best_sev, best_is_v3 = score, sev, is_v3
        elif is_v3 == best_is_v3 and score is not None and (best_score is None or score > best_score):
            best_score, best_sev = score, sev
    return best_score, best_sev


def parse_overview_xml(xml_bytes: bytes) -> list[dict[str, Any]]:
    """getVulnOverviewList のRDF/RSSをパースし VulnItem のリストを返す（契約準拠）。"""
    root = ET.fromstring(xml_bytes)
    items: list[dict[str, Any]] = []
    for el in root.iter():
        if _local(el.tag) != "item":
            continue
        title = link = identifier = None
        cpes: list[str] = []
        cvss_nodes: list[ET.Element] = []
        issued = modified = None
        refs: list[str] = []
        for child in el:
            name = _local(child.tag)
            text = (child.text or "").strip()
            if name == "title":
                title = text
            elif name == "link":
                link = text
            elif name == "identifier":
                identifier = text
            elif name == "cpe":
                if text:
                    cpes.append(text)
            elif name == "cvss":
                cvss_nodes.append(child)
            elif name == "issued":
                issued = text
            elif name == "modified":
                modified = text
            elif name == "references":
                # CVEが references に入る場合があるので拾う
                refs.append(child.get("id", ""))
                refs.append(text)
        vendor, product = (None, None)
        for c in cpes:
            vendor, product = cpe_to_vendor_product(c)
            if vendor or product:
                break
        cvss_score, cvss_sev = _pick_cvss(cvss_nodes)
        items.append({
            "vuln_id": identifier,
            "cve_ids": extract_cve_ids(title, link, identifier, *refs),
            "title": title,
            "cpe": cpes,
            "vendor": vendor,
            "product": product,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_sev,
            "published": _date_only(issued),
            "modified": _date_only(modified),
            "link": link,
        })
    return items


def filter_by_cvss(items: list[dict], cvss_min: float | None) -> list[dict]:
    """スコア判明分で cvss_min 未満を除外。スコア不明(None)は安全側で残す。"""
    if not cvss_min:
        return items
    out = []
    for it in items:
        s = it.get("cvss_score")
        if s is None or s >= cvss_min:
            out.append(it)
    return out


# ── ネットワーク（テストではモック/オフライン入力で迂回） ──────

def build_params(start_item: int, lookback_days: int) -> dict[str, str]:
    today = dt.date.today()
    start = today - dt.timedelta(days=lookback_days)
    return {
        "method": "getVulnOverviewList",
        "feed": "hnd",
        "lang": "ja",
        "startItem": str(start_item),
        "maxCountItem": str(PAGE_SIZE),
        "datePublishedStartY": f"{start.year:04d}",
        "datePublishedStartM": f"{start.month:02d}",
        "datePublishedStartD": f"{start.day:02d}",
        "datePublishedEndY": f"{today.year:04d}",
        "datePublishedEndM": f"{today.month:02d}",
        "datePublishedEndD": f"{today.day:02d}",
    }


def fetch_page(start_item: int, lookback_days: int, timeout: int = 30) -> bytes:
    params = build_params(start_item, lookback_days)
    url = f"{API_BASE}?{urlencode(params)}"
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.content


def fetch_all(lookback_days: int, max_items: int, logger) -> list[dict]:
    """ページングして全件パース（max_items 上限）。"""
    collected: list[dict] = []
    start = 1
    while len(collected) < max_items:
        logger.info("MyJVN取得: startItem=%d", start)
        page = parse_overview_xml(fetch_page(start, lookback_days))
        if not page:
            break
        collected.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE
    return collected[:max_items]


# ── オーケストレーション ────────────────────────────────

def run(config_path: str, input_xml: str | None = None, out_override: str | None = None) -> dict:
    cfg = common.load_config(config_path)
    logger = common.get_logger("fetch_vulns", cfg)
    fcfg = cfg.get("fetch", {})
    cvss_min = fcfg.get("cvss_min")
    out_path = out_override or fcfg.get("output", "data/vulns.json")

    if input_xml:  # オフライン（テスト/再現用）: ネットワークも状態も触らない
        logger.info("オフライン入力: %s", input_xml)
        items = parse_overview_xml(common.resolve(input_xml).read_bytes())
    else:
        items = fetch_all(
            lookback_days=int(fcfg.get("lookback_days", 7)),
            max_items=int(fcfg.get("max_items", 200)),
            logger=logger,
        )

    before = len(items)
    items = filter_by_cvss(items, cvss_min)
    logger.info("取得 %d件 → CVSS>=%s で %d件", before, cvss_min, len(items))

    # 状態（差分取得）: 前回以降に公開されたものだけ残す
    if not input_xml:
        state = common.read_json(fcfg.get("state_file", "state/last_fetched.json"), default={}) or {}
        last = state.get("last_fetched")
        if last:
            kept = [it for it in items if (it.get("published") or "") >= last]
            logger.info("前回(%s)以降で %d → %d件", last, len(items), len(kept))
            items = kept
        published_dates = [it["published"] for it in items if it.get("published")]
        new_state = {
            "schema_version": 1,
            "last_fetched": max(published_dates) if published_dates else last,
            "last_vuln_id": items[0]["vuln_id"] if items else state.get("last_vuln_id"),
        }
        common.write_json(fcfg.get("state_file", "state/last_fetched.json"), new_state)

    out = {
        "schema_version": 1,
        "generated_at": dt.date.today().isoformat(),
        "items": items,
    }
    common.write_json(out_path, out)
    logger.info("出力: %s (%d件)", out_path, len(items))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="MyJVN API から脆弱性情報を取得し vulns.json を出力")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--input", help="オフラインのXMLファイルからパースのみ実行（ネットワーク/状態に触れない）")
    ap.add_argument("--out", help="出力先の上書き")
    args = ap.parse_args(argv)
    run(args.config, input_xml=args.input, out_override=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
