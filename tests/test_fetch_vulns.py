"""fetch_vulns の純粋関数（パース/抽出/フィルタ）をフィクスチャXMLで検証する。
ネットワークには一切アクセスしない。"""
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

import fetch_vulns as fv  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "overview_sample.xml"


@pytest.fixture
def items():
    return fv.parse_overview_xml(FIXTURE.read_bytes())


def test_parse_count(items):
    assert len(items) == 3


def test_first_item_fields(items):
    it = items[0]
    assert it["vuln_id"] == "JVNDB-2026-001234"
    assert it["title"].startswith("Apache Log4j")
    assert it["link"].endswith("JVNDB-2026-001234.html")
    assert it["published"] == "2026-06-08"      # 時刻・TZが落ちて日付のみ
    assert it["modified"] == "2026-06-09"


def test_cpe_list_and_vendor_product(items):
    it = items[0]
    assert it["cpe"] == ["cpe:/a:apache:log4j:2.14.1", "cpe:/a:apache:tomcat:9.0.30"]
    assert it["vendor"] == "apache"
    assert it["product"] == "log4j"             # 最初のCPE由来


def test_cvss_prefers_v3(items):
    it = items[0]
    assert it["cvss_score"] == 9.8              # v2(6.8)ではなくv3(9.8)
    assert it["cvss_severity"] == "Critical"


def test_cve_extracted_from_references(items):
    assert items[0]["cve_ids"] == ["CVE-2026-12345"]


def test_item_without_cvss_has_none(items):
    it = items[2]
    assert it["vuln_id"] == "JVNDB-2026-000500"
    assert it["cvss_score"] is None
    assert it["cve_ids"] == []                  # CVE記載なし→空配列(契約で許容)


def test_cpe_to_vendor_product():
    assert fv.cpe_to_vendor_product("cpe:/a:apache:log4j:2.14.1") == ("apache", "log4j")
    assert fv.cpe_to_vendor_product("cpe:/o:fortinet:fortios") == ("fortinet", "fortios")
    assert fv.cpe_to_vendor_product("") == (None, None)
    assert fv.cpe_to_vendor_product("cpe:/a:apache") == ("apache", None)


def test_extract_cve_ids():
    out = fv.extract_cve_ids("見出し CVE-2026-0001", None, "再掲 cve-2026-0001 CVE-2025-12345")
    assert out == ["CVE-2026-0001", "CVE-2025-12345"]


def test_filter_by_cvss(items):
    kept = fv.filter_by_cvss(items, 7.0)
    ids = [it["vuln_id"] for it in kept]
    assert "JVNDB-2026-001234" in ids           # 9.8 残る
    assert "JVNDB-2026-000999" not in ids        # 3.5 除外
    assert "JVNDB-2026-000500" in ids            # None は安全側で残す
    assert len(kept) == 2


def test_filter_by_cvss_none_passthrough(items):
    assert fv.filter_by_cvss(items, None) == items


def test_build_params_shape():
    p = fv.build_params(51, 7)
    assert p["method"] == "getVulnOverviewList"
    assert p["feed"] == "hnd"
    assert p["startItem"] == "51"
    assert p["maxCountItem"] == "50"
    # 日付パラメータが Y/M/D に分かれて入っている
    for k in ("datePublishedStartY", "datePublishedStartM", "datePublishedStartD"):
        assert k in p
