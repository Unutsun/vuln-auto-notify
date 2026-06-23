"""match の突合ロジックを合成データで検証。"""
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

import match as m  # noqa: E402

ALIAS_ROWS = [
    {"社内呼称": "サンプル勤怠システム", "正式ベンダー": "apache", "正式製品名": "log4j",
     "cpe_prefix": "cpe:/a:apache:log4j", "対象外": "", "備考": ""},
    {"社内呼称": "サンプル勤怠システム", "正式ベンダー": "apache", "正式製品名": "tomcat",
     "cpe_prefix": "cpe:/a:apache:tomcat", "対象外": "", "備考": ""},
    {"社内呼称": "Acrobat", "正式ベンダー": "adobe", "正式製品名": "acrobat_reader",
     "cpe_prefix": "", "対象外": "", "備考": ""},
    {"社内呼称": "クラウド経費(SaaS)", "正式ベンダー": "", "正式製品名": "",
     "cpe_prefix": "", "対象外": "対象外", "備考": "SaaS"},
]

ASSETS = [
    {"asset_id": "APP-001", "display_name": "勤怠管理", "raw_product": "サンプル勤怠システム", "owner": "山田"},
    {"asset_id": "APP-002", "display_name": "Acrobat", "raw_product": "Adobe Acrobat Reader DC", "owner": "情シ"},
    {"asset_id": "APP-012", "display_name": "経費精算", "raw_product": "クラウド経費(SaaS)", "owner": "経理"},
]

VULN_LOG4J = {"vuln_id": "JVNDB-1", "cve_ids": ["CVE-2026-1"], "title": "Log4j RCE",
              "cpe": ["cpe:/a:apache:log4j:2.14.1"], "vendor": "apache", "product": "log4j",
              "cvss_score": 9.8, "cvss_severity": "Critical", "link": "http://x/1"}
VULN_ACROBAT = {"vuln_id": "JVNDB-2", "cve_ids": [], "title": "Acrobat bug",
                "cpe": ["cpe:/a:adobe:acrobat_reader:2021"], "vendor": "adobe", "product": "acrobat_reader",
                "cvss_score": 7.5, "cvss_severity": "High", "link": "http://x/2"}
VULN_OTHER = {"vuln_id": "JVNDB-3", "cve_ids": [], "title": "無関係",
              "cpe": ["cpe:/a:foo:bar:1"], "vendor": "foo", "product": "bar",
              "cvss_score": 8.0, "cvss_severity": "High", "link": "http://x/3"}


@pytest.fixture
def aliases_excluded():
    return m.load_aliases(ALIAS_ROWS)


def test_load_aliases_splits_excluded(aliases_excluded):
    aliases, excluded = aliases_excluded
    assert len(aliases) == 3
    assert "クラウド経費(saas)" in excluded


def test_cpe_match_is_high():
    alias = {"name": "サンプル勤怠システム", "name_norm": "サンプル勤怠システム", "vendor": "apache",
             "product": "log4j", "cpe_prefix": "cpe:/a:apache:log4j"}
    conf, on, _ = m.match_alias_vuln(alias, VULN_LOG4J)
    assert (conf, on) == ("high", "cpe")


def test_cpe_prefix_respects_boundary():
    # log4j prefix が log4j2 を誤マッチしない
    alias = {"name": "x", "name_norm": "x", "vendor": "", "product": "",
             "cpe_prefix": "cpe:/a:apache:log4j"}
    vuln = {"cpe": ["cpe:/a:apache:log4j2:1.0"], "vendor": "apache", "product": "log4j2"}
    assert m.match_alias_vuln(alias, vuln) is None


def test_product_only_is_low():
    alias = {"name": "x", "name_norm": "x", "vendor": "wrongvendor",
             "product": "log4j", "cpe_prefix": ""}
    conf, on, _ = m.match_alias_vuln(alias, VULN_LOG4J)
    assert conf == "low" and on == "alias_name"


def test_vendor_product_is_medium():
    alias = {"name": "x", "name_norm": "x", "vendor": "apache",
             "product": "log4j", "cpe_prefix": ""}
    conf, on, _ = m.match_alias_vuln(alias, VULN_LOG4J)
    assert conf == "medium" and on == "product"


def test_build_alerts_end_to_end(aliases_excluded):
    aliases, excluded = aliases_excluded
    alerts = m.build_alerts([VULN_LOG4J, VULN_ACROBAT, VULN_OTHER], ASSETS, aliases, excluded)
    keys = {a["alert_key"] for a in alerts}
    assert "APP-001|JVNDB-1" in keys      # サンプル勤怠システム×log4j(high)
    assert "APP-002|JVNDB-2" in keys      # Acrobat×acrobat(medium)
    assert all("JVNDB-3" not in k for k in keys)  # 無関係はヒットしない
    # 対象外資産APP-012は一切出ない
    assert all(not k.startswith("APP-012") for k in keys)


def test_excluded_asset_never_alerts(aliases_excluded):
    aliases, excluded = aliases_excluded
    vuln_saas = {"vuln_id": "V", "cpe": ["cpe:/a:apache:log4j:1"], "vendor": "apache",
                 "product": "log4j", "cve_ids": [], "title": "t", "cvss_score": 9.0,
                 "cvss_severity": "Critical", "link": "u"}
    # APP-012 の raw_product を log4j に偽装しても、対象外なので出ない
    assets = [{"asset_id": "APP-012", "display_name": "経費精算",
               "raw_product": "クラウド経費(SaaS)", "owner": "経理"}]
    assert m.build_alerts([vuln_saas], assets, aliases, excluded) == []


def test_min_confidence_filters_low(aliases_excluded):
    aliases, excluded = aliases_excluded
    # log4jに対しvendor不一致のaliasのみ→low。min=mediumで消える
    low_alias = [{"name": "勤怠管理", "name_norm": "勤怠管理", "vendor": "wrong",
                  "product": "log4j", "cpe_prefix": ""}]
    asset = [{"asset_id": "A", "display_name": "勤怠管理", "raw_product": "", "owner": "x"}]
    assert m.build_alerts([VULN_LOG4J], asset, low_alias, set(), "low")
    assert m.build_alerts([VULN_LOG4J], asset, low_alias, set(), "medium") == []


def test_high_confidence_wins_over_low(aliases_excluded):
    aliases, excluded = aliases_excluded
    # サンプル勤怠システムは log4j(cpe→high) と tomcat の2alias。log4j vulnには high が残る
    alerts = m.build_alerts([VULN_LOG4J], ASSETS, aliases, excluded)
    a = next(x for x in alerts if x["alert_key"] == "APP-001|JVNDB-1")
    assert a["confidence"] == "high"
