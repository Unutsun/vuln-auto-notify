"""notify の純粋関数＋dry-run＋冪等送信(posterを注入)を検証。ネットワーク非依存。"""
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

import notify as n  # noqa: E402
import common  # noqa: E402

ALERT = {
    "alert_key": "APP-001|JVNDB-1",
    "asset": {"asset_id": "APP-001", "display_name": "勤怠管理", "owner": "山田"},
    "vuln": {"vuln_id": "JVNDB-1", "cve_ids": ["CVE-2026-1"], "title": "Log4j RCE",
             "cvss_score": 9.8, "cvss_severity": "Critical", "link": "http://x/1"},
    "confidence": "high", "matched_on": "cpe", "match_reason": "[サンプル勤怠システム] cpe一致",
}


def test_build_payload_contract():
    p = n.build_payload(ALERT)
    assert p["schema_version"] == 1
    assert p["alert_key"] == "APP-001|JVNDB-1"
    assert p["app_name"] == "勤怠管理"
    assert p["cve"] == "CVE-2026-1"
    assert p["cvss_score"] == 9.8
    assert p["severity"] == "Critical"
    assert p["confidence"] == "high"
    assert p["link"] == "http://x/1"


def test_build_payload_empty_cve():
    a = dict(ALERT, vuln=dict(ALERT["vuln"], cve_ids=[]))
    assert n.build_payload(a)["cve"] == ""


def test_filter_unsent():
    alerts = [ALERT, dict(ALERT, alert_key="APP-002|JVNDB-2")]
    sent = {"APP-001|JVNDB-1"}
    out = n.filter_unsent(alerts, sent)
    assert [a["alert_key"] for a in out] == ["APP-002|JVNDB-2"]


def test_ledger_keys():
    led = {"sent": [{"alert_key": "A"}, {"alert_key": "B"}]}
    assert n.ledger_keys(led) == {"A", "B"}
    assert n.ledger_keys(None) == set()


def _write_min_project(tmp_path):
    """tmp配下に alerts.json と config を用意し config_path を返す。"""
    (tmp_path / "data").mkdir()
    common.write_json(tmp_path / "data" / "alerts.json",
                      {"schema_version": 1, "items": [ALERT,
                       dict(ALERT, alert_key="APP-002|JVNDB-2")]})
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "match:\n  output: '%s'\n"
        "notify:\n  webhook_url_env: 'TEAMS_WEBHOOK_URL'\n  ledger_file: '%s'\n  dry_run: false\n"
        "logging:\n  level: 'INFO'\n"
        % ((tmp_path / "data" / "alerts.json").as_posix(),
           (tmp_path / "state" / "sent_ledger.json").as_posix()),
        encoding="utf-8",
    )
    return str(cfg)


def test_dry_run_does_not_send_or_write_ledger(tmp_path):
    cfg = _write_min_project(tmp_path)
    res = n.run(cfg, dry_run=True)
    assert res["dry_run"] is True
    assert set(res["would_send"]) == {"APP-001|JVNDB-1", "APP-002|JVNDB-2"}
    assert not (tmp_path / "state" / "sent_ledger.json").exists()  # 台帳は触らない


def test_idempotent_send_with_injected_poster(tmp_path, monkeypatch):
    cfg = _write_min_project(tmp_path)
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "http://example.test/hook")
    calls = []

    def fake_poster(url, payload):
        calls.append(payload["alert_key"])
        return True

    res1 = n.run(cfg, dry_run=False, poster=fake_poster)
    assert res1["sent"] == 2
    assert set(calls) == {"APP-001|JVNDB-1", "APP-002|JVNDB-2"}

    # 2回目: 台帳済みなので再送ゼロ（冪等）
    calls.clear()
    res2 = n.run(cfg, dry_run=False, poster=fake_poster)
    assert res2["sent"] == 0
    assert calls == []


def test_missing_webhook_url_aborts(tmp_path, monkeypatch):
    cfg = _write_min_project(tmp_path)
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    # 開発者ローカルの .env が run() 内の load_dotenv() で TEAMS_WEBHOOK_URL を
    # 復活させると「URL未設定」条件が成立しない。読込を無効化して純粋に検証する。
    monkeypatch.setattr(n.common, "load_dotenv", lambda *a, **k: None)
    res = n.run(cfg, dry_run=False)
    assert res.get("error") == "webhook_url_missing"
