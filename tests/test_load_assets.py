"""load_assets の純粋関数を検証。ファイルI/Oは tmp_path / バイト列で完結。"""
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

import load_assets as la  # noqa: E402

COLUMN_MAP = {
    "asset_id": "レコードID",
    "display_name": "アプリケーション名",
    "raw_product": "製品・ベンダー",
    "version": "バージョン",
    "owner": "管理担当者",
    "department": "利用部署",
}

CSV_TEXT = (
    "レコードID,アプリケーション名,製品・ベンダー,バージョン,管理担当者,利用部署,区分,備考\n"
    "APP-001,勤怠管理,サンプル勤怠システム,,山田太郎,総務部,サーバ,オンプレ版\n"
    "APP-002,Acrobat,Adobe Acrobat Reader DC,2021.011,情シ,全社,クライアント,\n"
)


def test_decode_utf8_with_bom():
    raw = "アプリ,値\nテスト,1\n".encode("utf-8-sig")
    assert la.decode_bytes(raw, "auto").startswith("アプリ")


def test_decode_cp932_shiftjis():
    raw = "アプリ名,管理者\n勤怠,山田\n".encode("cp932")
    text = la.decode_bytes(raw, "auto")
    assert "勤怠" in text and "山田" in text


def test_decode_explicit_encoding():
    raw = "名前\n値\n".encode("cp932")
    assert la.decode_bytes(raw, "cp932").startswith("名前")


def test_map_row_basic():
    rows = la.parse_csv_text(CSV_TEXT)
    item = la.map_row(rows[0], COLUMN_MAP, 1)
    assert item["asset_id"] == "APP-001"
    assert item["display_name"] == "勤怠管理"
    assert item["raw_product"] == "サンプル勤怠システム"
    assert item["version"] is None          # 空欄 → None
    assert item["owner"] == "山田太郎"


def test_extra_keeps_unmapped_columns():
    rows = la.parse_csv_text(CSV_TEXT)
    item = la.map_row(rows[0], COLUMN_MAP, 1)
    # column_map に無い「区分」「備考」は extra に保持
    assert item["extra"]["区分"] == "サーバ"
    assert item["extra"]["備考"] == "オンプレ版"
    # マップ済みヘッダは extra に含めない
    assert "アプリケーション名" not in item["extra"]


def test_missing_display_name_skipped():
    rows = la.parse_csv_text("レコードID,アプリケーション名\nX-1,\n")
    item = la.map_row(rows[0], COLUMN_MAP, 1)
    assert item is None


def test_asset_id_autonumber_when_missing():
    # レコードID列が存在しないCSV → ROW-n で採番
    cmap = dict(COLUMN_MAP)
    rows = la.parse_csv_text("アプリケーション名,管理担当者\n基幹,鈴木\n")
    item = la.map_row(rows[0], cmap, 7)
    assert item["asset_id"] == "ROW-7"


def test_map_rows_counts_skips():
    text = (
        "レコードID,アプリケーション名\n"
        "A-1,勤怠\n"
        "A-2,\n"          # display_name 空 → スキップ
        "A-3,メール\n"
    )
    rows = la.parse_csv_text(text)
    items, skipped = la.map_rows(rows, COLUMN_MAP)
    assert [i["display_name"] for i in items] == ["勤怠", "メール"]
    assert skipped == [2]


def test_column_reorder_and_extra_column_tolerated():
    # 列順が違い、未知の列「新項目」が増えても position非依存で吸収
    text = (
        "備考,アプリケーション名,新項目,レコードID\n"
        "メモ,VPN,追加値,APP-9\n"
    )
    rows = la.parse_csv_text(text)
    item = la.map_row(rows[0], COLUMN_MAP, 1)
    assert item["display_name"] == "VPN"
    assert item["asset_id"] == "APP-9"
    assert item["extra"]["新項目"] == "追加値"


def test_run_end_to_end_with_dummy(tmp_path):
    csv_file = tmp_path / "a.csv"
    csv_file.write_text(CSV_TEXT, encoding="utf-8")
    out_file = tmp_path / "assets.json"
    result = la.run(csv_override=str(csv_file), out_override=str(out_file))
    assert result["schema_version"] == 1
    assert len(result["items"]) == 2
    assert out_file.exists()
