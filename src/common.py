"""全モジュール共通のユーティリティ（設定読込・ロギング・JSON入出力）。

各モジュール(fetch_vulns/load_assets/match/notify)から再利用する。
ここにビジネスロジックは置かない。
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
from pathlib import Path
from typing import Any

import yaml


def project_root() -> Path:
    """このファイル(src/common.py)の1つ上＝プロジェクトルート。"""
    return Path(__file__).resolve().parent.parent


def resolve(path: str | os.PathLike) -> Path:
    """設定中の相対パスをプロジェクトルート基準の絶対パスへ。"""
    p = Path(path)
    return p if p.is_absolute() else project_root() / p


def load_config(config_path: str | os.PathLike = "config.yaml") -> dict[str, Any]:
    with open(resolve(config_path), encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_dotenv(path: str | os.PathLike = ".env") -> None:
    """プロジェクト直下の .env を読み環境変数へ。既存の環境変数は上書きしない。
    依存ライブラリ不要の軽量実装（KEY=VALUE 形式、# はコメント）。"""
    p = resolve(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def get_logger(name: str, cfg: dict | None = None) -> logging.Logger:
    """コンソール＋（設定があれば）ファイルへ出力するロガー。"""
    logger = logging.getLogger(name)
    if logger.handlers:  # 二重登録防止
        return logger
    level = (cfg or {}).get("logging", {}).get("level", "INFO")
    logger.setLevel(level)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    log_path = (cfg or {}).get("logging", {}).get("path")
    if log_path:
        p = resolve(log_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(p, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


def decode_csv_bytes(data: bytes, encoding: str = "auto") -> str:
    """CSVバイト列を文字列へ。auto は UTF-8(BOM可)→CP932(Shift_JIS) の順に試す。"""
    if encoding and encoding != "auto":
        return data.decode(encoding)
    for enc in ("utf-8-sig", "cp932"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def parse_csv_text(text: str) -> list[dict[str, str]]:
    """ヘッダ付きCSVテキスト → 行(dict)のリスト。"""
    return [dict(row) for row in csv.DictReader(io.StringIO(text))]


def read_csv_rows(path: str | os.PathLike, encoding: str = "auto") -> list[dict[str, str]]:
    data = resolve(path).read_bytes()
    return parse_csv_text(decode_csv_bytes(data, encoding))


def read_json(path: str | os.PathLike, default: Any = None) -> Any:
    p = resolve(path)
    if not p.exists():
        return default
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str | os.PathLike, data: Any) -> None:
    p = resolve(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
