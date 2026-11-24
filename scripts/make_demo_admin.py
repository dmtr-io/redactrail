"""Собрать демо-корень админки для скриншотов: только синтетические данные.

    python scripts/make_demo_admin.py --out tmp/demo-admin
    python -m redactrail.admin --root tmp/demo-admin --port 8799 --no-browser

Изображения снимаются с этого корня; реальные журналы и сессии не используются.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sys
import time
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from redactrail.runtime import enable_utf8_output


def write_json(path: pathlib.Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    enable_utf8_output()
    parser = argparse.ArgumentParser(description="Демо-данные для скриншотов админки")
    parser.add_argument("--out", default="tmp/demo-admin")
    args = parser.parse_args()
    root = pathlib.Path(args.out).resolve()
    if root.exists():
        shutil.rmtree(root)
    (root / "audit").mkdir(parents=True)
    (root / "state").mkdir(parents=True)
    shutil.copy("policy.example.json", root / "policy.json")

    today = date.today().isoformat()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    records = []
    for index in range(6):
        stamp = (now - timedelta(minutes=12 - index)).isoformat()
        records.append(
            {
                "v": 2,
                "time": stamp,
                "mode": "strict",
                "bytes": 180_000 + index * 21_000,
                "masked": {"person": 12 + index, "phone": 3, "email": 2, "secret_assign": 1},
                "new": {"person": [f"{index:010X}"], "phone": []},
                "blocked": "image" if index == 2 else None,
            }
        )
    (root / "audit" / f"{today}.jsonl").write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n",
        encoding="utf-8",
    )
    (root / "audit" / f"blocks-{today}.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"time": now.isoformat(), "class": "image", "hash": "demo0000", "length": 0, "where": "messages[4].content[1]"}),
                json.dumps({"time": (now - timedelta(minutes=4)).isoformat(), "class": "unknown_field", "hash": "demo0001", "length": 12, "where": "messages[2].content[0].output_config"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    write_json(
        root / "audit" / f"suggestions-{today}.json",
        [
            {
                "id": "demo-rule",
                "class": "phone",
                "kind": "rule_patch",
                "verdict": "предложено моделью",
                "count": 1,
                "window": "pattern: (?<!\\d)9\\d{9}(?!\\d)",
                "action": "проверить и принять правило",
                "payload": {
                    "class": "phone",
                    "pattern": "(?<!\\d)9\\d{9}(?!\\d)",
                    "flags": "",
                    "explanation": "мобильный без +7/8: ровно 10 цифр, начинается с 9",
                    "confidence": 0.8,
                },
                "evidence": {"file": "demo/session.v4.jsonl", "chunk": 0, "hash": "demo0002", "length": 10},
            },
            {
                "id": "demo-missed",
                "class": "person",
                "kind": "missed_pii",
                "verdict": "пропуск правил",
                "count": 1,
                "window": "найдено моделью в демо-сессии; значение по клику",
                "action": "посмотреть значение и добавить правило",
                "file": "demo/session.v4.jsonl",
                "chunk": 0,
                "hash": "demo0003",
                "length": 8,
            },
            {
                "id": "demo-field",
                "class": "unknown_field",
                "kind": "add_allowed_field",
                "verdict": "частое срабатывание",
                "count": 4,
                "window": "поле или тип: output_config",
                "action": "разрешить output_config",
                "payload": "output_config",
            },
        ],
    )
    write_json(
        root / "state" / "cache.json",
        {"time": now.isoformat(), "hits": 18420, "misses": 30115, "size": 32, "limit": 32},
    )
    write_json(
        root / "state" / "audit-runs.jsonl",
        [],
    )
    (root / "state" / "audit-runs.jsonl").write_text(
        json.dumps(
            {
                "id": "demo-run",
                "started": now.isoformat(),
                "finished": now.isoformat(),
                "state": "done",
                "model": "demo-model",
                "summary": {"sessions": 12, "chunks": 48, "masked_known": 31, "findings": 2, "errors": 0},
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    write_json(
        root / "audit" / f"review-{today}-demo.json",
        {
            "id": "demo",
            "date": today,
            "started_at": now.isoformat(),
            "finished_at": now.isoformat(),
            "model": "demo-model",
            "sessions": 12,
            "chunks": 48,
            "masked_known": 31,
            "cancelled": False,
            "findings": [{"session": "demo", "class": "person", "hash": "demo0003", "length": 8, "chunk": 0}],
            "errors": [],
        },
    )
    print(f"демо-корень: {root}")
    print(f"админка: python -m redactrail.admin --root {root} --port 8799 --no-browser")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
