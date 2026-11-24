"""Проверка журналов: битые строки, неизвестная версия схемы, отсутствующие поля.

Read-only: ничего не чинит и не удаляет. Код возврата 1, если есть замечания —
удобно гонять вручную. Строки без поля ``v`` считаются старым форматом и в замечания
не попадают: журналы до появления версии схемы иначе давали бы сотни «ошибок».

Запуск: ``python -m redactrail.audit_check --dir audit``.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

from .audit import RECORD_VERSION, SUPPORTED_VERSIONS

REQUIRED_REQUESTS = ("time", "masked")
REQUIRED_BLOCKS = ("time", "class", "hash", "where")


@dataclass
class Issue:
    file: str
    line: int
    problem: str


@dataclass
class Report:
    files: int = 0
    lines: int = 0
    legacy: int = 0
    issues: list[Issue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues


def check_line(record: object, name: str, number: int) -> tuple[list[Issue], bool]:
    """Вернуть замечания и признак строки старого формата (без ``v``)."""
    if not isinstance(record, dict):
        return [Issue(name, number, "строка не объект")], False
    issues: list[Issue] = []
    legacy = "v" not in record
    if not legacy and record["v"] not in SUPPORTED_VERSIONS:
        issues.append(Issue(name, number, f"версия {record['v']!r}, ожидается {RECORD_VERSION}"))
    blocks = name.startswith("blocks-")
    for key in REQUIRED_BLOCKS if blocks else REQUIRED_REQUESTS:
        if key not in record:
            issues.append(Issue(name, number, f"нет поля {key}"))
    if blocks:
        return issues, legacy
    masked = record.get("masked")
    if masked is not None and not isinstance(masked, dict):
        issues.append(Issue(name, number, "masked не объект"))
    elif isinstance(masked, dict):
        for klass, count in masked.items():
            if not isinstance(count, int) or count < 0:
                issues.append(Issue(name, number, f"masked[{klass}] не число"))
    if "bytes" in record and not isinstance(record["bytes"], int):
        issues.append(Issue(name, number, "bytes не число"))
    new = record.get("new")
    if new is not None and not isinstance(new, dict):
        issues.append(Issue(name, number, "new не объект"))
    elif isinstance(new, dict):
        for klass, values in new.items():
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                issues.append(Issue(name, number, f"new[{klass}] не список строк"))
    return issues, legacy


def check_file(path: Path) -> Report:
    report = Report(files=1)
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        report.issues.append(Issue(path.name, 0, f"не читается: {error}"))
        return report
    for number, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        report.lines += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            report.issues.append(Issue(path.name, number, f"битый JSON: {error.msg}"))
            continue
        issues, legacy = check_line(record, path.name, number)
        report.issues.extend(issues)
        if legacy:
            report.legacy += 1
    return report


def run(directory: Path, pattern: str = "*.jsonl") -> Report:
    total = Report()
    if not directory.exists():
        total.issues.append(Issue(str(directory), 0, "каталога нет"))
        return total
    for path in sorted(directory.glob(pattern)):
        part = check_file(path)
        total.files += 1
        total.lines += part.lines
        total.legacy += part.legacy
        total.issues.extend(part.issues)
    return total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверка журналов redactrail")
    parser.add_argument("--dir", default="audit")
    parser.add_argument("--pattern", default="*.jsonl")
    parser.add_argument("--quiet", action="store_true", help="только код возврата")
    args = parser.parse_args(argv)

    report = run(Path(args.dir), args.pattern)
    if not args.quiet:
        print(
            f"[audit_check] файлов {report.files}, строк {report.lines}, "
            f"старого формата {report.legacy}, замечаний {len(report.issues)}"
        )
        for issue in report.issues[:50]:
            print(f"  {issue.file}:{issue.line}: {issue.problem}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
