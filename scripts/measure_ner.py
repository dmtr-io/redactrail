"""Замер качества детекторов на размеченном корпусе.

Запуск: ``python scripts/measure_ner.py`` (или с ``--verbose``, чтобы увидеть
пропуски и ложные срабатывания). Скрипт ничего не меняет на диске и не требует
сети: корпус лежит в ``tests/corpus/ner_corpus.jsonl``.

Метрика — по сущностям, а не по символам: предсказание и эталон считаются
совпавшими, если их пересечение покрывает не меньше половины объединения (IoU).
Так «ул. Ленина, д. 15» и «г. Москва, ул. Ленина, д. 15» не считаются полным
промахом, но и «фамилия из полного ФИО» не выдаётся за точное попадание.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from redactrail import entities, ner  # noqa: E402
from redactrail.detections import Finding  # noqa: E402
from redactrail.runtime import enable_utf8_output  # noqa: E402

CORPUS = ROOT / "tests" / "corpus" / "ner_corpus.jsonl"
CLASSES = ("person", "org", "address", "phone")
IOU_THRESHOLD = 0.5


@dataclass
class Span:
    start: int
    end: int
    klass: str
    text: str

    def __str__(self) -> str:
        return f"{self.klass}:{self.text!r}"


@dataclass
class Case:
    case_id: str
    text: str
    gold: list[Span]
    predicted: list[Span] = field(default_factory=list)


def _iou(a: Span, b: Span) -> float:
    inter = max(0, min(a.end, b.end) - max(a.start, b.start))
    union = max(a.end, b.end) - min(a.start, b.start)
    return inter / union if union else 0.0


def _matched(case: Case) -> list[Span]:
    matched: list[Span] = []
    used: set[int] = set()
    for gold in case.gold:
        best_index, best_score = -1, 0.0
        for index, predicted in enumerate(case.predicted):
            if index in used or predicted.klass != gold.klass:
                continue
            score = _iou(gold, predicted)
            if score >= IOU_THRESHOLD and score > best_score:
                best_index, best_score = index, score
        if best_index >= 0:
            used.add(best_index)
            matched.append(gold)
    return matched


def load_corpus(path: Path) -> list[Case]:
    cases: list[Case] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            text = data["text"]
            gold: list[Span] = []
            for entity in data.get("entities", []):
                value = entity["value"]
                start = text.find(value)
                if start < 0:
                    raise ValueError(f"{data['id']}: нет значения {value!r} в тексте")
                if text.find(value, start + 1) >= 0:
                    raise ValueError(f"{data['id']}: значение {value!r} встречается дважды")
                gold.append(Span(start, start + len(value), entity["class"], value))
            cases.append(Case(case_id=data["id"], text=text, gold=gold))
    return cases


def predict(case: Case) -> list[Span]:
    predicted: list[Span] = []
    for finding in ner.find_ner(case.text):
        predicted.append(Span(finding.start, finding.end, finding.klass, finding.value))
    for finding in entities.find_entities(case.text):
        if finding.klass == "phone":
            predicted.append(Span(finding.start, finding.end, finding.klass, finding.value))
    return _merge_predictions(predicted)


def _merge_predictions(predicted: list[Span]) -> list[Span]:
    """Убрать дубли и пересечения предсказаний одного класса (длинное важнее)."""
    ordered = sorted(predicted, key=lambda s: (s.start, -len(s.text)))
    result: list[Span] = []
    for span in ordered:
        overlaps = [r for r in result if r.start < span.end and span.start < r.end]
        if not overlaps:
            result.append(span)
            continue
        for other in overlaps:
            if span.klass == other.klass and len(span.text) > len(other.text):
                result.remove(other)
                result.append(span)
            elif span.klass != other.klass:
                result.append(span)
    return sorted(result, key=lambda s: s.start)


def score(cases: list[Case]) -> dict[str, dict[str, float]]:
    stats: dict[str, dict[str, float]] = {
        klass: {"gold": 0, "predicted": 0, "matched": 0} for klass in CLASSES
    }
    for case in cases:
        matched = _matched(case)
        for klass in CLASSES:
            stats[klass]["gold"] += sum(1 for g in case.gold if g.klass == klass)
            stats[klass]["predicted"] += sum(1 for p in case.predicted if p.klass == klass)
            stats[klass]["matched"] += sum(1 for g in matched if g.klass == klass)
    result: dict[str, dict[str, float]] = {}
    for klass, counters in stats.items():
        gold = counters["gold"]
        predicted = counters["predicted"]
        matched = counters["matched"]
        result[klass] = {
            "gold": gold,
            "predicted": predicted,
            "matched": matched,
            "recall": matched / gold if gold else 1.0,
            "precision": matched / predicted if predicted else 1.0,
        }
    return result


def main() -> int:
    enable_utf8_output()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true", help="показать промахи")
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()

    cases = load_corpus(args.corpus)
    for case in cases:
        case.predicted = predict(case)
    metrics = score(cases)

    print(f"Корпус: {args.corpus} ({len(cases)} текстов)\n")
    print(f"{'класс':<10} {'эталон':>7} {'найдено':>8} {'верно':>6} {'recall':>7} {'prec':>6}")
    print("-" * 48)
    for klass in CLASSES:
        row = metrics[klass]
        print(
            f"{klass:<10} {int(row['gold']):>7} {int(row['predicted']):>8} "
            f"{int(row['matched']):>6} {row['recall']:>7.3f} {row['precision']:>6.3f}"
        )

    if args.verbose:
        print("\nПромахи:")
        for case in cases:
            matched = _matched(case)
            missed = [g for g in case.gold if g not in matched]
            if missed:
                print(f"\n[{case.case_id}] {case.text}")
                for gold in missed:
                    print(f"  пропущено: {gold}")
                for span in case.predicted:
                    print(f"    предсказано: {span}")
        print("\nЛожные срабатывания:")
        for case in cases:
            matched = _matched(case)
            for span in case.predicted:
                if not any(_iou(span, g) >= IOU_THRESHOLD and g.klass == span.klass for g in matched):
                    print(f"[{case.case_id}] {span}  ←  {case.text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
