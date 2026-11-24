"""Общие помощники тестов: загрузка корпуса и метрика качества.

Метрика та же, что в `scripts/measure_ner.py`: сущность считается найденной,
если предсказание пересекается с эталоном не меньше чем на половину объединения.
"""

from __future__ import annotations

import json
import shutil
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
SCRATCH_ROOT = ROOT / "tmp" / "tests"
IOU_THRESHOLD = 0.5


def source_policy() -> Path:
    """Локальная политика, если она есть, иначе публичный пример.

    Тесты и CI не должны зависеть от `policy.json`: он не публикуется.
    """
    local = ROOT / "policy.json"
    return local if local.exists() else ROOT / "policy.example.json"


@contextmanager
def scratch_dir() -> Iterator[Path]:
    """Временный каталог внутри рабочей папки проекта, а не в системном Temp.

    Системный Temp на этой машине закрыт песочницей: каталог создаётся, но файлы
    в нём — нет. `tmp/` уже в `.gitignore`, поэтому мусор в репозиторий не попадёт.
    """
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    path = SCRATCH_ROOT / uuid.uuid4().hex
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    klass: str
    text: str


@dataclass
class Case:
    case_id: str
    text: str
    gold: list[Span]
    predicted: list[Span] = field(default_factory=list)


def load_corpus(name: str) -> list[Case]:
    path = CORPUS_DIR / name
    cases: list[Case] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
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
                    raise ValueError(f"{data['id']}: нет {value!r} в тексте")
                if text.find(value, start + 1) >= 0:
                    raise ValueError(f"{data['id']}: {value!r} встречается дважды")
                gold.append(Span(start, start + len(value), entity["class"], value))
            cases.append(Case(case_id=data["id"], text=text, gold=gold))
    return cases


def iou(a: Span, b: Span) -> float:
    inter = max(0, min(a.end, b.end) - max(a.start, b.start))
    union = max(a.end, b.end) - min(a.start, b.start)
    return inter / union if union else 0.0


def match(case: Case) -> list[Span]:
    matched: list[Span] = []
    used: set[int] = set()
    for gold in case.gold:
        best_index, best_score = -1, 0.0
        for index, predicted in enumerate(case.predicted):
            if index in used or predicted.klass != gold.klass:
                continue
            score = iou(gold, predicted)
            if score >= IOU_THRESHOLD and score > best_score:
                best_index, best_score = index, score
        if best_index >= 0:
            used.add(best_index)
            matched.append(gold)
    return matched


def predict_ner(text: str) -> list[Span]:
    """Предсказания детекторов для замера качества NER.

    Телефоны берутся из детерминированных правил, остальное — из `ner.py`:
    так измеряется именно то, что отвечает за свободный текст.
    """
    from redactrail import entities, ner

    spans = [Span(f.start, f.end, f.klass, f.value) for f in ner.find_ner(text)]
    spans.extend(
        Span(f.start, f.end, f.klass, f.value)
        for f in entities.find_entities(text)
        if f.klass == "phone"
    )
    ordered = sorted(spans, key=lambda s: (s.start, -len(s.text)))
    result: list[Span] = []
    for span in ordered:
        overlapping = [r for r in result if r.start < span.end and span.start < r.end]
        if not overlapping:
            result.append(span)
            continue
        for other in overlapping:
            if span.klass == other.klass and len(span.text) > len(other.text):
                result.remove(other)
                result.append(span)
            elif span.klass != other.klass:
                result.append(span)
    return sorted(result, key=lambda s: s.start)


def quality(cases: list[Case], klass: str) -> tuple[float, float]:
    """Вернуть (recall, precision) по классу."""
    gold_total = predicted_total = matched_total = 0
    for case in cases:
        matched = match(case)
        gold_total += sum(1 for g in case.gold if g.klass == klass)
        predicted_total += sum(1 for p in case.predicted if p.klass == klass)
        matched_total += sum(1 for g in matched if g.klass == klass)
    recall = matched_total / gold_total if gold_total else 1.0
    precision = matched_total / predicted_total if predicted_total else 1.0
    return recall, precision


def load_predict(name: str) -> list[Case]:
    cases = load_corpus(name)
    for case in cases:
        case.predicted = predict_ner(case.text)
    return cases
