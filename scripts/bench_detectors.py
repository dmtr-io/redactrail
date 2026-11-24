"""Бенчмарк детекторов: recall/precision по классам, FP на 1000 символов, латентность.

Формат корпуса — как у NER-корпуса: `{"id","text","entities":[{value,class}]}`;
допускается и `spans` с готовыми позициями.

    python scripts/bench_detectors.py --corpus tests/corpus/pii_bench.jsonl
    python scripts/bench_detectors.py --corpus ... --gate --json tmp/bench.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from redactrail import scan
from redactrail.detections import Finding
from redactrail.policy import load_policy

PUNCT = " \t.,;:()[]«»\"'"


def normalize(value: str) -> str:
    """Сравнение значений: регистр, ё, пробелы и пунктуация по краям."""
    text = value.casefold().replace("ё", "е")
    text = "".join(ch for ch in text if not ch.isspace())
    return text.strip(PUNCT)


def load_corpus(paths: list[pathlib.Path]) -> list[dict]:
    docs: list[dict] = []
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            text = data["text"]
            truth: list[tuple[str, int, int, str]] = []
            for entity in data.get("entities") or []:
                value = entity["value"]
                klass = entity["class"]
                start = text.find(value)
                if start < 0:
                    raise ValueError(f"{data['id']}: значения {value!r} нет в тексте")
                truth.append((klass, start, start + len(value), value))
            for span in data.get("spans") or []:
                truth.append((span["class"], span["start"], span["end"], text[span["start"] : span["end"]]))
            docs.append({"id": data["id"], "text": text, "truth": truth})
    return docs


def match(
    truths: list[tuple[str, int, int, str]],
    preds: list[Finding],
    mode: str,
) -> tuple[int, int, int]:
    """Вернуть TP/FP/FN для одного режима сравнения."""
    used: set[int] = set()
    tp = 0
    for klass, start, end, value in truths:
        for index, pred in enumerate(preds):
            if index in used or pred.klass != klass:
                continue
            if mode == "strict":
                ok = pred.start == start and pred.end == end
            elif mode == "overlap":
                ok = pred.start < end and start < pred.end
            else:  # value
                ok = normalize(pred.value) == normalize(value)
            if ok:
                used.add(index)
                tp += 1
                break
    fp = len(preds) - len(used)
    fn = len(truths) - tp
    return tp, fp, fn


def bench(docs: list[dict], policy) -> dict:
    classes: dict[str, dict[str, int]] = {}
    latencies: list[float] = []
    chars = 0
    total_truth = 0
    for doc in docs:
        chars += len(doc["text"])
        scan._CACHE.clear()
        started = time.perf_counter()
        preds = scan.detect(doc["text"], policy)
        latencies.append((time.perf_counter() - started) * 1000)
        by_class: dict[str, list[tuple[str, int, int, str]]] = {}
        for item in doc["truth"]:
            by_class.setdefault(item[0], []).append(item)
        pred_by_class: dict[str, list[Finding]] = {}
        for pred in preds:
            pred_by_class.setdefault(pred.klass, []).append(pred)
        for klass, truths in by_class.items():
            stats = classes.setdefault(
                klass, {"truth": 0, "tp": 0, "strict": 0, "value": 0, "fp": 0}
            )
            stats["truth"] += len(truths)
            total_truth += len(truths)
            strict_tp, _, _ = match(truths, pred_by_class.get(klass, []), "strict")
            overlap_tp, overlap_fp, _ = match(truths, pred_by_class.get(klass, []), "overlap")
            value_tp, _, _ = match(truths, pred_by_class.get(klass, []), "value")
            stats["strict"] += strict_tp
            stats["tp"] += overlap_tp
            stats["value"] += value_tp
        # ложные срабатывания считаем по всем предсказаниям классов, где есть разметка
        for klass, preds_of_class in pred_by_class.items():
            if klass not in classes:
                continue
            truth_of_class = by_class.get(klass, [])
            _, fp, _ = match(truth_of_class, preds_of_class, "overlap")
            classes[klass]["fp"] += fp
    return {"classes": classes, "chars": chars, "latencies": latencies, "truth": total_truth}


def report(result: dict) -> list[str]:
    lines: list[str] = []
    header = (
        "| class | truth | recall strict | recall overlap | recall value | "
        "precision overlap | FP/1k |"
    )
    lines.append(header)
    lines.append("|---|---|---|---|---|---|---|")
    total_tp = total_fp = total_truth = 0
    for klass, stats in sorted(result["classes"].items()):
        truth = stats["truth"] or 1
        tp = stats["tp"]
        fp = stats["fp"]
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        lines.append(
            f"| {klass} | {stats['truth']} | {stats['strict'] / truth:.2f} | {tp / truth:.2f} | "
            f"{stats['value'] / truth:.2f} | {precision:.2f} | "
            f"{(fp / result['chars'] * 1000) if result['chars'] else 0:.2f} |"
        )
        total_tp += tp
        total_fp += fp
        total_truth += stats["truth"]
    overall_recall = total_tp / (total_truth or 1)
    overall_precision = total_tp / ((total_tp + total_fp) or 1)
    latencies = sorted(result["latencies"])
    p50 = statistics.median(latencies) if latencies else 0.0
    p95 = latencies[int(len(latencies) * 0.95) - 1] if latencies else 0.0
    lines.append("")
    lines.append(
        f"документов: {len(result['latencies'])}, символов: {result['chars']}, "
        f"разметки: {total_truth}, recall: {overall_recall:.2f}, precision: {overall_precision:.2f}, "
        f"FP/1k: {total_fp / (result['chars'] or 1) * 1000:.2f}, "
        f"latency p50: {p50:.1f} мс, p95: {p95:.1f} мс"
    )
    return lines


def gate_failures(result: dict, thresholds: dict) -> list[str]:
    failures: list[str] = []
    for klass, limits in (thresholds.get("classes") or {}).items():
        stats = result["classes"].get(klass)
        if not stats or not stats["truth"]:
            failures.append(f"{klass}: нет данных в корпусе")
            continue
        recall = stats["tp"] / stats["truth"]
        precision = stats["tp"] / ((stats["tp"] + stats["fp"]) or 1)
        if "recall_overlap" in limits and recall < limits["recall_overlap"]:
            failures.append(f"{klass}: recall {recall:.2f} < {limits['recall_overlap']:.2f}")
        if "precision" in limits and precision < limits["precision"]:
            failures.append(f"{klass}: precision {precision:.2f} < {limits['precision']:.2f}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Бенчмарк детекторов PII")
    parser.add_argument("--corpus", action="append", required=True)
    parser.add_argument("--policy", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--gate", action="store_true")
    parser.add_argument(
        "--thresholds", default="tests/corpus/bench_thresholds.json"
    )
    args = parser.parse_args(argv)

    docs = load_corpus([pathlib.Path(item) for item in args.corpus])
    policy = load_policy(args.policy)
    result = bench(docs, policy)
    for line in report(result):
        print(line)
    if args.json:
        pathlib.Path(args.json).write_text(
            json.dumps({k: v for k, v in result.items() if k != "latencies"}, ensure_ascii=False, indent=2)
            + "\n",
            encoding="utf-8",
        )
    if args.gate:
        thresholds_path = pathlib.Path(args.thresholds)
        if not thresholds_path.exists():
            print(f"нет файла порогов: {thresholds_path}", file=sys.stderr)
            return 2
        thresholds = json.loads(thresholds_path.read_text(encoding="utf-8"))
        failures = gate_failures(result, thresholds)
        for failure in failures:
            print(f"ПОРОГ: {failure}", file=sys.stderr)
        return 1 if failures else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
