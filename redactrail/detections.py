"""Находки детекторов и правила разрешения пересечений.

Детекторы работают независимо друг от друга: правило телефонов ничего не знает
о правилах ИНН, а NER — о секретах. Пересечения неизбежны («ИП Иванов И.И.» — это
и организация, и человек; номер карты может лежать внутри длинного числа).
Разрешение вынесено сюда, чтобы порядок был один и тот же для всех детекторов
и проверялся тестами отдельно от них.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Sequence

MASK = "mask"
BLOCK = "block"
ALLOW = "allow"
ACTIONS = (MASK, BLOCK, ALLOW)

#: Чем больше число, тем важнее действие: блокировка сильнее маскировки.
_ACTION_RANK = {ALLOW: 0, MASK: 1, BLOCK: 2}


@dataclass(frozen=True)
class Finding:
    """Найденный фрагмент: полуинтервал ``[start, end)`` в исходном тексте."""

    start: int
    end: int
    klass: str
    value: str = ""

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ValueError("start не может быть отрицательным")
        if self.end < self.start:
            raise ValueError("end меньше start")

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "Finding") -> bool:
        return self.start < other.end and other.start < self.end

    def __str__(self) -> str:  # pragma: no cover - отладочный вывод
        return f"{self.klass}[{self.start}:{self.end}]={self.value!r}"


def _rank(finding: Finding, actions: Mapping[str, str]) -> int:
    return _ACTION_RANK.get(actions.get(finding.klass, MASK), 1)


def _resolve_group(
    group: Sequence[Finding], actions: Mapping[str, str]
) -> list[Finding]:
    """Выбрать победителя в одной связной группе пересекающихся находок.

    Проигравшие не выбрасываются целиком: если находка выходит за пределы
    победителя, её «хвосты» остаются отдельными интервалами. Иначе блокировка
    внутри длинной маскированной фразы оставила бы её хвост открытым.
    """
    winner_index = max(
        range(len(group)),
        key=lambda i: (_rank(group[i], actions), group[i].length, -group[i].start),
    )
    winner = group[winner_index]
    result = [winner]
    for index, finding in enumerate(group):
        if index == winner_index:
            continue
        if finding.start < winner.start:
            result.append(
                Finding(finding.start, winner.start, finding.klass, finding.value)
            )
        if finding.end > winner.end:
            result.append(
                Finding(winner.end, finding.end, finding.klass, finding.value)
            )
    return result


def _pass(items: Sequence[Finding], actions: Mapping[str, str]) -> list[Finding]:
    ordered = sorted(items, key=lambda f: (f.start, -f.length))
    out: list[Finding] = []
    index = 0
    while index < len(ordered):
        group = [ordered[index]]
        end = ordered[index].end
        cursor = index + 1
        while cursor < len(ordered) and ordered[cursor].start < end:
            group.append(ordered[cursor])
            end = max(end, ordered[cursor].end)
            cursor += 1
        if len(group) == 1:
            out.append(group[0])
        else:
            out.extend(_resolve_group(group, actions))
        index = cursor
    return sorted(out, key=lambda f: (f.start, -f.length))


def merge(
    findings: Iterable[Finding], actions: Mapping[str, str], max_passes: int = 8
) -> list[Finding]:
    """Привести находки к отсортированному списку непересекающихся интервалов.

    Разрешение идёт в несколько проходов: обрезка «хвостов» может снова создать
    пересечения. За ``max_passes`` проходов сходится на любых реальных данных;
    если нет — остатки принудительно сливаются в один интервал, то есть текст
    маскируется с избытком (fail-closed), а не с недостатком.
    """
    current = sorted(
        (f for f in findings if f.end > f.start), key=lambda f: (f.start, -f.length)
    )
    for _ in range(max_passes):
        resolved = _pass(current, actions)
        if resolved == current:
            return resolved
        current = resolved
    merged: list[Finding] = []
    for finding in current:
        if merged and merged[-1].overlaps(finding):
            last = merged[-1]
            merged[-1] = Finding(
                last.start, max(last.end, finding.end), last.klass, last.value
            )
        else:
            merged.append(finding)
    return merged


def apply_mask(text: str, findings: Sequence[Finding], replacer: Callable[[Finding], str]) -> str:
    """Собрать текст обратно, заменив находки на псевдонимы.

    Служит только для тестов и отладки: настоящий санитайзер (M2) обходит payload
    целиком и маскирует блоки, а не строки. Тем не менее одна реализация склейки
    на всех помогает ловить ошибки смещений раньше.
    """
    pieces: list[str] = []
    cursor = 0
    for finding in findings:
        if finding.start < cursor:
            raise ValueError(f"находки пересекаются: {finding}")
        pieces.append(text[cursor : finding.start])
        pieces.append(replacer(finding))
        cursor = finding.end
    pieces.append(text[cursor:])
    return "".join(pieces)
