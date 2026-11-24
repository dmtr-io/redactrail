"""Приёмка M1: качество детекторов на размеченных корпусах.

Порог по ФИО согласован отдельно: recall ≥ 0.90 (пропуск человека — утечка),
precision ≥ 0.95 (иначе обычный текст тонет в ложных маскировках).

Dev-корпус писался до настройки детектора, отложенный — независимо и после,
чтобы измерение не превратилось в проверку самого себя. Оба корпуса
синтетические; реальные персональные данные в репозиторий не попадают.
"""

from __future__ import annotations

import unittest

from tests import support

PERSON_RECALL = 0.90
PERSON_PRECISION = 0.95

#: Нижние границы для остальных классов: регрессия ловится, но требования
#: к качеству NER сформулированы для ФИО, а организации и адреса — по форме.
OTHER_RECALL = 0.90
OTHER_PRECISION = 0.90
PHONE_RECALL = 0.85
PHONE_PRECISION = 0.95


class _CorpusQuality:
    """Миксин: сами тесты живут в двух конкретных классах ниже."""

    corpus = ""
    label = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = support.load_predict(cls.corpus)

    def _report(self, klass: str, recall: float, precision: float) -> str:
        return (
            f"{self.label}/{klass}: recall={recall:.3f}, precision={precision:.3f} "
            f"(текстов: {len(self.cases)})"
        )

    def test_person_recall(self) -> None:
        recall, precision = support.quality(self.cases, "person")
        self.assertGreaterEqual(recall, PERSON_RECALL, self._report("person", recall, precision))

    def test_person_precision(self) -> None:
        recall, precision = support.quality(self.cases, "person")
        self.assertGreaterEqual(
            precision, PERSON_PRECISION, self._report("person", recall, precision)
        )

    def test_org_quality(self) -> None:
        recall, precision = support.quality(self.cases, "org")
        self.assertGreaterEqual(recall, OTHER_RECALL, self._report("org", recall, precision))
        self.assertGreaterEqual(precision, OTHER_PRECISION, self._report("org", recall, precision))

    def test_address_quality(self) -> None:
        recall, precision = support.quality(self.cases, "address")
        self.assertGreaterEqual(recall, OTHER_RECALL, self._report("address", recall, precision))
        self.assertGreaterEqual(
            precision, OTHER_PRECISION, self._report("address", recall, precision)
        )

    def test_phone_quality(self) -> None:
        recall, precision = support.quality(self.cases, "phone")
        self.assertGreaterEqual(recall, PHONE_RECALL, self._report("phone", recall, precision))
        self.assertGreaterEqual(
            precision, PHONE_PRECISION, self._report("phone", recall, precision)
        )


class DevCorpusTests(_CorpusQuality, unittest.TestCase):
    corpus = "ner_corpus.jsonl"
    label = "dev"


class HoldoutCorpusTests(_CorpusQuality, unittest.TestCase):
    corpus = "ner_holdout.jsonl"
    label = "holdout"


class CorpusIntegrityTests(unittest.TestCase):
    def test_dev_corpus_is_well_formed(self) -> None:
        cases = support.load_corpus("ner_corpus.jsonl")
        self.assertGreaterEqual(len(cases), 40)
        self.assertTrue(any(not case.gold for case in cases), "нет текстов без сущностей")

    def test_holdout_corpus_is_well_formed(self) -> None:
        cases = support.load_corpus("ner_holdout.jsonl")
        self.assertGreaterEqual(len(cases), 20)
        self.assertTrue(any(not case.gold for case in cases), "нет текстов без сущностей")


if __name__ == "__main__":
    unittest.main()
