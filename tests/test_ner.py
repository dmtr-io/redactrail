"""NER на синтетических примерах: ФИО, организации, адреса и ловушки."""

from __future__ import annotations

import unittest

from redactrail import ner


def spans(text: str, klass: str) -> list[str]:
    return [f.value for f in ner.find_ner(text) if f.klass == klass]


def has(text: str, klass: str) -> bool:
    return klass in {f.klass for f in ner.find_ner(text)}


class PersonTests(unittest.TestCase):
    def test_full_name(self) -> None:
        text = "Договор подписал Иванов Иван Иванович."
        self.assertEqual(spans(text, "person"), ["Иванов Иван Иванович"])

    def test_initials_after_surname(self) -> None:
        self.assertEqual(
            spans("Заявку принял Иванов И. И.", "person"), ["Иванов И. И."]
        )

    def test_initials_without_spaces(self) -> None:
        self.assertEqual(spans("Иванов И.И. уехал", "person"), ["Иванов И.И."])

    def test_name_and_patronymic(self) -> None:
        self.assertEqual(spans("Позвоните Ивану Петровичу", "person"), ["Ивану Петровичу"])

    def test_lowercase_name_and_patronymic(self) -> None:
        # чат и логи: «пётр петрович» — это человек, хотя всё строчными
        self.assertEqual(spans("позвоните иван петрович сегодня", "person"), ["иван петрович"])

    def test_capital_name_lowercase_patronymic(self) -> None:
        self.assertEqual(spans("Звоните Иван петрович завтра", "person"), ["Иван петрович"])

    def test_lowercase_name_capital_patronymic(self) -> None:
        self.assertEqual(spans("Звоните иван Петрович завтра", "person"), ["иван Петрович"])

    def test_mixed_case_surname_and_name(self) -> None:
        self.assertEqual(spans("Отчёт сдал Иванов иван", "person"), ["Иванов иван"])

    def test_single_lowercase_name_is_not_person(self) -> None:
        # одиночное строчное имя — обычное слово, маскировать нельзя
        self.assertFalse(has("иван пришёл на склад", "person"))
        self.assertFalse(has("петрович ошибся в расчётах", "person"))

    def test_full_name_in_oblique_cases(self) -> None:
        self.assertEqual(
            spans("Перезвоните Дмитрию Алексеевичу Панову после обеда", "person"),
            ["Дмитрию Алексеевичу Панову"],
        )

    def test_surname_before_first_name(self) -> None:
        self.assertEqual(spans("Слово взял Лев Толстой", "person"), ["Лев Толстой"])

    def test_single_surname_in_prose(self) -> None:
        self.assertEqual(spans("Иванову поручили подготовить отчёт", "person"), ["Иванову"])

    def test_unknown_surname_by_ending(self) -> None:
        self.assertEqual(spans("Ковальчуку сообщили о переносе", "person"), ["Ковальчуку"])

    def test_adjective_lookalike_is_not_person(self) -> None:
        self.assertFalse(has("Толстой полосой отмечена зона", "person"))

    def test_common_word_ending_like_surname(self) -> None:
        self.assertFalse(has("Товаров на складе не осталось", "person"))
        self.assertFalse(has("Логин a.demenko указан в подписи", "person"))

    def test_district_name_is_not_person(self) -> None:
        self.assertFalse(has("Петровский район закрыт на ремонт", "person"))

    def test_city_name_is_not_person(self) -> None:
        self.assertFalse(has("Ростов-на-Дону упомянут в письме", "person"))


class OrgTests(unittest.TestCase):
    def test_quoted_guillemets(self) -> None:
        self.assertEqual(spans("ООО «Ромашка» поставило товар", "org"), ["ООО «Ромашка»"])

    def test_quoted_quotes(self) -> None:
        self.assertEqual(spans('АО "Вектор" подтвердило', "org"), ['АО "Вектор"'])

    def test_without_quotes(self) -> None:
        self.assertEqual(spans("отгрузил ООО Северный ветер", "org"), ["ООО Северный ветер"])

    def test_fund_in_genitive(self) -> None:
        self.assertEqual(
            spans("Директор Фонда «Добрый путь детства» подтвердила", "org"),
            ["Фонда «Добрый путь детства»"],
        )

    def test_individual_entrepreneur(self) -> None:
        found = spans("Договор с ИП Ковальчук И.И. подписан", "org")
        self.assertTrue(any(value.startswith("ИП Ковальчук") for value in found), found)


class AddressTests(unittest.TestCase):
    def test_city_street_house_flat(self) -> None:
        self.assertEqual(
            spans("Адрес: г. Москва, ул. Ленина, д. 15, кв. 3.", "address"),
            ["г. Москва, ул. Ленина, д. 15, кв. 3"],
        )

    def test_avenue(self) -> None:
        self.assertEqual(spans("пр-т Мира, 12", "address"), ["пр-т Мира, 12"])

    def test_settlement(self) -> None:
        self.assertEqual(
            spans("пос. Северный, ул. Садовая, 7", "address"),
            ["пос. Северный, ул. Садовая, 7"],
        )

    def test_street_without_city(self) -> None:
        self.assertEqual(spans("Москва, ул. Тверская, 1", "address"), ["ул. Тверская, 1"])

    def test_address_stops_before_next_sentence(self) -> None:
        self.assertEqual(
            spans("г. Москва, ул. Ленина, д. 15. Далее по тексту", "address"),
            ["г. Москва, ул. Ленина, д. 15"],
        )

    def test_year_is_not_address(self) -> None:
        self.assertFalse(has("в 2024 г. выросла выручка", "address"))

    def test_street_inside_address_is_not_person(self) -> None:
        text = "г. Москва, ул. Пушкина, д. 5"
        self.assertEqual([f.klass for f in ner.find_ner(text)], ["address"])


class CombinedTests(unittest.TestCase):
    def test_person_inside_org_keeps_both(self) -> None:
        text = "ООО «Ромашка» в лице Иванова Ивана Ивановича"
        classes = {f.klass for f in ner.find_ner(text)}
        self.assertEqual(classes, {"org", "person"})


if __name__ == "__main__":
    unittest.main()
