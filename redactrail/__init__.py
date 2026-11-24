"""Локальный прокси-маскировщик для DSH.

Пакет намеренно не зависит ни от чего, кроме стандартной библиотеки Python 3.12:
он стоит в горячем пути каждого запроса к модели, а любая внешняя зависимость —
это ещё один способ сломать работу и ещё один поставщик, которому нужно доверять.
"""

__version__ = "0.1.0"

from .detections import Finding
from .pseudonym import Pseudonymizer, load_or_create_key
from .policy import Policy, load_policy

__all__ = [
    "Finding",
    "Policy",
    "Pseudonymizer",
    "load_or_create_key",
    "load_policy",
    "__version__",
]
