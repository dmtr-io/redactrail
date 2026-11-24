"""Локальная админка ревью: очередь предложений, сводка, применение правок.

Отдельный процесс на 127.0.0.1:8788 из стандартной библиотеки. Читает журналы и
предложения, пишет решения, применяет принятые правки в `policy.json` с бэкапом.
Ключ HMAC ей не нужен: она ничего не маскирует.

Модель доступа: токен в `state/admin-token` (создаётся при первом запуске),
сверка `Host`/`Origin`, мутации только `POST`, значения кандидатов — только по
явному запросу. Проверки и запуск описаны в `docs/admin-ui.md`.
"""

from __future__ import annotations

import argparse
import hashlib
from itertools import islice
import json
import os
import re
import secrets
import sys
import threading
import time
import webbrowser
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen

from . import __version__, recover, review, rule_suggest, rules, scan, services
from .audit import append_line, prune_audit
from .detections import apply_mask
from .oplog import OpLog
from .policy import load_policy
from .runtime import enable_utf8_output

DEFAULT_PORT = 8788
TOKEN_FILE = Path("state") / "admin-token"
DECISIONS_FILE = Path("state") / "review-decisions.json"
CANDIDATES_FILE = Path("state") / "review-candidates.json"
SUGGESTIONS_GLOB = "suggestions-*.json"
MAX_BLOCKS = 100
#: Сколько дней журнала блокировок читать (история нужна только для экрана).
BLOCKS_DAYS = 7
#: Хвост файла, который читаем: больше строк всё равно не покажем.
TAIL_LINES = 200
#: Хвост файла в байтах: одна строка ~150 байт, 64 КБ хватает с запасом.
TAIL_BYTES = 65536


def load_token(path: Path = TOKEN_FILE) -> str:
    if path.exists():
        return path.read_text(encoding="ascii").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(32)
    path.write_text(token, encoding="ascii")
    return token


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)


class AdminState:
    """Файловое состояние админки: предложения, решения, кандидаты, журналы."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.audit_dir = root / "audit"
        self.policy_path = root / "policy.json"
        self.backups_dir = root / "state" / "backups"
        self.decisions_path = root / DECISIONS_FILE
        self.candidates_path = root / CANDIDATES_FILE
        self.blocks_dir = self.audit_dir
        self._cache: dict[tuple, list[str]] = {}
        policy = load_policy(self.policy_path)
        self._policy_cache = (self.policy_path.stat().st_mtime, policy)
        self.retention_days = policy.limits.retention_days
        self.started_at = time.time()
        self.oplog = OpLog(root / "state" / "admin.log")
        self.runs_path = root / "state" / "audit-runs.jsonl"
        self.cursor_path = root / "state" / "audit-cursor.json"
        self._review_lock = threading.Lock()
        self._review_cancel = threading.Event()
        self._review_status: dict[str, Any] = {
            "state": "idle",
            "started": None,
            "finished": None,
            "summary": None,
            "error": None,
            "processed": 0,
        }
        prune_audit(self.audit_dir, self.retention_days)

    def _policy(self):
        """Политика с кэшем по mtime: разбор JSON и компиляция правил не бесплатны."""
        try:
            mtime = self.policy_path.stat().st_mtime
        except OSError:
            return load_policy(self.policy_path)
        if self._policy_cache and self._policy_cache[0] == mtime:
            return self._policy_cache[1]
        policy = load_policy(self.policy_path)
        self._policy_cache = (mtime, policy)
        return policy

    def _tail_lines(self, path: Path, limit: int = TAIL_LINES) -> list[str]:
        """Последние строки файла без чтения всего файла, с кэшем по mtime и размеру."""
        try:
            stat = path.stat()
        except OSError:
            return []
        key = (str(path), stat.st_mtime, stat.st_size)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        if len(self._cache) > 400:
            self._cache.clear()
        try:
            with path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - TAIL_BYTES))
                lines = handle.read().splitlines()[-limit:]
        except OSError:
            return []
        decoded = [line.decode("utf-8", "replace") for line in lines]
        self._cache[key] = decoded
        return decoded

    def suggestions(self) -> list[dict]:
        items: list[dict] = []
        for path in sorted(self.audit_dir.glob(SUGGESTIONS_GLOB)):
            data = read_json(path, [])
            if isinstance(data, list):
                items.extend(item for item in data if isinstance(item, dict))
        decisions = self.decisions()
        for item in items:
            item["decision"] = decisions.get(str(item.get("id")), "pending")
        covered: set[str] = set()
        for item in items:
            if item.get("kind") == "rule_patch" and item.get("decision") in ("applied", "accepted"):
                digest = str((item.get("evidence") or {}).get("hash") or "")
                if digest:
                    covered.add(digest)
        for item in items:
            if (
                item.get("kind") == "missed_pii"
                and item.get("decision") == "pending"
                and str(item.get("hash") or "") in covered
            ):
                item["decision"] = "covered"
        # Один и тот же id может прийти из файлов разных дней (полный прогон без
        # курсора): в очередь он должен попасть один раз, побеждает последняя запись.
        unique: dict[str, dict] = {}
        for item in items:
            unique[str(item.get("id"))] = item
        merged = list(unique.values())
        return merged[-review.MAX_SUGGESTIONS :] if len(merged) > review.MAX_SUGGESTIONS else merged

    def decisions(self) -> dict[str, str]:
        data = read_json(self.decisions_path, {})
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}

    def candidates(self) -> dict[str, Any]:
        data = read_json(self.candidates_path, {})
        return data if isinstance(data, dict) else {}

    def set_decision(self, suggestion_id: str, decision: str) -> None:
        data = self.decisions()
        data[suggestion_id] = decision
        write_json_atomic(self.decisions_path, data)

    def blocks(self) -> list[dict]:
        items: list[dict] = []
        for path in sorted(self.blocks_dir.glob("blocks-*.jsonl"))[-BLOCKS_DAYS:]:
            for line in self._tail_lines(path):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    items.append(record)
        return items[-MAX_BLOCKS:]

    def request_stats(self) -> dict:
        path = self.audit_dir / f"{date.today().isoformat()}.jsonl"
        masked: dict[str, int] = {}
        unique: dict[str, int] = {}
        blocked: dict[str, int] = {}
        requests = 0
        fresh = 0
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            requests += 1
            if "new" in record:
                fresh += 1
            for klass, count in (record.get("masked") or {}).items():
                masked[klass] = masked.get(klass, 0) + int(count)
            for klass, values in (record.get("new") or {}).items():
                # «new» — впервые встреченные сегодня псевдонимы: их сумма и есть
                # число разных значений, в отличие от «masked» (срабатываний).
                if isinstance(values, list):
                    unique[klass] = unique.get(klass, 0) + len(values)
            if record.get("blocked"):
                klass = str(record["blocked"])
                blocked[klass] = blocked.get(klass, 0) + 1
        return {
            "day": date.today().isoformat(),
            "requests": requests,
            "masked": dict(sorted(masked.items(), key=lambda kv: -kv[1])),
            "unique": dict(sorted(unique.items(), key=lambda kv: -kv[1])),
            # Часть строк написана до появления поля new: «разные значения»
            # за такой день неполные, и сводка обязана это сказать.
            "unique_partial": 0 < fresh < requests,
            "blocked": dict(sorted(blocked.items(), key=lambda kv: -kv[1])),
        }

    def cache_stats(self) -> dict | None:
        """Статистика кеша детекции из `state/cache.json`, который пишет прокси."""
        data = read_json(self.root / "state" / "cache.json", None)
        if not isinstance(data, dict) or "hits" not in data:
            return None
        hits = int(data.get("hits") or 0)
        misses = int(data.get("misses") or 0)
        total = hits + misses
        return {
            "hits": hits,
            "misses": misses,
            "hit_rate": round(hits / total * 100, 1) if total else 0.0,
            "size": int(data.get("size") or 0),
            "limit": int(data.get("limit") or 0),
            "time": data.get("time"),
        }

    def policy_summary(self) -> dict:
        policy = self._policy()
        return {
            "mode": policy.mode,
            "markers": list(policy.markers),
            "allow": [rule.name for rule in policy.allow],
            "actions": dict(policy.actions),
        }

    def settings(self) -> dict:
        policy = self._policy()
        return {
            "mode": policy.mode,
            "images_blocked": policy.action_for("image") == "block",
            "secrets": policy.action_for("secret_assign"),
            "markers": policy.action_for("marker"),
            "budget_ms": policy.limits.budget_ms,
        }

    def candidate_value(self, item: Mapping[str, Any]) -> str | None:
        """Значение по клику: из файла кандидатов или из сессии по хешу цитаты."""
        kind = item.get("kind")
        if kind == "add_allow":
            value = self.candidates().get(str(item.get("id")))
            return str(value) if value is not None else None
        if kind == "missed_pii":
            return self._find_missed_value(item)
        if kind == "boundary":
            # [[PERSON_93F3CFA9A1]] разрыв маски: по клику ищем соседний участок
            # в том же блоке сессии — по смещению, длине и хешу.
            return self._find_missed_value(item)
        return None

    def _find_missed_value(self, item: Mapping[str, Any]) -> str | None:
        """Перечитать блок сессии и найти исходную цитату по длине и хешу.

        Хеш считается по исходному участку, поэтому смена политики не ломает показ.
        """
        root = Path(self.review_config()["sessions"])
        return review.find_quote(root, item)

    def suggest_rules(self, limit: int = 5) -> dict:
        """Попросить модель предложить правила по пропускам аудита."""
        config = self.review_config()
        reviewer = review.LocalReviewer(config["base_url"], config["model"])
        reviewer.ensure_available()
        result = rule_suggest.suggest_rules(
            self._policy(),
            Path(config["sessions"]),
            self.suggestions(),
            lambda prompt: reviewer.ask_json(prompt, rule_suggest.SYSTEM_PROMPT),
            limit=limit,
            report_dir=self.audit_dir,
        )
        self._log("rules_suggested", created=result["created"], attempted=result["attempted"])
        return result

    def rules(self) -> dict:
        """Снимок всех правил: что действует сейчас и какие значения допустимы."""
        return rules.rules_view(self._policy(), read_json(self.policy_path, {}))

    def save_rules(self, data: Mapping[str, Any]) -> dict:
        """Записать правку правил с бэкапом. Ошибка валидации — исключение."""
        raw = read_json(self.policy_path, {})
        if not isinstance(raw, dict):
            raise ValueError("policy.json повреждён: ожидался объект")
        merged = rules.apply_edits(raw, data)
        before = json.dumps(raw, ensure_ascii=False, sort_keys=True)
        backup = self._backup_policy()
        write_json_atomic(self.policy_path, merged)
        self._policy_cache = (self.policy_path.stat().st_mtime, load_policy(self.policy_path))
        self.retention_days = int(self._policy().limits.retention_days)
        self.log("rules_saved", sections=",".join(sorted(map(str, data.keys()))), backup=str(backup))
        return {
            "rules": self.rules(),
            "backup": str(backup),
            "diff": build_diff(before, json.dumps(merged, ensure_ascii=False, sort_keys=True)),
        }

    def block_value(self, record: Mapping[str, Any]) -> dict:
        """Фраза блокировки по клику: пересобираем её из журнала сессий.

        Значение не сохраняется — оно уходит только в ответ на этот запрос.
        """
        root = self.review_config()["sessions"]
        started = time.monotonic()
        try:
            found = recover.find_phrase(record, root, self._policy())
        except recover.RecoverError as error:
            self.log("block_value", klass=str(record.get("class") or ""), found=False)
            raise ValueError(str(error)) from None
        self.log(
            "block_value",
            klass=str(record.get("class") or ""),
            found=True,
            how=found.how,
            ms=int((time.monotonic() - started) * 1000),
        )
        return {
            "value": found.value,
            "how": found.how,
            "matches": [
                {"session": match.session, "context": match.context} for match in found.matches
            ],
        }

    def log(self, event: str, **fields: Any) -> None:
        self.oplog.write(event, **fields)

    def _log(self, event: str, **fields: Any) -> None:
        self.log(event, **fields)

    def audit_runs(self, limit: int = 10) -> list[dict]:
        """История запусков аудита: переживает перезапуск админки."""
        try:
            lines = self.runs_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        runs: list[dict] = []
        for line in lines[-limit:]:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                runs.append(record)
        return runs

    def hourly_counts(self) -> list[dict]:
        """Запросы по часам за сегодня, **в местной зоне**.

        Журнал хранит UTC; раньше час брался прямо из строки, и график был сдвинут
        на смещение зоны (для Москвы — на 3 часа).
        """
        buckets = [0] * 24
        path = self.audit_dir / f"{date.today().isoformat()}.jsonl"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            stamp = str(record.get("time") or "")
            try:
                moment = datetime.fromisoformat(stamp)
            except ValueError:
                continue
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            hour = moment.astimezone().hour
            buckets[hour] += 1
        return [{"hour": hour, "requests": buckets[hour]} for hour in range(24)]

    def dashboard(self) -> dict:
        config = self.review_config()
        proxy_log = OpLog(self.root / "state" / "proxy.log").tail(15)
        events = self.oplog.tail(15) + proxy_log
        events.sort(key=lambda item: str(item.get("time") or ""))
        return {
            "mode": self._policy().mode,
            "stats": self.request_stats(),
            "cache": self.cache_stats(),
            "hourly": self.hourly_counts(),
            "last_request": self.last_request(),
            "audit_runs": self.audit_runs(10),
            "last_report": self.last_report(),
            "review": config,
            "logs": events[-20:],
            "proxy": self._probe_http("http://127.0.0.1:8787/health"),
            "model": self._probe_model(config["base_url"]),
        }

    def last_request(self) -> dict | None:
        """Последняя строка журнала: когда, сколько и что замаскировано."""
        path = self.audit_dir / f"{date.today().isoformat()}.jsonl"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        for line in reversed(lines):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            masked = record.get("masked") or {}
            top = sorted(masked.items(), key=lambda item: -item[1])[:6] if isinstance(masked, dict) else []
            return {
                "time": record.get("time"),
                "bytes": record.get("bytes"),
                "blocked": record.get("blocked"),
                "masked": dict(top),
            }
        return None

    def check_text(self, text: str) -> dict:
        """Что уйдёт провайдеру: маскировка тем же кодом, что в горячем пути.

        Текст никуда не отправляется и не сохраняется: в журнал попадают только
        классы и длина. Превью показывает метки `<PERSON>`, реальный запрос получит
        псевдоним `[[PERSON_…]]`.
        """
        policy = self._policy()
        findings = scan.detect(text, policy)
        maskable = [finding for finding in findings if not policy.is_block(finding.klass)]
        counters: dict[str, dict[str, int]] = {}
        replacer_values: dict[tuple[str, str], str] = {}

        def replacer(finding) -> str:
            key = (finding.klass, finding.value)
            if key not in replacer_values:
                per_class = counters.setdefault(finding.klass, {})
                per_class[finding.value] = len(per_class) + 1
                replacer_values[key] = f"<{finding.klass.upper()}_{per_class[finding.value]}>"
            return replacer_values[key]

        masked = apply_mask(text, maskable, replacer) if maskable else text
        classes: dict[str, int] = {}
        for finding in maskable:
            classes[finding.klass] = classes.get(finding.klass, 0) + 1
        blocked = next((finding.klass for finding in findings if policy.is_block(finding.klass)), None)
        if policy.mode == "off":
            masked, classes, blocked = text, {}, None
        self.log(
            "check_text",
            chars=len(text),
            classes=sorted(classes),
            blocked=blocked,
            mode=policy.mode,
        )
        return {
            "masked": masked,
            "classes": dict(sorted(classes.items(), key=lambda item: -item[1])),
            "findings": len(findings),
            "blocked": blocked,
            "mode": policy.mode,
        }

    # --- аудит и процессы ---------------------------------------------

    def review_config(self) -> dict:
        settings = self._policy().review
        return {
            "base_url": settings.base_url,
            "model": settings.model,
            "sessions": settings.sessions or str(Path.home() / ".dsh" / "sessions"),
            "days": settings.days,
            "limit": settings.limit,
            "per_session": settings.per_session,
        }

    def review_status(self) -> dict:
        with self._review_lock:
            status = dict(self._review_status)
        status["last_report"] = self.last_report()
        status["config"] = self.review_config()
        status["cursor"] = self.cursor_info()
        if status.get("summary") is None:
            history = self.audit_runs(1)
            status["last_run"] = history[-1] if history else None
        return status

    def cursor_info(self) -> dict:
        """Что запомнил курсор аудита: сколько сессий и событий уже проверено."""
        entries = review.load_cursor(self.cursor_path)
        return {
            "path": str(self.cursor_path),
            "sessions": len(entries),
            "events": sum(int(entry.get("events") or 0) for entry in entries.values()),
        }

    def last_report(self) -> dict | None:
        files = sorted(self.audit_dir.glob("review-*.json"), key=lambda path: path.stat().st_mtime)
        if not files:
            return None
        data = read_json(files[-1], {})
        if not isinstance(data, dict):
            return None
        return {
            "file": files[-1].name,
            "id": data.get("id"),
            "date": data.get("date"),
            "started_at": data.get("started_at"),
            "finished_at": data.get("finished_at") or data.get("generated_at"),
            "model": data.get("model"),
            "sessions": data.get("sessions"),
            "chunks": data.get("chunks"),
            "masked_known": data.get("masked_known"),
            "findings": len(data.get("findings") or []),
            "boundaries": len(data.get("boundaries") or []),
            "errors": len(data.get("errors") or []),
        }

    def start_review(
        self,
        days: int | None = None,
        limit: int | None = None,
        per_session: int | None = None,
        no_llm: bool = False,
        resume: bool = False,
    ) -> bool:
        with self._review_lock:
            if self._review_status["state"] == "running":
                return False
            self._review_cancel.clear()
            self._review_status = {
                "state": "running",
                "started": datetime.now().isoformat(timespec="seconds"),
                "finished": None,
                "summary": None,
                "error": None,
                "processed": 0,
            }
        config = self.review_config()
        self._log(
            "review_start",
            model=config["model"],
            days=int(days or config["days"]),
            limit=int(limit or config["limit"]),
            no_llm=no_llm,
            resume=resume,
        )
        thread = threading.Thread(
            target=self._review_job,
            args=(config, days, limit, per_session, no_llm, resume),
            daemon=True,
            name="review",
        )
        thread.start()
        return True

    def _review_job(self, config: dict, days, limit, per_session, no_llm, resume=False) -> None:
        try:
            policy = self._policy()
            reviewer = None
            if not no_llm:
                client = review.LocalReviewer(config["base_url"], config["model"])
                client.ensure_available()  # иначе прогон молча закончится ошибками
                reviewer = client.ask
            report = review.run_review(
                Path(config["sessions"]),
                policy,
                reviewer,
                days=int(days or config["days"]),
                limit=int(limit or config["limit"]),
                per_session=int(per_session or config["per_session"]),
                report_dir=self.audit_dir,
                model=config["model"],
                should_stop=self._review_cancel.is_set,
                on_progress=self._review_progress,
                cursor_path=self.cursor_path,
                resume=bool(resume),
            )
            summary = {
                "sessions": report.sessions,
                "chunks": report.chunks,
                "masked_known": report.masked_known,
                "findings": len(report.findings),
                "boundaries": len(report.boundaries),
                "errors": len(report.errors),
                "cancelled": report.cancelled,
                "resumed": report.resumed,
                "skipped_events": report.skipped_events,
            }
            self._finish_review("done", summary=summary)
        except Exception as error:  # noqa: BLE001 - фоновой задаче нельзя падать молча
            self._finish_review("error", error=f"{error.__class__.__name__}: {error}")

    def _review_progress(self, processed: int) -> None:
        with self._review_lock:
            self._review_status["processed"] = processed

    def cancel_review(self) -> bool:
        """Остановить долгий прогон: поток проверит флаг после текущего фрагмента."""
        with self._review_lock:
            if self._review_status["state"] != "running":
                return False
            self._review_cancel.set()
        self._log("review_cancel")
        return True

    def _finish_review(self, state: str, summary: dict | None = None, error: str | None = None) -> None:
        with self._review_lock:
            self._review_status.update(
                {
                    "state": state,
                    "finished": datetime.now().isoformat(timespec="seconds"),
                    "summary": summary,
                    "error": error,
                }
            )
            record = {
                "started": self._review_status["started"],
                "finished": self._review_status["finished"],
                "state": state,
                "model": self.review_config()["model"],
                "summary": summary,
                "error": error,
            }
        self._log("review_done", state=state, error=error, **(summary or {}))
        try:
            append_line(self.runs_path, json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            return

    def processes(self) -> dict:
        config = self.review_config()
        reports = sorted(self.audit_dir.glob("review-*.json"))
        journal_files = sorted(self.audit_dir.glob("*.jsonl"))
        journal = []
        for path in journal_files[-7:]:
            try:
                journal.append({"name": path.name, "bytes": path.stat().st_size})
            except OSError:
                continue
        with self._review_lock:
            review_state = self._review_status["state"]
        return {
            "admin": {
                "version": __version__,
                "uptime_s": int(time.time() - self.started_at),
                "port": getattr(self, "admin_port", None),
            },
            "proxy": self._probe_http("http://127.0.0.1:8787/health"),
            "model": self._probe_model(config["base_url"]),
            "audit": {
                "state": review_state,
                "reports": len(reports),
                "last": self.last_report(),
            },
            "journal": {
                "retention_days": self.retention_days,
                "files": journal,
                "bytes_total": sum(item["bytes"] for item in journal),
            },
            "autostart": self.autostart(),
            "review": config,
        }

    def autostart(self) -> dict:
        """Состояние задач планировщика: зарегистрированы или нет.

        `schtasks /Query` проверяется по коду возврата, а не по тексту: вывод
        локализован, и разбирать «Готово»/«Running» значило бы зависеть от локали.
        """
        return {
            "available": services.available(),
            "supervisor": {
                "task": services.SUPERVISOR_TASK,
                "installed": services.task_installed(services.SUPERVISOR_TASK),
            },
            "audit": {
                "task": services.AUDIT_TASK,
                "installed": services.task_installed(services.AUDIT_TASK),
            },
        }

    def restart_proxy(self) -> dict:
        """Перезапустить прокси. В едином процессе — только отчёт, не убийство себя."""
        if os.environ.get("REDACTRAIL_UNIFIED") == "1":
            self.log("proxy_restart", unified=True)
            return {
                "ok": True,
                "unified": True,
                "restarted": False,
                "actions": [],
                "message": (
                    "Единый процесс: политика перечитывается автоматически. "
                    "Для смены кода закройте и запустите приложение заново."
                ),
            }
        report = services.restart_proxy()
        self.log(
            "proxy_restart",
            ok=report.get("ok"),
            actions=",".join(report.get("actions") or []) or "-",
        )
        return report

    @staticmethod
    def _probe_http(url: str, timeout: float = 1.0) -> dict:
        try:
            with urlopen(url, timeout=timeout) as response:  # noqa: S310 - только локальные адреса
                body = response.read(200).decode("utf-8", "replace")
            return {"url": url, "reachable": True, "status": response.status, "body": body}
        except (URLError, OSError, ValueError) as error:
            return {"url": url, "reachable": False, "error": str(error)[:120]}

    @classmethod
    def _probe_model(cls, base_url: str) -> dict:
        models_url = base_url.rstrip("/")
        if models_url.endswith("/chat/completions"):
            models_url = models_url[: -len("/chat/completions")] + "/models"
        try:
            with urlopen(models_url, timeout=1.5) as response:  # noqa: S310 - локальный хост
                raw = response.read(65536).decode("utf-8", "replace")
                status = response.status
        except (URLError, OSError, ValueError) as error:
            return {"models_url": models_url, "reachable": False, "error": str(error)[:120]}
        models: list[str] = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {}
        entries = data.get("data") or data.get("models") or []
        for item in entries:
            if isinstance(item, dict):
                name = item.get("id") or item.get("name")
                if name:
                    models.append(str(name))
        return {"models_url": models_url, "reachable": True, "status": status, "models": models[:10]}

    def _backup_policy(self) -> Path:
        """Копия policy.json рядом с состоянием: в корне репозитория ей не место."""
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        backup = self.backups_dir / f"policy-{datetime.now():%Y%m%d-%H%M%S-%f}.json"
        backup.write_bytes(self.policy_path.read_bytes())
        return backup

    def update_settings(self, data: Mapping[str, Any]) -> dict:
        """Правка policy.json из админки: бэкап, атомарная запись, те же поля."""
        policy = read_json(self.policy_path, {})
        if not isinstance(policy, dict):
            raise ValueError("policy.json повреждён")
        actions = dict(policy.get("actions") or {})

        if "mode" in data:
            mode = str(data["mode"])
            if mode not in ("strict", "audit", "off"):
                raise ValueError(f"неизвестный режим {mode!r}")
            policy["mode"] = mode
        if "images_blocked" in data:
            value = "block" if bool(data["images_blocked"]) else "allow"
            actions["image"] = value
            actions["document"] = value
        if "secrets" in data:
            value = str(data["secrets"])
            if value not in ("mask", "block", "allow"):
                raise ValueError(f"недопустимое действие для секретов: {value!r}")
            for klass in ("private_key", "secret_token", "secret_assign"):
                actions[klass] = value
        if "markers" in data:
            value = str(data["markers"])
            if value not in ("mask", "block", "allow"):
                raise ValueError(f"недопустимое действие для маркеров: {value!r}")
            actions["marker"] = value
        policy["actions"] = actions

        if "review" in data:
            raw = data["review"]
            if not isinstance(raw, Mapping):
                raise ValueError("review должен быть объектом")
            current = dict(policy.get("review") or {})
            for key in ("base_url", "model", "sessions"):
                if key in raw:
                    value = raw[key]
                    if not isinstance(value, str):
                        raise ValueError(f"review.{key} должен быть строкой")
                    current[key] = value.strip()
            for key in ("days", "limit", "per_session"):
                if key in raw:
                    value = int(raw[key])
                    if value < 1:
                        raise ValueError(f"review.{key} меньше 1")
                    current[key] = value
            policy["review"] = current

        backup = self._backup_policy()
        write_json_atomic(self.policy_path, policy)
        self._log("settings_saved", keys=sorted(map(str, data.keys())), backup=str(backup))
        return {"settings": self.settings(), "backup": str(backup)}

    # --- применение правок -------------------------------------------

    def proposed_changes(self) -> list[dict]:
        """Что изменится в policy.json по принятым предложениям."""
        policy = read_json(self.policy_path, {})
        if not isinstance(policy, dict):
            policy = {}
        markers = list(policy.get("markers", []))
        allow = list(policy.get("allow", []))
        changes: list[dict] = []
        for item in self.suggestions():
            if item.get("decision") != "accepted":
                continue
            kind = item.get("kind")
            payload = item.get("payload")
            if kind == "remove_marker" and isinstance(payload, str):
                if payload in markers:
                    markers.remove(payload)
                    changes.append({"suggestion": item["id"], "action": "remove_marker", "value": payload})
            elif kind == "add_marker" and isinstance(payload, str):
                if payload not in markers:
                    markers.append(payload)
                    changes.append({"suggestion": item["id"], "action": "add_marker", "value": payload})
            elif kind == "add_allow" and isinstance(payload, Mapping):
                rule = {
                    "name": str(payload.get("name", "review")),
                    "pattern": str(payload.get("pattern", "")),
                    "classes": list(payload.get("classes", ["*"])),
                }
                if rule["pattern"] and not any(r.get("name") == rule["name"] for r in allow if isinstance(r, dict)):
                    allow.append(rule)
                    changes.append({"suggestion": item["id"], "action": "add_allow", "value": rule["name"]})
            elif kind in ("add_allowed_field", "add_allowed_block", "add_allowed_role") and isinstance(payload, str) and payload:
                key = {
                    "add_allowed_field": "allowed_fields",
                    "add_allowed_block": "allowed_block_types",
                    "add_allowed_role": "allowed_roles",
                }[kind]
                request = policy.get("request") or {}
                values = list(request.get(key) or [])
                if payload not in values:
                    values.append(payload)
                    request[key] = values
                    policy["request"] = request
                    changes.append({"suggestion": item["id"], "action": kind, "value": payload})
            elif kind in ("add_surname", "unknown"):
                changes.append({"suggestion": item["id"], "action": str(kind), "value": "требует M4"})
            elif kind == "rule_patch" and isinstance(payload, Mapping):
                pattern = str(payload.get("pattern") or "")
                flags = str(payload.get("flags") or "")
                klass = str(payload.get("class") or item.get("class") or "")
                reason = rule_suggest.validate_rule(pattern, flags, self._policy(), klass)
                if reason:
                    changes.append(
                        {"suggestion": item["id"], "action": "rule_error", "value": reason}
                    )
                    continue
                name = (
                    "model-"
                    + re.sub(r"\W+", "-", klass)[:20]
                    + "-"
                    + hashlib.sha256((klass + pattern + flags).encode("utf-8")).hexdigest()[:8]
                )
                changes.append(
                    {
                        "suggestion": item["id"],
                        "action": "add_extra_rule",
                        "value": pattern,
                        "name": name,
                        "class": klass,
                        "flags": flags,
                        "explanation": str(payload.get("explanation") or "")[:300],
                    }
                )
        return changes

    def apply(self) -> dict:
        policy = read_json(self.policy_path, {})
        if not isinstance(policy, dict):
            raise ValueError("policy.json повреждён")
        before = json.dumps(policy, ensure_ascii=False, sort_keys=True)
        changes = self.proposed_changes()

        markers = list(policy.get("markers", []))
        allow = list(policy.get("allow", []))
        for change in changes:
            if change["action"] == "remove_marker":
                markers = [m for m in markers if m != change["value"]]
            elif change["action"] == "add_marker":
                if change["value"] not in markers:
                    markers.append(change["value"])
            elif change["action"] == "add_allow":
                item = next(
                    (s for s in self.suggestions() if s.get("id") == change["suggestion"]),
                    None,
                )
                payload = (item or {}).get("payload") or {}
                allow.append(
                    {
                        "name": str(payload.get("name", "review")),
                        "pattern": str(payload.get("pattern", "")),
                        "classes": list(payload.get("classes", ["*"])),
                    }
                )
            elif change["action"] in ("add_allowed_field", "add_allowed_block", "add_allowed_role"):
                key = {
                    "add_allowed_field": "allowed_fields",
                    "add_allowed_block": "allowed_block_types",
                    "add_allowed_role": "allowed_roles",
                }[change["action"]]
                request = dict(policy.get("request") or {})
                values = list(request.get(key) or [])
                if change["value"] not in values:
                    values.append(change["value"])
                request[key] = values
                policy["request"] = request
            elif change["action"] == "add_extra_rule":
                extra = list(policy.get("extra_rules") or [])
                exists = any(
                    isinstance(entry, Mapping)
                    and entry.get("class") == change.get("class")
                    and entry.get("pattern") == change.get("value")
                    for entry in extra
                )
                if not exists:
                    extra.append(
                        {
                            "name": change.get("name"),
                            "class": change.get("class"),
                            "pattern": change.get("value"),
                            "flags": change.get("flags", ""),
                            "explanation": change.get("explanation", ""),
                        }
                    )
                    policy["extra_rules"] = extra
        policy["markers"] = markers
        policy["allow"] = allow

        backup = self._backup_policy()
        write_json_atomic(self.policy_path, policy)
        self._log("policy_apply", changes=len(changes), backup=str(backup))

        covered: set[str] = set()
        for change in changes:
            if change.get("action") != "add_extra_rule":
                continue
            item = next(
                (s for s in self.suggestions() if s.get("id") == change.get("suggestion")), None
            )
            evidence = (item or {}).get("evidence") or {}
            digest = str(evidence.get("hash") or "")
            if digest:
                covered.add(digest)

        for item in self.suggestions():
            if item.get("decision") == "accepted":
                self.set_decision(str(item["id"]), "applied")
            elif (
                item.get("kind") == "missed_pii"
                and item.get("decision") == "pending"
                and str(item.get("hash") or "") in covered
            ):
                # Находка закрыта принятым правилом: убираем из «ждут решения».
                self.set_decision(str(item["id"]), "covered")
        return {
            "applied": changes,
            "backup": str(backup),
            "diff": build_diff(before, json.dumps(policy, ensure_ascii=False, sort_keys=True)),
        }


def review_signature() -> dict:
    """Диагностика: какой модуль аудита загружен и что фильтруется."""
    import inspect

    source = inspect.getsource(review.run_review)
    sample = review.meaningful_findings([{"category": "person", "quote": "abc"}])
    return {
        "file": review.__file__,
        "noise_filter": "len(quote) < 4" in source,
        "short_quote_passes": len(sample),
    }


def build_diff(before: str, after: str) -> list[str]:
    """Простой построчный diff: достаточно, чтобы увидеть правку."""
    import difflib

    return list(
        difflib.unified_diff(
            json.dumps(json.loads(before), ensure_ascii=False, indent=2, sort_keys=True).splitlines(),
            json.dumps(json.loads(after), ensure_ascii=False, indent=2, sort_keys=True).splitlines(),
            "policy.json",
            "policy.json (новый)",
            lineterm="",
        )
    )


class AdminHandler(BaseHTTPRequestHandler):
    server: "AdminServer"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        # Локальный браузер может не присылать cookie (настройки приватности, IP-хост).
        # Чтение по loopback разрешаем без токена; мутации всё равно требуют его.
        trusted = self._authorised() or self._bootstrap_allowed(query)
        if parts.path in ("/", "/admin"):
            if not trusted:
                self._json(401, {"error": "нужен токен"})
                return
            self._cookie_header = True
            if parts.path == "/admin":
                self._redirect("/")
            else:
                self._html()
            return
        if not trusted:
            self._json(401, {"error": "нужен токен"})
            return
        if parts.path == "/api/state":
            self._json(200, self._state())
        elif parts.path == "/api/dashboard":
            self._json(200, self.server.state.dashboard())
        elif parts.path == "/api/processes":
            self._json(200, self.server.state.processes())
        elif parts.path == "/api/review/status":
            self._json(200, self.server.state.review_status())
        elif parts.path == "/api/rules":
            self._json(200, self.server.state.rules())
        elif parts.path.startswith("/api/candidates/"):
            self._value(parts.path.rsplit("/", 1)[-1])
        else:
            self._json(404, {"error": "неизвестный путь"})

    def do_POST(self) -> None:  # noqa: N802
        # Тело читаем сразу и целиком: иначе в keep-alive остаются байты и следующий
        # запрос на том же соединении ломается («{}POST» в строке запроса).
        body = self._read_body()
        if not self._authorised(origin_check=True) and not self._same_origin_post():
            self._json(403, {"error": "отказано"})
            return
        parts = urlsplit(self.path)
        if parts.path == "/api/policy/apply":
            try:
                self._json(200, self.server.state.apply())
            except Exception as error:  # noqa: BLE001
                self._json(400, {"error": str(error)})
            return
        if parts.path == "/api/settings":
            try:
                payload = json.loads(body or "{}")
                self._json(200, self.server.state.update_settings(payload))
            except (ValueError, json.JSONDecodeError) as error:
                self._json(400, {"error": str(error)})
            return
        if parts.path == "/api/rules":
            try:
                payload = json.loads(body or "{}")
                self._json(200, self.server.state.save_rules(payload))
            except (ValueError, json.JSONDecodeError) as error:
                self._json(400, {"error": str(error)})
            return
        if parts.path == "/api/rules/suggest":
            try:
                payload = json.loads(body or "{}")
                limit = int(payload.get("limit") or 5)
                self._json(200, self.server.state.suggest_rules(limit=limit))
            except Exception as error:  # noqa: BLE001 - модель может быть недоступна
                self._json(400, {"error": str(error)})
            return
        if parts.path == "/api/blocks/value":
            try:
                payload = json.loads(body or "{}")
            except json.JSONDecodeError:
                payload = {}
            try:
                self._json(200, self.server.state.block_value(payload))
            except ValueError as error:
                self._json(404, {"error": str(error)})
            return
        if parts.path == "/api/blocks/review":
            try:
                items = review.block_suggestions(
                    self.server.state.audit_dir, days=7, policy=self.server.state._policy()
                )
                added = review.merge_suggestions(
                    self.server.state.audit_dir, date.today().isoformat(), items
                )
                self.server.state.log("blocks_review", found=len(items), added=added)
                self._json(200, {"found": len(items), "added": added})
            except Exception as error:  # noqa: BLE001
                self._json(400, {"error": str(error)})
            return
        if parts.path == "/api/blocks/suggest":
            try:
                payload = json.loads(body or "{}")
            except json.JSONDecodeError:
                payload = {}
            where = str(payload.get("where") or "")
            klass = str(payload.get("class") or "")
            detail = review.block_detail(where)
            if not detail or klass not in ("unknown_field", "unknown_block"):
                self._json(400, {"error": "в записи нет имени поля или типа блока"})
                return
            kind = (
                "add_allowed_role"
                if "роль" in where
                else ("add_allowed_field" if klass == "unknown_field" else "add_allowed_block")
            )
            allowed = {
                "add_allowed_field": set(self.server.state._policy().request.allowed_fields),
                "add_allowed_block": set(self.server.state._policy().request.allowed_block_types),
                "add_allowed_role": set(self.server.state._policy().request.allowed_roles),
            }[kind]
            if detail in allowed:
                self._json(200, {"added": 0, "detail": detail, "note": "уже разрешено"})
                return
            item = {
                "id": "b-" + hashlib.sha256(f"{kind}:{detail}".encode("utf-8")).hexdigest()[:10],
                "class": klass,
                "kind": kind,
                "payload": detail,
                "verdict": "частое срабатывание",
                "count": 1,
                "window": f"поле или тип: {detail}",
                "action": f"разрешить {detail}",
            }
            added = review.merge_suggestions(
                self.server.state.audit_dir, date.today().isoformat(), [item]
            )
            self._json(200, {"added": added, "detail": detail})
            return
        if parts.path == "/api/review/cancel":
            self._json(200, {"cancelled": self.server.state.cancel_review()})
            return
        if parts.path == "/api/review/run":
            try:
                payload = json.loads(body or "{}")
            except json.JSONDecodeError:
                payload = {}
            started = self.server.state.start_review(
                days=payload.get("days"),
                limit=payload.get("limit"),
                per_session=payload.get("per_session"),
                no_llm=bool(payload.get("no_llm")),
                resume=bool(payload.get("resume")),
            )
            self._json(200 if started else 409, {"started": started, "status": self.server.state.review_status()})
            return
        if parts.path == "/api/proxy/restart":
            self._json(200, self.server.state.restart_proxy())
            return
        if parts.path == "/api/check":
            try:
                payload = json.loads(body or "{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "не JSON"})
                return
            text = payload.get("text") if isinstance(payload, dict) else None
            if not isinstance(text, str):
                self._json(400, {"error": "нужно поле text"})
                return
            if len(text) > 20000:
                self._json(400, {"error": "слишком длинный текст, максимум 20 000 символов"})
                return
            self._json(200, self.server.state.check_text(text))
            return
        segments = parts.path.strip("/").split("/")
        if len(segments) == 4 and segments[0] == "api" and segments[1] == "suggestions":
            suggestion_id, action = segments[2], segments[3]
            if action in ("accept", "reject"):
                known = {str(s.get("id")) for s in self.server.state.suggestions()}
                if suggestion_id not in known:
                    self._json(404, {"error": "нет такого предложения"})
                    return
                self.server.state.set_decision(suggestion_id, "accepted" if action == "accept" else "rejected")
                self._json(200, {"ok": True})
                return
        self._json(404, {"error": "неизвестный путь"})

    # --- проверки -----------------------------------------------------

    def _authorised(self, origin_check: bool = False) -> bool:
        token = self.headers.get("X-Admin-Token") or ""
        cookie = self.headers.get("Cookie") or ""
        if not token and "admin_token=" in cookie:
            token = cookie.split("admin_token=", 1)[1].split(";", 1)[0]
        if token != self.server.token:
            return False
        if origin_check:
            origin = self.headers.get("Origin")
            if origin and origin not in (f"http://127.0.0.1:{self.server.port}", f"http://localhost:{self.server.port}"):
                return False
        return True

    def _same_origin_post(self) -> bool:
        """Запрос со страницы самой админки: Origin совпадает с адресом сервера.

        Нужен на случай, когда браузер не присылает cookie. Чужой Origin не пройдёт,
        запрос без Origin (сторонний скрипт) — тоже.
        """
        origin = self.headers.get("Origin") or ""
        port = self.server.port
        if origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
            return False
        return self.client_address[0] in ("127.0.0.1", "::1")

    def _bootstrap_allowed(self, query: Mapping[str, list[str]]) -> bool:
        """Вход для локального браузера: без токена, но только с этого хоста.

        Токен остаётся вторым способом. Смысл послабления: админка живёт на loopback,
        а набирать 64 символа вручную неудобно. Чужая страница не пройдёт: запрос с
        `Origin` отклоняется, `Host` сверяется с портом сервера.
        """
        if "token" in query:
            return query["token"][0] == self.server.token
        if self.headers.get("Origin"):
            return False
        host = (self.headers.get("Host") or "").lower()
        port = self.server.port
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"):
            return False
        return self.client_address[0] in ("127.0.0.1", "::1")

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if getattr(self, "_cookie_header", False):
            self.send_header("Set-Cookie", f"admin_token={self.server.token}; HttpOnly; SameSite=Strict; Path=/")
        self.end_headers()

    def _read_body(self) -> str:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return ""
        if length <= 0 or length > 65536:
            return ""
        return self.rfile.read(length).decode("utf-8")

    def _state(self) -> dict:
        suggestions = self.server.state.suggestions()
        return {
            "version": __version__,
            "mode": self.server.state.policy_summary()["mode"],
            "settings": self.server.state.settings(),
            "stats": self.server.state.request_stats(),
            "cache": self.server.state.cache_stats(),
            "suggestions": suggestions,
            "blocks": self.server.state.blocks(),
            "changes": self.server.state.proposed_changes(),
            "pending": sum(1 for s in suggestions if s.get("decision") == "pending"),
            "build": review_signature(),
        }

    def _value(self, suggestion_id: str) -> None:
        items = {str(s.get("id")): s for s in self.server.state.suggestions()}
        item = items.get(suggestion_id)
        if item is None:
            self._json(404, {"error": "нет такого предложения"})
            return
        value = self.server.state.candidate_value(item)
        if value is None:
            self._json(
                403,
                {"error": "значение показывается только для кандидатов в allow-лист и находок аудита"},
            )
            return
        self._json(200, {"value": value})

    # --- ответы -------------------------------------------------------

    def _cookie(self) -> None:
        self._cookie_header = True

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self) -> None:
        body = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'none'",
        )
        if getattr(self, "_cookie_header", False):
            self.send_header("Set-Cookie", f"admin_token={self.server.token}; HttpOnly; SameSite=Strict; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


class AdminServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], root: Path, token: str) -> None:
        super().__init__(address, AdminHandler)
        self.root = root
        self.token = token
        self.state = AdminState(root)
        self.state.admin_port = self.server_address[1]
        self.state._log("admin_start", port=self.server_address[1], root=str(root), version=__version__)
        self.port = self.server_address[1]


PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>redactrail — ревью</title>
<style>
  :root{
    --bg:#f5f6f8; --surface:#fff; --border:#e5e7eb; --text:#0f172a; --muted:#64748b;
    --faint:#94a3b8; --accent:#4f46e5; --accent-soft:#eef2ff; --ok:#059669; --ok-soft:#ecfdf5;
    --warn:#b45309; --warn-soft:#fffbeb; --bad:#b91c1c; --bad-soft:#fef2f2;
    --mono:ui-monospace,"Cascadia Code",Consolas,monospace; --radius:12px;
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  body{font:14px/1.45 "Segoe UI",system-ui,sans-serif;color:var(--text);background:var(--bg);display:flex;min-height:100vh}
  a{color:var(--accent);text-decoration:none}

  /* ---------- sidebar ---------- */
  aside{width:252px;flex:0 0 252px;background:var(--surface);border-right:1px solid var(--border);
    display:flex;flex-direction:column;padding:18px 14px;position:sticky;top:0;height:100vh}
  .brand{display:flex;align-items:center;gap:10px;padding:2px 8px 18px}
  .logo{width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,#6366f1,#4338ca);
    display:grid;place-items:center;color:#fff;flex:0 0 32px}
  .brand b{display:block;font-size:14.5px;letter-spacing:-.01em}
  .brand span{font-size:11px;color:var(--faint)}
  nav{display:flex;flex-direction:column;gap:2px}
  nav a{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:8px;color:#334155;
    font-size:13.5px;font-weight:500}
  nav a:hover{background:#f8fafc}
  nav a.active{background:var(--accent-soft);color:var(--accent);font-weight:600}
  nav a .count{margin-left:auto;background:#eef0f3;color:#475569;border-radius:999px;padding:1px 7px;
    font-size:11.5px;font-weight:600;min-width:22px;text-align:center}
  nav a.active .count{background:#e0e7ff;color:var(--accent)}
  nav .group{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);
    padding:14px 10px 5px;font-weight:600}
  .side-foot{margin-top:auto;border-top:1px solid var(--border);padding:12px 8px 2px;font-size:12px;color:var(--muted)}
  .side-foot .row{display:flex;justify-content:space-between;margin-top:6px}
  .dot{width:7px;height:7px;border-radius:50%;background:var(--ok);display:inline-block;margin-right:6px}
  .dot.off{background:var(--bad)}

  /* ---------- layout ---------- */
  main{flex:1;min-width:0;padding:0 0 48px}
  .topbar{position:sticky;top:0;z-index:5;background:rgba(245,246,248,.92);backdrop-filter:blur(6px);
    border-bottom:1px solid var(--border);padding:18px 32px;display:flex;align-items:flex-end;gap:16px}
  .topbar h1{margin:0;font-size:21px;letter-spacing:-.02em}
  .topbar .sub{color:var(--muted);font-size:12.5px;margin-top:3px}
  .spacer{flex:1}
  .content{padding:24px 32px 0;display:flex;flex-direction:column;gap:18px}
  .chip{display:inline-flex;align-items:center;gap:7px;background:var(--surface);border:1px solid var(--border);
    border-radius:8px;padding:7px 11px;font-size:12.5px;color:#334155;white-space:nowrap}
  .chip b{font-weight:600}
  .mono{font-family:var(--mono);font-size:12px}
  .muted{color:var(--muted)} .faint{color:var(--faint)}
  .hidden{display:none!important}

  /* ---------- controls ---------- */
  button{font:inherit;cursor:pointer;border:1px solid var(--border);background:var(--surface);
    color:#334155;border-radius:8px;padding:7px 12px;font-size:12.5px}
  button:hover{background:#f8fafc}
  button.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
  button.primary:hover{background:#4338ca}
  button.ghost{background:transparent}
  button.small{padding:4px 9px;font-size:12px}
  button.danger{color:var(--bad);border-color:#fecaca}
  select,input[type=text],input[type=number]{font:inherit;font-size:13px;color:var(--text);
    background:#fff;border:1px solid var(--border);border-radius:8px;padding:7px 10px;min-width:0}
  select:focus,input:focus{outline:2px solid #c7d2fe;outline-offset:0;border-color:#a5b4fc}
  label.inline{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:#334155}

  /* ---------- cards ---------- */
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px}
  .card .l{color:var(--muted);font-size:12px}
  .card .v{font-size:27px;font-weight:650;letter-spacing:-.02em;margin-top:2px;line-height:1.15}
  .card .v.small{font-size:16px;margin-top:6px}
  .card .hint{font-size:11.5px;color:var(--faint);margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

  /* ---------- panels & grids ---------- */
  .panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;min-width:0}
  .panel h2{margin:0 0 14px;font-size:13.5px;font-weight:650;display:flex;align-items:center;gap:8px}
  .panel h2 .right{margin-left:auto;font-weight:400;font-size:12px;color:var(--faint)}
  .two-col{display:grid;grid-template-columns:1.5fr 1fr;gap:18px;align-items:start}
  .split{display:grid;grid-template-columns:1fr 1fr;gap:18px;align-items:start}
  @media (max-width:1200px){.two-col{grid-template-columns:1fr}.split{grid-template-columns:1fr}}
  .toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}

  /* ---------- bars ---------- */
  .bars{display:grid;gap:10px}
  .bar-row{display:grid;grid-template-columns:120px 1fr 56px;align-items:center;gap:10px;font-size:12.5px}
  .bar-row .cls{font-family:var(--mono);font-size:11.5px;color:#334155;overflow:hidden;text-overflow:ellipsis}
  .bar{height:8px;background:#f1f3f6;border-radius:999px;overflow:hidden}
  .bar i{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,#818cf8,#4f46e5)}
  .bar-row .n{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}

  .hourly{display:grid;grid-template-columns:repeat(24,1fr);gap:3px;align-items:end;height:110px}
  .hourly .col{display:flex;flex-direction:column;justify-content:flex-end;height:100%}
  .hourly .col i{display:block;background:linear-gradient(180deg,#818cf8,#4f46e5);border-radius:3px 3px 0 0;min-height:2px}
  .hourly .col span{font-size:9px;color:var(--faint);text-align:center;margin-top:4px}
  pre.log{font-family:var(--mono);font-size:11.5px;background:#0f172a;color:#cbd5e1;border-radius:10px;
    padding:12px 14px;overflow:auto;max-height:240px;line-height:1.5;margin:0;white-space:pre-wrap}

  /* ---------- tables ---------- */
  .table-wrap{overflow:auto;border:1px solid var(--border);border-radius:10px;background:var(--surface)}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--faint);
    font-weight:600;padding:10px 12px;background:#fafbfc;position:sticky;top:0;white-space:nowrap;z-index:1}
  td{border-top:1px solid var(--border);padding:11px 12px;vertical-align:top;font-size:13px}
  tbody tr:hover td{background:#fafbfc}
  td.actions{white-space:nowrap;text-align:right}
  .empty{color:var(--muted);padding:22px;text-align:center}
  .klass{font-family:var(--mono);font-size:11.5px;background:#f1f5f9;color:#334155;border-radius:6px;padding:2px 7px}
  .tag{font-family:var(--mono);font-size:11.5px;border-radius:6px;padding:2px 7px}
  .tag.bad{background:var(--bad-soft);color:var(--bad)}
  .tag.warn{background:var(--warn-soft);color:var(--warn)}
  .tag.ok{background:var(--ok-soft);color:var(--ok)}
  .win{font-size:12.5px;color:#334155;background:#f8fafc;border:1px dashed var(--border);
    border-radius:8px;padding:7px 9px;max-width:560px;white-space:pre-wrap;word-break:break-word}
  .verdict{font-size:12px;white-space:nowrap}
  .verdict.fp{color:var(--ok)} .verdict.tp{color:var(--bad)} .verdict.unsure{color:var(--warn)}

  /* ---------- lists ---------- */
  .list{display:flex;flex-direction:column;gap:0}
  .list .item{display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px dashed var(--border);font-size:12.5px}
  .list .item:last-child{border-bottom:0}
  .list .item .meta{margin-left:auto;color:var(--faint);font-variant-numeric:tabular-nums;white-space:nowrap}

  /* ---------- forms ---------- */
  .form{display:grid;grid-template-columns:220px minmax(0,420px);gap:10px 16px;align-items:center;font-size:13px}
  .form label{color:#334155}
  .form .full{grid-column:1/-1}
  .note{font-size:12px;color:var(--muted);margin-top:10px;line-height:1.5}
  .msg{font-family:var(--mono);font-size:12px;color:var(--muted);margin-top:10px;word-break:break-all}
  .editor{width:100%;min-height:110px;padding:10px;border:1px solid var(--border);border-radius:10px;
    font:inherit;resize:vertical;background:var(--surface)}
  .editor.tall{min-height:210px}

  /* ---------- diff ---------- */
  pre.diff{font-family:var(--mono);font-size:12.5px;background:#0f172a;color:#e2e8f0;border-radius:10px;
    padding:14px 16px;overflow:auto;line-height:1.55;margin:0}
  pre.diff .add{color:#86efac} pre.diff .del{color:#fca5a5} pre.diff .ctx{color:#94a3b8}

  @media (max-width:900px){
    body{display:block}
    aside{width:auto;flex:none;height:auto;position:static;border-right:0;border-bottom:1px solid var(--border);
      padding:12px 14px;flex-direction:row;align-items:center;gap:10px;overflow-x:auto}
    .brand{padding:0;flex:0 0 auto}
    .brand span{display:none}
    nav{flex-direction:row}
    nav .group{display:none}
    nav a{padding:7px 9px;white-space:nowrap}
    nav a .count{display:none}
    .side-foot{display:none}
    .topbar,.content{padding-left:16px;padding-right:16px}
    .form{grid-template-columns:1fr}
  }
</style>
</head>
<body>
<aside>
  <div class="brand">
    <div class="logo">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M12 3l7 3v6c0 4.2-2.9 7.5-7 9-4.1-1.5-7-4.8-7-9V6l7-3z"/>
      </svg>
    </div>
    <div><b>redactrail</b><span>админка ревью</span></div>
  </div>

  <nav id="nav">
    <div class="group">Обзор</div>
    <a href="#dashboard" data-view="dashboard">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="5" rx="2"/><rect x="13" y="10" width="8" height="11" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/></svg>
      Сводка
    </a>
    <a href="#queue" data-view="queue">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h10"/></svg>
      Очередь <span class="count" id="navPending">0</span>
    </a>
    <a href="#blocks" data-view="blocks">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01"/><path d="M10.3 3.9L2.6 17a2 2 0 001.7 3h15.4a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>
      Блокировки <span class="count" id="navBlocks">0</span>
    </a>
    <a href="#rules" data-view="rules">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5V6a2 2 0 012-2h13v16H6a2 2 0 00-2 1.5z"/><path d="M8 8h7M8 12h5"/></svg>
      Правила
    </a>
    <a href="#changes" data-view="changes">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12m0 0l-4-4m4 4l4-4"/><path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"/></svg>
      Изменения
    </a>
    <div class="group">Система</div>
    <a href="#processes" data-view="processes">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg>
      Процессы
    </a>
    <a href="#settings" data-view="settings">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 00-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 00-2-1.2L14 3h-4l-.5 2.6a7 7 0 00-2 1.2l-2.4-1-2 3.4 2 1.6A7 7 0 005 12c0 .4 0 .8.1 1.2l-2 1.6 2 3.4 2.4-1a7 7 0 002 1.2L10 21h4l.5-2.6a7 7 0 002-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z"/></svg>
      Настройки
    </a>
    <a href="#check" data-view="check">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M20 20l-4.5-4.5"/></svg>
      Проверка
    </a>
  </nav>

  <div class="side-foot">
    <div><span class="dot" id="footDot"></span><span id="footProxy">проверяю…</span></div>
    <div class="row"><span>режим</span><b id="footMode">—</b></div>
    <div class="row"><span>версия</span><span class="mono" id="footVersion">—</span></div>
  </div>
</aside>

<main>
  <div class="topbar">
    <div>
      <h1 id="title">Сводка</h1>
      <div class="sub" id="subtitle">—</div>
    </div>
    <div class="spacer"></div>
    <span class="chip" id="modeChip"><span class="dot" id="modeDot"></span> режим <b id="modeName">—</b></span>
    <button id="refreshBtn">Обновить</button>
  </div>

  <div class="content">
    <!-- ==================== DASHBOARD ==================== -->
    <section data-section="dashboard">
      <div class="cards" style="margin-bottom:18px">
        <div class="card"><div class="l">Запросов сегодня</div><div class="v" id="kpiRequests">0</div><div class="hint" id="kpiRequestsHint"></div></div>
        <div class="card"><div class="l" id="kpiMaskedLabel">Замаскировано</div><div class="v" id="kpiMasked">0</div><div class="hint" id="kpiMaskedHint"></div></div>
        <div class="card"><div class="l">Заблокировано</div><div class="v" id="kpiBlocked">0</div><div class="hint" id="kpiBlockedHint"></div></div>
        <div class="card"><div class="l">Ждут решения</div><div class="v" id="kpiPending">0</div><div class="hint" id="kpiPendingHint"></div></div>
      </div>

      <div class="panel" style="margin-bottom:18px">
        <h2>Последний запрос <span class="right" id="lastReqWhen"></span></h2>
        <div class="list" id="lastRequest"></div>
      </div>

      <div class="two-col" style="margin-bottom:18px">
        <div class="panel">
          <h2>Маскировка по классам <span class="right" id="barsHint">за сегодня</span></h2>
          <div class="bars" id="bars"></div>
        </div>
        <div class="panel">
          <h2>Последние блокировки <span class="right" id="blocksCount"></span></h2>
          <div class="list" id="lastBlocks"></div>
          <div class="note">Классы и хеши, без значений. Полный список — в разделе «Блокировки».</div>
        </div>
      </div>

      <div class="panel">
        <h2>Очередь предложений <span class="right" id="queueHint"></span></h2>
        <div id="queuePreview"></div>
      </div>

      <div class="split">
        <div class="panel">
          <h2>Запросы по часам <span class="right" id="hourlyHint"></span></h2>
          <div class="hourly" id="hourly"></div>
          <div class="note" id="cacheInfo">кеш детекции: —</div>
        </div>
        <div class="panel">
          <h2>Запуски аудита <span class="right" id="runsHint"></span></h2>
          <div class="list" id="auditRuns"></div>
        </div>
      </div>

      <div class="panel">
        <h2>События <span class="right">state/admin.log · state/proxy.log</span></h2>
        <pre class="log" id="eventLog">пока пусто</pre>
      </div>
    </section>

    <!-- ==================== QUEUE ==================== -->
    <section data-section="queue" class="hidden">
      <div class="toolbar">
        <select id="queueFilter">
          <option value="pending" selected>ждут решения</option>
          <option value="all">все</option>
          <option value="covered">покрыто правилом</option>
          <option value="accepted">принятые</option>
          <option value="rejected">отклонённые</option>
          <option value="applied">применённые</option>
        </select>
        <input type="text" id="queueSearch" placeholder="фильтр по классу или ID" style="width:240px">
        <span class="spacer"></span>
        <button class="primary" id="applyBtn">Применить принятые</button>
        <button class="ghost" id="rulesSuggestBtn">Правила по пропускам</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Класс</th><th>Вердикт</th><th>Окно</th><th>Предложение</th><th>Статус</th><th></th></tr></thead>
          <tbody id="queueRows"></tbody>
        </table>
      </div>
      <div class="msg" id="applyMsg"></div>
      <pre class="diff hidden" id="valueBox"></pre>
      <pre class="diff hidden" id="applyDiff"></pre>
    </section>

    <!-- ==================== BLOCKS ==================== -->
    <section data-section="blocks" class="hidden">
      <div class="toolbar">
        <input type="text" id="blockSearch" placeholder="фильтр по классу или месту" style="width:280px">
        <button id="blockReviewBtn">Разобрать блокировки</button>
        <span class="spacer"></span>
        <span class="mono muted" id="blocksSummary"></span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Время (местное)</th><th>Класс</th><th>Место</th><th>Хеш</th><th>Длина</th><th>Решение</th></tr></thead>
          <tbody id="blockRows"></tbody>
        </table>
      </div>
      <pre class="diff hidden" id="blockValueBox"></pre>
    </section>

    <!-- ==================== RULES ==================== -->
    <section data-section="rules" class="hidden">
      <div class="toolbar">
        <span class="muted" id="rulesHint">—</span>
        <span class="spacer"></span>
        <button class="primary" id="saveRulesBtn">Сохранить правила</button>
      </div>
      <div class="two-col" style="margin-bottom:18px">
        <div class="panel">
          <h2>Что прокси делает с классом</h2>
          <div class="table-wrap" style="max-height:430px;overflow:auto">
            <table><thead><tr><th>Класс</th><th>Действие</th></tr></thead>
            <tbody id="rulesActions"></tbody></table>
          </div>
          <div class="note"><span class="mono">mask</span> — заменить меткой,
            <span class="mono">block</span> — отказать в запросе,
            <span class="mono">allow</span> — пропустить как есть.</div>
        </div>
        <div class="panel">
          <h2>Маркеры <span class="right" id="rulesMarkersCount"></span></h2>
          <textarea id="rulesMarkers" class="editor tall" placeholder="одна фраза в строке"></textarea>
          <div class="note">Ищутся в «позиции грифа»: с начала строки или после слов «пометка»,
            «гриф», «штамп», «маркировка». Регистр не важен, пустые строки игнорируются.</div>
        </div>
      </div>
      <div class="panel" style="margin-bottom:18px">
        <h2>Allow-правила <span class="right" id="rulesAllowCount"></span></h2>
        <div class="note">Участки текста, внутри которых детекторы молчат: GUID, даты, URL, наши токены.
          Классы и precheck — через запятую; «*» в классах — все классы.</div>
        <div class="table-wrap">
          <table><thead><tr><th>Имя</th><th>Шаблон (regex)</th><th>Классы</th><th>precheck</th><th></th></tr></thead>
          <tbody id="rulesAllow"></tbody></table>
        </div>
        <div style="margin-top:10px"><button id="addAllowBtn">Добавить правило</button></div>
      </div>
      <div class="two-col" style="margin-bottom:18px">
        <div class="panel">
          <h2>Структура запроса</h2>
          <div class="form" style="grid-template-columns:1fr">
            <label>Разрешённые поля — по одному в строке</label>
            <textarea id="rulesFields" class="editor"></textarea>
            <label>Разрешённые роли</label>
            <textarea id="rulesRoles" class="editor"></textarea>
            <label>Разрешённые типы блоков</label>
            <textarea id="rulesBlockTypes" class="editor"></textarea>
            <label>Запрещённые типы блоков</label>
            <textarea id="rulesBlockedTypes" class="editor"></textarea>
          </div>
          <div class="note">Всё, чего нет в списке полей, блокируется как
            <span class="mono">unknown_field</span> — так и задумано в strict.</div>
        </div>
        <div class="panel">
          <h2>Лимиты и ответ</h2>
          <div class="form">
            <label>Кусок текста, символов</label><input type="number" id="rulesChunk" min="1000">
            <label>Текст в запросе</label><input type="number" id="rulesRequest" min="1000">
            <label>Бюджет детекции, мс</label><input type="number" id="rulesBudget" min="10">
            <label>Хранить журналы, дней</label><input type="number" id="rulesRetention" min="1">
            <label>Разворачивать текст ответа</label>
            <label class="inline"><input type="checkbox" id="rulesRestoreText"></label>
            <label>Разворачивать tool_use</label>
            <label class="inline"><input type="checkbox" id="rulesRestoreToolUse"></label>
          </div>
        </div>
      </div>
      <div class="panel" style="margin-bottom:18px">
        <h2>Правила из политики <span class="right" id="rulesExtraCount"></span></h2>
        <div class="note">Добавки к встроенным правилам — раздел
          <span class="mono">extra_rules</span>. Их предлагает модель по пропускам аудита
          и принимает человек; встроенные правила они не отключают.</div>
        <div class="table-wrap">
          <table><thead><tr><th>Имя</th><th>Класс</th><th>Шаблон (regex)</th><th>Флаги</th><th>Пояснение</th></tr></thead>
          <tbody id="rulesExtra"></tbody></table>
        </div>
      </div>
      <div class="panel">
        <h2>Правила детекторов <span class="right">только чтение · entities.py</span></h2>
        <div class="note">Регулярные выражения живут в коде вместе с тестами: их правят в
          <span class="mono">redactrail/entities.py</span>, а не в админке.</div>
        <div class="table-wrap" style="max-height:360px;overflow:auto">
          <table><thead><tr><th>Класс</th><th>Шаблон</th><th>precheck</th><th>Проверка</th></tr></thead>
          <tbody id="rulesDetectors"></tbody></table>
        </div>
      </div>
      <div class="msg" id="rulesMsg"></div>
      <pre class="diff hidden" id="rulesDiff"></pre>
    </section>

    <!-- ==================== CHANGES ==================== -->
    <section data-section="changes" class="hidden">
      <div class="toolbar">
        <span class="muted" id="changesHint">—</span>
        <span class="spacer"></span>
        <button class="primary" id="applyBtn2">Применить принятые</button>
      </div>
      <div class="split">
        <div class="panel">
          <h2>Что изменится</h2>
          <div class="list" id="changesList"></div>
        </div>
        <div class="panel">
          <h2>Diff policy.json</h2>
          <pre class="diff" id="changesDiff">нажмите «Применить принятые» — здесь появится diff</pre>
          <div class="msg" id="changesMsg"></div>
        </div>
      </div>
    </section>

    <!-- ==================== PROCESSES ==================== -->
    <section data-section="processes" class="hidden">
      <div class="cards" style="margin-bottom:18px">
        <div class="card"><div class="l">Прокси · 8787</div><div class="v small" id="pProxy">…</div><div class="hint" id="pProxyHint"></div></div>
        <div class="card"><div class="l">Модель аудита</div><div class="v small" id="pModel">…</div><div class="hint" id="pModelHint"></div></div>
        <div class="card"><div class="l">Админка</div><div class="v small" id="pAdmin">…</div><div class="hint" id="pAdminHint"></div></div>
        <div class="card"><div class="l">Аудит</div><div class="v small" id="pAudit">…</div><div class="hint" id="pAuditHint"></div></div>
      </div>

      <div class="two-col" style="margin-bottom:18px">
        <div class="panel">
          <h2>Настройки аудита</h2>
          <div class="form">
            <label>Адрес модели</label><input type="text" id="revUrl">
            <label>Модель</label><input type="text" id="revModel">
            <label>Каталог сессий</label><input type="text" id="revSessions">
            <label>Дней в проходе</label><input type="number" id="revDays" min="1">
            <label>Лимит фрагментов (0 — весь текст)</label><input type="number" id="revLimit" min="0">
          </div>
          <div style="margin-top:14px"><button class="primary" id="saveReviewBtn">Сохранить настройки</button>
            <span class="msg" id="revSaveMsg"></span></div>
          <div class="note">Пишется в <span class="mono">policy.json → review</span> с бэкапом; применяется сразу.</div>
        </div>
        <div class="panel">
          <h2>Запуск аудита <span class="right" id="revStatus">—</span></h2>
          <label class="inline"><input type="checkbox" id="revNoLlm"> без модели — только чтение и маскировка</label>
          <label class="inline"><input type="checkbox" id="revResume"> продолжить с места остановки</label>
          <div style="margin-top:14px"><button class="primary" id="runReviewBtn">Запустить</button>
            <button id="cancelReviewBtn">Остановить</button></div>
          <div class="note">Полный проход по умолчанию: лимит 0 — весь текст. Галочка «продолжить»
            пропускает события, уже проверенные прошлыми прогонами (курсор в
            <span class="mono">state/audit-cursor.json</span>); без неё аудит честно перечитывает
            всё окно и обновляет отметку. Модель отвечает ~7–9 секунд на фрагмент, поэтому
            большой прогон идёт долго; «Остановить» завершает его после текущего фрагмента,
            отчёт сохраняется.</div>
          <div class="msg" id="revCursor"></div>
          <div class="list" id="lastReport" style="margin-top:14px"></div>
        </div>
      </div>

      <div class="panel">
        <h2>Автозапуск <span class="right" id="autostartNote"></span></h2>
        <div class="list" id="autostartList"></div>
        <div style="margin-top:14px">
          <button class="primary" id="restartProxyBtn">Перезапустить прокси</button>
          <span class="msg" id="restartProxyMsg"></span>
        </div>
        <div class="note">Задача <span class="mono">redactrail-supervisor</span> при входе в
          систему запускает <span class="mono">scripts/supervise.ps1</span>: он раз в 10 секунд
          проверяет порты 8787 и 8788 и поднимает упавшее. Кнопка завершает процесс прокси —
          супервизор поднимает его заново; админка продолжает работать. Ставится
          <span class="mono">scripts/install-autostart.ps1</span>, снимается
          <span class="mono">scripts/uninstall-autostart.ps1</span>.</div>
      </div>

      <div class="panel">
        <h2>Журналы <span class="right" id="journalNote"></span></h2>
        <div class="table-wrap">
          <table><thead><tr><th>Файл</th><th>Размер</th></tr></thead><tbody id="journal"></tbody></table>
        </div>
      </div>
    </section>

    <!-- ==================== SETTINGS ==================== -->
    <section data-section="settings" class="hidden">
      <div class="split">
        <div class="panel">
          <h2>Что делает прокси</h2>
          <div class="form">
            <label>Режим</label>
            <select id="modeSel">
              <option value="strict">strict — маскировать и блокировать</option>
              <option value="audit">audit — только записывать</option>
              <option value="off">off — прозрачный прокси</option>
            </select>
            <label>Картинки и вложения</label>
            <label class="inline"><input type="checkbox" id="imgChk"> блокировать</label>
            <label>Секреты</label>
            <select id="secSel"><option value="mask">маскировать</option><option value="block">блокировать</option><option value="allow">пропускать</option></select>
            <label>Маркеры</label>
            <select id="mkSel"><option value="mask">маскировать</option><option value="block">блокировать</option><option value="allow">пропускать</option></select>
          </div>
          <div style="margin-top:16px"><button class="primary" id="saveModeBtn">Сохранить режим</button>
            <button id="saveImagesBtn">Сохранить картинки</button>
            <button id="saveSecretsBtn">Сохранить секреты</button>
            <button id="saveMarkersBtn">Сохранить маркеры</button></div>
          <div class="msg" id="settingsMsg"></div>
          <div class="note">Любая правка переписывает <span class="mono">policy.json</span> с бэкапом и применяется на следующем запросе — прокси перечитывает политику сам.</div>
        </div>
        <div class="panel">
          <h2>Политика</h2>
          <div class="list" id="policyList"></div>
          <div class="note" id="policyNote"></div>
        </div>
      </div>
    </section>
    <!-- ==================== CHECK ==================== -->
    <section data-section="check" class="hidden">
      <div class="panel">
        <h2>Проверка текста</h2>
        <div class="note">Вставьте фрагмент — покажем, что уйдёт провайдеру. Текст не сохраняется
          и не отправляется в модель; в журнал попадут только классы и длина.</div>
        <textarea id="checkInput" placeholder="Например: Иван Петров, телефон +7 999 123-45-67, почта ivan@example.ru"
          style="width:100%;min-height:150px;margin-top:12px;padding:10px;border:1px solid var(--border);border-radius:10px;font:inherit;resize:vertical"></textarea>
        <div style="margin-top:12px"><button class="primary" id="checkBtn">Проверить</button>
          <span class="msg" id="checkSummary"></span></div>
        <pre class="log" id="checkOutput" style="margin-top:14px">результат появится здесь</pre>
      </div>
    </section>
  </div>
</main>

<script>
const state = {data: null, processes: null, review: null, rules: null};

function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function $(id){return document.getElementById(id);}
function show(id, value){const node=$(id); if(node) node.textContent = value;}
function fmt(n){return Number(n||0).toLocaleString('ru-RU');}
function fmtTime(value, full){
  if (!value) return '';
  const date = new Date(value);
  if (isNaN(date.getTime())) return String(value);
  return full ? date.toLocaleString('ru-RU') : date.toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'});
}

function currentView(){
  const hash = (location.hash||'#dashboard').slice(1);
  return document.querySelector(`#nav a[data-view="${hash}"]`) ? hash : 'dashboard';
}
function route(){
  const view = currentView();
  document.querySelectorAll('section[data-section]').forEach(s => {
    s.classList.toggle('hidden', s.dataset.section !== view);
  });
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('active', a.dataset.view === view));
  const titles = {dashboard:'Сводка', queue:'Очередь предложений', blocks:'Блокировки', rules:'Правила', changes:'Изменения', processes:'Процессы', settings:'Настройки', check:'Проверка'};
  const subs = {dashboard:'что происходит с запросами', queue:'предложения от ревью', blocks:'события блокировок', rules:'что разрешено, что маскируется, что блокируется', changes:'правки policy.json', processes:'прокси, модель, аудит, журналы', settings:'режим и фильтры', check:'что уйдёт провайдеру'};
  show('title', titles[view]); show('subtitle', subs[view]);
  if (view === 'processes') loadProcesses();
  if (view === 'settings') loadPolicy();
  if (view === 'rules') loadRules();
  if (view === 'dashboard') loadDashboard();
}

async function getJSON(url){const r = await fetch(url); if(!r.ok) throw new Error(url + ': ' + r.status); return r.json();}
async function postJSON(url, body){
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body||{})});
  return r.json();
}

async function loadDashboard(){
  try {
    const data = await getJSON('/api/dashboard');
    const maximum = Math.max(1, ...data.hourly.map(item => item.requests));
    $('hourly').innerHTML = data.hourly.map(item => {
      const height = Math.round((item.requests / maximum) * 100);
      return `<div class="col" title="${item.hour}:00 — ${item.requests}">
        <i style="height:${item.requests ? Math.max(3, height) : 1}%;opacity:${item.requests ? 1 : .18}"></i>
        <span>${String(item.hour).padStart(2, '0')}</span></div>`;
    }).join('');
    const total = data.hourly.reduce((sum, item) => sum + item.requests, 0);
    show('hourlyHint', total + ' за ' + ((data.stats && data.stats.day) || 'сегодня'));
    const lastRun = data.last_request;
    if (lastRun) {
      show('lastReqWhen', fmtTime(lastRun.time, true));
      const maskedRows = Object.entries(lastRun.masked || {}).map(([klass, count]) =>
        `<div class="item"><span class="klass">${esc(klass)}</span><span class="meta">${count}</span></div>`).join('');
      $('lastRequest').innerHTML =
        `<div class="item"><span>Размер контекста</span><span class="meta">${Math.round((lastRun.bytes || 0) / 1024)} КБ</span></div>`
        + `<div class="item"><span>Заблокировано</span><span class="meta">${esc(lastRun.blocked || 'нет')}</span></div>`
        + maskedRows
        + `<div class="note">Счётчики — срабатывания в этом запросе. В сводке выше считается число разных значений.</div>`;
    } else {
      $('lastRequest').innerHTML = '<div class="empty">запросов пока не было</div>';
    }
    const runs = data.audit_runs || [];
    $('auditRuns').innerHTML = runs.length ? runs.slice().reverse().map(run => {
      const summary = run.summary || {};
      const label = run.state === 'error' ? 'ошибка' : ('фрагментов ' + (summary.chunks || 0) + ', находок ' + (summary.findings || 0)
        + (summary.boundaries ? ', разрывов ' + summary.boundaries : ''));
      return `<div class="item"><span class="mono faint">${esc(fmtTime(run.finished || run.started, true))}</span>
        <span class="tag ${run.state === 'error' ? 'bad' : 'ok'}">${esc(run.state || '?')}</span>
        <span class="muted">${esc(label)}</span>
        <span class="meta">${esc(run.model || '')}</span></div>`;
    }).join('') : '<div class="empty">аудит ещё не запускался</div>';
    show('runsHint', runs.length ? ('всего ' + runs.length + ' в истории') : '');
    const events = data.logs || [];
    $('eventLog').textContent = events.length ? events.map(item => {
      const time = String(item.time || '').replace('T', ' ').slice(11, 19);
      const rest = Object.entries(item).filter(([key]) => !['time', 'event'].includes(key))
        .map(([key, value]) => key + '=' + (typeof value === 'object' ? JSON.stringify(value) : value)).join(' ');
      return `${time}  ${String(item.event || '?').padEnd(18)} ${rest}`;
    }).join('\\n') : 'пока пусто';
  } catch (error) {
    show('hourlyHint', 'нет данных: ' + error.message);
  }
}

async function checkText(){
  const text = $('checkInput').value;
  const data = await postJSON('/api/check', {text});
  if (data.error) { $('checkOutput').textContent = 'ошибка: ' + data.error; return; }
  $('checkOutput').textContent = data.masked;
  const classes = Object.entries(data.classes || {}).map(([klass, count]) => klass + ' ' + count).join(', ');
  show('checkSummary', data.mode === 'off'
    ? 'режим off: уйдёт как есть'
    : (data.blocked ? ('заблокировано: ' + data.blocked)
    : (classes ? ('замаскировано: ' + classes) : 'ничего не найдено — уйдёт как есть')));
}

async function loadState(){
  try {
    await _loadState();
    show('subtitle', 'обновлено ' + new Date().toLocaleTimeString('ru-RU'));
  } catch (error) {
    show('subtitle', 'нет данных: ' + (error && error.message ? error.message : error));
  }
}
async function _loadState(){
  const data = await getJSON('/api/state');
  state.data = data;
  const masked = Object.values(data.stats.masked||{}).reduce((a,b)=>a+b,0);
  const unique = Object.values(data.stats.unique||{}).reduce((a,b)=>a+b,0);
  const blocked = Object.values(data.stats.blocked||{}).reduce((a,b)=>a+b,0);
  const day = data.stats.day || 'сегодня';
  const partial = !!data.stats.unique_partial;
  const period = partial ? 'с момента обновления' : ('за ' + day);
  show('kpiRequests', fmt(data.stats.requests));
  show('kpiRequestsHint', 'за ' + day);
  // «Замаскировано» — это разные значения; «срабатываний» больше, потому что
  // DSH пересылает всю переписку в каждом запросе. Если учёт разных значений
  // ещё не было включён в журнале, честнее назвать цифру срабатываниями.
  if (unique && !partial) {
    show('kpiMaskedLabel', 'Разных значений');
    show('kpiMasked', fmt(unique));
    show('kpiMaskedHint', Object.keys(data.stats.unique).length + ' классов · ' + fmt(masked) + ' срабатываний');
  } else if (unique) {
    show('kpiMaskedLabel', 'Разных значений (частично)');
    show('kpiMasked', fmt(unique));
    show('kpiMaskedHint', Object.keys(data.stats.unique).length + ' классов · ' + fmt(masked) + ' срабатываний · учёт с последнего запуска');
  } else {
    show('kpiMaskedLabel', 'Срабатываний');
    show('kpiMasked', fmt(masked));
    show('kpiMaskedHint', Object.keys(data.stats.masked||{}).length + ' классов · история переотправляется');
  }
  show('kpiBlocked', fmt(blocked));
  show('kpiBlockedHint', 'за ' + day);
  show('kpiPending', fmt(data.pending));
  show('kpiPendingHint', data.changes && data.changes.length ? (data.changes.length + ' принято к применению') : 'нет принятых');
  show('modeName', data.mode);
  $('modeSel').value = data.mode;
  show('footMode', data.mode);
  show('footVersion', data.version);
  show('navPending', data.pending);
  show('navBlocks', (data.blocks||[]).length);
  show('queueHint', data.suggestions.length ? (data.pending + ' ждут решения · ' + data.suggestions.length + ' всего') : 'пусто');
  if (unique && !partial) {
    renderBars(data.stats.unique, 'разных значений ' + period);
  } else if (unique) {
    renderBars(data.stats.unique, 'разных значений с последнего запуска');
  } else {
    renderBars(data.stats.masked, 'срабатываний за ' + day + ' · история переотправляется');
  }
  renderCache(data.cache);
  renderLastBlocks(data.blocks||[]);
  renderQueuePreview(data.suggestions||[]);
  renderQueue(data.suggestions||[]);
  renderBlocks(data.blocks||[]);
  renderChanges(data.changes||[]);
  if (data.settings) {
    $('imgChk').checked = !!data.settings.images_blocked;
    $('secSel').value = data.settings.secrets || 'mask';
    $('mkSel').value = data.settings.markers || 'mask';
    show('settingsMsg', '');
  }
}

function renderCache(cache){
  if (!cache) {
    show('cacheInfo', 'кеш детекции: прокси ещё не присылал статистику');
    return;
  }
  const total = cache.hits + cache.misses;
  const rate = total ? Math.round(cache.hits / total * 100) : 0;
  show('cacheInfo', `кеш детекции: ${fmt(cache.hits)} попаданий · ${fmt(cache.misses)} промахов · ${rate}% · ${cache.size||0}/${cache.limit||0}`);
}

function renderBars(masked, hint){
  const entries = Object.entries(masked).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const max = entries.length ? entries[0][1] : 1;
  $('bars').innerHTML = entries.length ? entries.map(([klass,count]) =>
    `<div class="bar-row"><span class="cls">${esc(klass)}</span><span class="bar"><i style="width:${Math.max(2,Math.round(count/max*100))}%"></i></span><span class="n">${fmt(count)}</span></div>`
  ).join('') : '<div class="empty">пока ничего не маскировалось</div>';
  if (hint) show('barsHint', hint);
}

function renderLastBlocks(blocks){
  const recent = blocks.slice(-5).reverse();
  $('lastBlocks').innerHTML = recent.length ? recent.map(b =>
    `<div class="item"><span class="tag warn">${esc(b['class']||'?')}</span><span class="mono muted">${esc(b.where||'')}</span><span class="meta">${esc(fmtTime(b.time))}</span></div>`
  ).join('') : '<div class="empty">блокировок не было</div>';
  show('blocksCount', blocks.length + ' за 7 дней');
}

function queueRow(item, compact){
  const verdict = item.verdict ? `<span class="verdict ${item.verdict === 'ложное' ? 'fp' : (item.verdict === 'настоящее' ? 'tp' : 'unsure')}">${esc(item.verdict)}${item.count ? ' · ' + item.count + '×' : ''}</span>` : '—';
  const peek = (item.kind === 'missed_pii' || item.kind === 'add_allow' || item.kind === 'boundary')
    ? `<button class="small ghost" onclick="showValue('${esc(item.id)}')">Показать</button> ` : '';
  const buttons = item.decision === 'pending'
    ? peek + `<button class="small" onclick="act('${esc(item.id)}','accept')">Принять</button> <button class="small ghost" onclick="act('${esc(item.id)}','reject')">Отклонить</button>`
    : `<span class="faint">${esc(item.decision)}</span>`;
  if (compact) {
    return `<div class="item"><span class="mono faint">#${esc(item.id)}</span><span class="klass">${esc(item.class||'')}</span>
      <span class="muted" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(item.action||item.kind||'')}</span>
      <span class="meta">${buttons}</span></div>`;
  }
  return `<tr><td class="mono faint">#${esc(item.id)}</td><td><span class="klass">${esc(item.class||'')}</span></td>
    <td>${verdict}</td><td><div class="win">${esc(item.window||'')}</div></td>
    <td>${esc(item.action||item.kind||'')}</td><td class="faint">${esc(item.decision||'')}</td>
    <td class="actions">${buttons}</td></tr>`;
}

function renderQueuePreview(items){
  const pending = items.filter(i => i.decision === 'pending').slice(0,3);
  $('queuePreview').innerHTML = pending.length ? `<div class="list">${pending.map(i => queueRow(i,true)).join('')}</div>`
    : '<div class="empty">предложений пока нет — их создаёт ночной аудит</div>';
}

function filteredQueue(){
  const data = state.data || {suggestions:[]};
  const mode = $('queueFilter').value;
  const needle = ($('queueSearch').value||'').toLowerCase();
  return data.suggestions.filter(item => {
    if (mode !== 'all' && (item.decision||'pending') !== mode) return false;
    if (!needle) return true;
    return (String(item.id)+' '+String(item.class||'')).toLowerCase().includes(needle);
  });
}

function renderQueue(items){
  const rows = filteredQueue();
  const empty = $('queueFilter').value === 'pending'
    ? 'нерешённых нет — история в фильтре «все»'
    : 'ничего нет';
  $('queueRows').innerHTML = rows.length ? rows.map(i => queueRow(i,false)).join('')
    : `<tr><td colspan="7" class="empty">${esc(empty)}</td></tr>`;
}

function renderBlocks(blocks){
  const needle = ($('blockSearch').value||'').toLowerCase();
  const rows = blocks.filter(b => !needle || (String(b['class'])+' '+String(b.where)).toLowerCase().includes(needle)).slice(-100).reverse();
  $('blockRows').innerHTML = rows.length ? rows.map(b => {
    const klass = String(b['class'] || '');
    const suggestable = (klass === 'unknown_field' || klass === 'unknown_block') && /'[^']+'/.test(String(b.where || ''));
    const button = suggestable
      ? ` <button class="small" data-where="${esc(b.where || '')}" data-class="${esc(klass)}" onclick="suggestBlock(this)">В allow</button>`
      : '';
    const peek = (b.hash && b.length)
      ? ` <button class="small ghost" data-time="${esc(b.time || '')}" data-klass="${esc(klass)}" data-hash="${esc(b.hash)}" data-length="${b.length}" onclick="showBlockValue(this)">Показать</button>`
      : '';
    return `<tr><td class="mono">${esc(fmtTime(b.time, true))}</td><td><span class="tag bad">${esc(klass || '?')}</span></td>
     <td class="mono muted">${esc(b.where||'')}</td><td class="mono faint">${esc(b.hash || '—')}</td>
     <td class="mono">${esc(b.length ? b.length : '—')}</td><td class="faint">${esc(b.decision||'')}${peek}${button}</td></tr>`;
  }).join('') : '<tr><td colspan="6" class="empty">блокировок нет</td></tr>';
  show('blocksSummary', rows.length + ' из ' + blocks.length);
}

async function suggestBlock(button){
  const data = await postJSON('/api/blocks/suggest', {where: button.dataset.where, class: button.dataset.class});
  if (data.error) { show('blocksSummary', 'ошибка: ' + data.error); return; }
  show('blocksSummary', 'предложение добавлено: ' + data.detail);
  await loadState();
}

async function reviewBlocks(){
  const data = await postJSON('/api/blocks/review');
  show('blocksSummary', data.error ? ('ошибка: ' + data.error)
    : ('найдено ' + data.found + ', добавлено ' + data.added));
  await loadState();
}

async function showBlockValue(button){
  const box = $('blockValueBox');
  if (!box) return;
  box.classList.remove('hidden');
  box.textContent = 'ищу фразу в сессиях — это может занять несколько секунд…';
  const record = {
    time: button.dataset.time || '',
    'class': button.dataset.klass || '',
    hash: button.dataset.hash || '',
    length: Number(button.dataset.length || 0),
  };
  try {
    const data = await postJSON('/api/blocks/value', record);
    if (data.error) { box.textContent = 'недоступно: ' + data.error; return; }
    const lines = ['фраза: ' + data.value, 'найдено: ' + data.how];
    (data.matches || []).forEach((match, index) => {
      lines.push('', '[' + (index + 1) + '] ' + match.session, match.context);
    });
    lines.push('', 'значение не сохраняется: показано только здесь.');
    box.textContent = lines.join('\\n');
  } catch (error) {
    box.textContent = 'ошибка: ' + error;
  }
}

async function loadRules(){
  try {
    state.rules = await getJSON('/api/rules');
    renderRules(state.rules);
  } catch (error) {
    show('rulesHint', 'нет данных: ' + (error && error.message ? error.message : error));
  }
}

function renderRules(data){
  if (!data) return;
  const actions = data.actions || {};
  const allowed = data.actions_allowed || ['mask', 'block', 'allow'];
  $('rulesActions').innerHTML = (data.classes || []).map(name => {
    const current = actions[name] || 'mask';
    const options = allowed.map(action =>
      `<option value="${esc(action)}"${action === current ? ' selected' : ''}>${esc(action)}</option>`).join('');
    return `<tr><td class="mono">${esc(name)}</td><td><select class="actionSel" data-class="${esc(name)}">${options}</select></td></tr>`;
  }).join('') || '<tr><td colspan="2" class="empty">классов нет</td></tr>';
  $('rulesMarkers').value = (data.markers || []).join('\\n');
  show('rulesMarkersCount', (data.markers || []).length + ' фраз');
  renderAllow(data.allow || []);
  const extra = data.extra_rules || [];
  show('rulesExtraCount', extra.length ? (extra.length + ' правил') : 'пока нет');
  $('rulesExtra').innerHTML = extra.length ? extra.map(rule => `
    <tr><td class="mono">${esc(rule.name||'')}</td><td><span class="klass">${esc(rule.class||'')}</span></td>
    <td class="mono">${esc(rule.pattern||'')}</td><td>${esc(rule.flags||'—')}</td>
    <td class="muted">${esc(rule.explanation||'')}</td></tr>`).join('')
    : '<tr><td colspan="5" class="empty">пока нет — их добавляет принятое предложение или человек в policy.json</td></tr>';
  const request = data.request || {};
  $('rulesFields').value = (request.allowed_fields || []).join('\\n');
  $('rulesRoles').value = (request.allowed_roles || []).join('\\n');
  $('rulesBlockTypes').value = (request.allowed_block_types || []).join('\\n');
  $('rulesBlockedTypes').value = (request.blocked_block_types || []).join('\\n');
  const limits = data.limits || {};
  $('rulesChunk').value = limits.chunk_chars;
  $('rulesRequest').value = limits.request_chars;
  $('rulesBudget').value = limits.budget_ms;
  $('rulesRetention').value = limits.retention_days;
  const restore = data.restore || {};
  $('rulesRestoreText').checked = !!restore.text;
  $('rulesRestoreToolUse').checked = !!restore.tool_use;
  $('rulesDetectors').innerHTML = (data.detectors || []).map(rule =>
    `<tr><td class="mono">${esc(rule.name)}</td>
     <td class="mono faint" style="max-width:520px;word-break:break-all">${esc(rule.pattern)}</td>
     <td class="mono faint">${esc((rule.precheck || []).join(', ') || '—')}</td>
     <td class="faint">${esc(rule.validator || 'форма')}</td></tr>`
  ).join('') || '<tr><td colspan="4" class="empty">правил нет</td></tr>';
  show('rulesHint', 'режим ' + (data.mode || '?') + ' · policy.json + entities.py');
  show('rulesMsg', '');
  $('rulesDiff').classList.add('hidden');
}

function renderAllow(rows){
  show('rulesAllowCount', rows.length + ' правил');
  $('rulesAllow').innerHTML = rows.map(rule => `
    <tr>
      <td><input type="text" class="allowName" value="${esc(rule.name)}" style="width:120px"></td>
      <td><input type="text" class="allowPattern" value="${esc(rule.pattern)}" style="width:100%"></td>
      <td><input type="text" class="allowClasses" value="${esc((rule.classes || []).join(', '))}" style="width:110px"></td>
      <td><input type="text" class="allowPrecheck" value="${esc((rule.precheck || []).join(', '))}" style="width:110px"></td>
      <td><button class="small ghost" onclick="removeAllow(this)">Удалить</button></td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">правил нет</td></tr>';
}

function removeAllow(button){
  const row = button.closest('tr');
  if (row) row.remove();
  const left = document.querySelectorAll('#rulesAllow input.allowName').length;
  show('rulesAllowCount', left + ' правил');
}

function addAllowRow(){
  const body = $('rulesAllow');
  if (body.querySelector('.empty')) body.innerHTML = '';
  const row = document.createElement('tr');
  row.innerHTML = `
      <td><input type="text" class="allowName" value="new_rule" style="width:120px"></td>
      <td><input type="text" class="allowPattern" value="" style="width:100%"></td>
      <td><input type="text" class="allowClasses" value="*" style="width:110px"></td>
      <td><input type="text" class="allowPrecheck" value="" style="width:110px"></td>
      <td><button class="small ghost" onclick="removeAllow(this)">Удалить</button></td>`;
  body.appendChild(row);
  show('rulesAllowCount', document.querySelectorAll('#rulesAllow input.allowName').length + ' правил');
}

function rulesLines(id){
  return ($(id).value || '').split('\\n').map(line => line.trim()).filter(Boolean);
}

async function saveRules(){
  const actions = {};
  document.querySelectorAll('#rulesActions select.actionSel').forEach(select => {
    actions[select.dataset.class] = select.value;
  });
  const allow = [...document.querySelectorAll('#rulesAllow input.allowName')].map(input => {
    const row = input.closest('tr');
    const split = selector => (row.querySelector(selector).value || '').split(',')
      .map(part => part.trim()).filter(Boolean);
    return {
      name: input.value.trim(),
      pattern: row.querySelector('.allowPattern').value.trim(),
      classes: split('.allowClasses'),
      precheck: split('.allowPrecheck'),
    };
  });
  const body = {
    actions: actions,
    markers: rulesLines('rulesMarkers'),
    allow: allow,
    request: {
      allowed_fields: rulesLines('rulesFields'),
      allowed_roles: rulesLines('rulesRoles'),
      allowed_block_types: rulesLines('rulesBlockTypes'),
      blocked_block_types: rulesLines('rulesBlockedTypes'),
    },
    limits: {
      chunk_chars: Number($('rulesChunk').value),
      request_chars: Number($('rulesRequest').value),
      budget_ms: Number($('rulesBudget').value),
      retention_days: Number($('rulesRetention').value),
    },
    restore: {text: $('rulesRestoreText').checked, tool_use: $('rulesRestoreToolUse').checked},
  };
  if (state.rules && state.rules.mode) body.mode = state.rules.mode;
  show('rulesMsg', 'сохраняю…');
  const data = await postJSON('/api/rules', body);
  if (data.error) { show('rulesMsg', 'ошибка: ' + data.error); return; }
  state.rules = data.rules;
  renderRules(data.rules);
  show('rulesMsg', 'сохранено, бэкап: ' + (data.backup || '—'));
  if (data.diff && data.diff.length) {
    const box = $('rulesDiff');
    box.classList.remove('hidden');
    box.innerHTML = data.diff.map(line => {
      const cls = line.startsWith('+') ? 'add' : line.startsWith('-') ? 'del' : 'ctx';
      return `<span class="${cls}">${esc(line)}</span>`;
    }).join('\\n');
  }
  await loadState();
}

function renderChanges(changes){
  const data = state.data || {};
  const total = (data.suggestions||[]).filter(i => i.decision === 'accepted').length;
  show('changesHint', total ? (total + ' предложений принято, ждут применения') : 'принятых предложений нет');
  $('changesList').innerHTML = changes.length ? changes.map(c =>
    `<div class="item"><span class="mono faint">#${esc(c.suggestion)}</span><span class="klass">${esc(c.action)}</span>
     <span class="muted">${esc(typeof c.value === 'string' ? c.value : JSON.stringify(c.value))}</span></div>`
  ).join('') : '<div class="empty">нет принятых правок</div>';
}

async function showValue(id){
  const box = $('valueBox');
  box.classList.remove('hidden');
  box.textContent = 'загружаю…';
  try {
    const response = await fetch('/api/candidates/' + encodeURIComponent(id));
    const data = await response.json();
    box.textContent = data.value ? ('значение: ' + data.value) : ('недоступно: ' + (data.error || response.status));
  } catch (error) {
    box.textContent = 'недоступно: ' + error;
  }
}

async function act(id, action){
  await postJSON(`/api/suggestions/${encodeURIComponent(id)}/${action}`);
  await loadState();
}

async function suggestRules(){
  show('queueHint', 'спрашиваю модель…');
  try {
    const data = await postJSON('/api/rules/suggest', {limit: 5});
    if (data.error) { show('queueHint', 'ошибка: ' + data.error); return; }
    show('queueHint', `создано ${data.created} из ${data.attempted} проверенных`);
    await loadState();
  } catch (error) {
    show('queueHint', 'ошибка: ' + error);
  }
}

async function applyPolicy(){
  const data = await postJSON('/api/policy/apply');
  const target = $('applyDiff') || $('changesDiff');
  if (data.diff) {
    target.classList.remove('hidden');
    target.innerHTML = data.diff.map(line => {
      const cls = line.startsWith('+') ? 'add' : line.startsWith('-') ? 'del' : 'ctx';
      return `<span class="${cls}">${esc(line)}</span>`;
    }).join('\\n');
  }
  show('applyMsg', data.error ? ('ошибка: ' + data.error) : ('бэкап: ' + (data.backup||'—')));
  show('changesMsg', data.error ? ('ошибка: ' + data.error) : ('бэкап: ' + (data.backup||'—')));
  await loadState();
}

async function saveSetting(key, value){
  const data = await postJSON('/api/settings', {[key]: value});
  show('settingsMsg', data.error ? ('ошибка: ' + data.error) : ('сохранено, бэкап: ' + data.backup));
  await loadState();
}

function loadPolicy(){
  const d = state.data; if (!d) return;
  const settings = d.settings || {};
  $('modeSel').value = settings.mode || d.mode;
  $('imgChk').checked = !!settings.images_blocked;
  $('secSel').value = settings.secrets || 'mask';
  $('mkSel').value = settings.markers || 'mask';
  $('policyList').innerHTML = `
    <div class="item"><span>Классов с маскировкой</span><span class="meta">${Object.keys(d.stats.masked||{}).length}</span></div>
    <div class="item"><span>Бюджет детекции</span><span class="meta">${settings.budget_ms||'—'} мс</span></div>
    <div class="item"><span>Версия</span><span class="meta mono">${esc(d.version)}</span></div>`;
  show('policyNote', 'Файл policy.json, бэкапы рядом: policy.json.bak-<время>.');
}

async function loadProcesses(){
  try {
    const p = await getJSON('/api/processes');
    const s = await getJSON('/api/review/status');
    state.processes = p; state.review = s;
    show('pProxy', p.proxy.reachable ? 'отвечает' : 'нет связи');
    show('pProxyHint', p.proxy.reachable ? (p.proxy.body||'') : (p.proxy.error||''));
    $('footDot').className = p.proxy.reachable ? 'dot' : 'dot off';
    show('footProxy', p.proxy.reachable ? 'прокси отвечает' : 'прокси молчит');
    show('pModel', p.model.reachable ? 'доступна' : 'нет связи');
    show('pModelHint', (p.model.models||[]).join(', ') || p.model.error || p.model.models_url || '');
    show('pAdmin', 'uptime ' + p.admin.uptime_s + ' c');
    show('pAdminHint', 'порт ' + (p.admin.port||'—') + ' · v' + p.admin.version);
    renderAutostart(p.autostart || {});
    show('pAudit', s.state);
    if (s.config) {
      $('revUrl').value = s.config.base_url; $('revModel').value = s.config.model;
      $('revSessions').value = s.config.sessions; $('revDays').value = s.config.days; $('revLimit').value = s.config.limit;
    }
    const summary = s.summary ? ('фрагментов ' + s.summary.chunks + ', находок ' + s.summary.findings
      + (s.summary.boundaries ? ', разрывов ' + s.summary.boundaries : '')
      + ', ошибок ' + (s.summary.errors||0)
      + (s.summary.cancelled ? ' — остановлен' : '')
      + (s.summary.resumed ? ' · пропущено событий ' + (s.summary.skipped_events || 0) : '')) : 'не запускался';
    show('revStatus', s.state === 'running'
      ? ('выполняется… обработано ' + (s.processed || 0))
      : (s.error ? 'ошибка'
      : (s.summary ? summary
      : (s.last_run ? ('последний: ' + fmtTime(s.last_run.finished || s.last_run.started, true) + ' — ' + (s.last_run.state || '?')) : 'не запускался'))));
    show('pAuditHint', s.summary ? summary : (s.last_run ? ('последний запуск: ' + fmtTime(s.last_run.finished || s.last_run.started, true)) : 'запусков не было'));
    const cursor = s.cursor || {};
    show('revCursor', cursor.sessions
      ? ('курсор: ' + cursor.sessions + ' сессий, ' + fmt(cursor.events || 0) + ' событий — «продолжить» начнёт после них')
      : 'курсора нет: первое «продолжить» проверит всё, дальше будет только новое');
    const last = s.last_report;
    $('lastReport').innerHTML = last ? `
      <div class="item"><span>Последний отчёт</span><span class="meta mono">${esc(last.file)}</span></div>
      <div class="item"><span>Модель</span><span class="meta">${esc(last.model||'—')}</span></div>
      <div class="item"><span>Фрагментов / находок / разрывов</span><span class="meta">${last.chunks} / ${last.findings} / ${last.boundaries || 0}</span></div>` : '<div class="empty">отчётов нет</div>';
    show('journalNote', 'хранится ' + p.journal.retention_days + ' дней · ' + p.journal.bytes_total + ' Б');
    $('journal').innerHTML = (p.journal.files||[]).length ? p.journal.files.map(f =>
      `<tr><td class="mono">${esc(f.name)}</td><td class="mono">${f.bytes} Б</td></tr>`).join('')
      : '<tr><td colspan="2" class="empty">журналов нет</td></tr>';
  } catch (error) {
    show('pProxy', 'ошибка'); show('pProxyHint', String(error));
  }
}

function renderAutostart(a){
  const supervisor = a.supervisor || {}, audit = a.audit || {};
  if (!a.available){
    show('autostartNote', 'только Windows');
    $('autostartList').innerHTML = '<div class="empty">задачи планировщика доступны только на Windows</div>';
    $('restartProxyBtn').disabled = true;
    return;
  }
  $('restartProxyBtn').disabled = !supervisor.installed;
  show('autostartNote', supervisor.installed ? 'автозапуск включён' : 'автозапуск не установлен');
  const row = (title, task, installed) =>
    `<div class="item"><span>${esc(title)}</span><span class="meta mono">${esc(task||'—')} · ${installed ? 'зарегистрирована' : 'нет'}</span></div>`;
  $('autostartList').innerHTML = row('Приложение (прокси + админка)', supervisor.task, supervisor.installed)
    + row('Ночной аудит', audit.task, audit.installed);
}

async function restartProxy(){
  const button = $('restartProxyBtn');
  const wasDisabled = button.disabled;
  button.disabled = true;
  show('restartProxyMsg', 'перезапускаю…');
  try {
    const data = await postJSON('/api/proxy/restart', {});
    const after = data.after || data.before || {};
    const hint = data.hint ? (' — ' + data.hint) : '';
    if (data.ok) {
      show('restartProxyMsg', 'прокси отвечает' + hint);
    } else {
      show('restartProxyMsg', 'не поднялся: ' + (after.error || 'нет ответа') + hint);
    }
  } catch (error) {
    show('restartProxyMsg', 'ошибка: ' + String(error));
  }
  button.disabled = wasDisabled;
  await loadProcesses();
}

async function saveReview(){
  const body = {review:{base_url:$('revUrl').value, model:$('revModel').value, sessions:$('revSessions').value,
    days:Number($('revDays').value), limit:Number($('revLimit').value)}};
  const data = await postJSON('/api/settings', body);
  show('revSaveMsg', data.error ? ('ошибка: ' + data.error) : ('сохранено, бэкап: ' + data.backup));
  await loadProcesses();
}

async function runReview(){
  show('revStatus', 'запускаю…');
  await postJSON('/api/review/run', {days:Number($('revDays').value), limit:Number($('revLimit').value),
    no_llm:$('revNoLlm').checked, resume:$('revResume').checked});
  setTimeout(loadProcesses, 800);
}

// wiring
window.addEventListener('hashchange', route);
window.addEventListener('error', (event) => {
  show('subtitle', 'ошибка страницы: ' + (event.message || 'см. консоль'));
});
$('queueFilter').addEventListener('change', () => renderQueue());
$('queueSearch').addEventListener('input', () => renderQueue());
$('blockSearch').addEventListener('input', () => renderBlocks(state.data ? state.data.blocks : []));
$('applyBtn').addEventListener('click', applyPolicy);
$('applyBtn2').addEventListener('click', applyPolicy);
$('rulesSuggestBtn').addEventListener('click', suggestRules);
$('saveReviewBtn').addEventListener('click', saveReview);
$('runReviewBtn').addEventListener('click', runReview);
$('cancelReviewBtn').addEventListener('click', async () => { await postJSON('/api/review/cancel'); loadProcesses(); });
$('restartProxyBtn').addEventListener('click', restartProxy);
$('blockReviewBtn').addEventListener('click', reviewBlocks);
$('saveRulesBtn').addEventListener('click', saveRules);
$('addAllowBtn').addEventListener('click', addAllowRow);
$('saveModeBtn').addEventListener('click', () => saveSetting('mode', $('modeSel').value));
$('saveImagesBtn').addEventListener('click', () => saveSetting('images_blocked', $('imgChk').checked));
$('saveSecretsBtn').addEventListener('click', () => saveSetting('secrets', $('secSel').value));
$('saveMarkersBtn').addEventListener('click', () => saveSetting('markers', $('mkSel').value));
$('checkBtn').addEventListener('click', checkText);
$('refreshBtn').addEventListener('click', async () => { await loadState(); if (currentView()==='processes') await loadProcesses(); });

route();
loadState().catch(error => { show('subtitle', 'ошибка загрузки: ' + error); });
loadProcesses();
loadDashboard();
setInterval(() => {
  if (document.hidden) return;
  loadState().catch(() => {});
  if (currentView() === 'processes') loadProcesses();
  if (currentView() === 'dashboard') loadDashboard();
}, 5000);
</script>
</body>
</html>
"""


def build_server(
    port: int = DEFAULT_PORT, root: str | Path = ".", token: str | None = None
) -> AdminServer:
    root_path = Path(root).resolve()
    admin_token = token or load_token(root_path / TOKEN_FILE)
    return AdminServer(("127.0.0.1", port), root_path, admin_token)


def _open_browser(url: str) -> None:
    """Открыть админку в браузере. Не критично, если не получилось."""
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001 - окружение без браузера не должно валить админку
        return


def main(argv: list[str] | None = None) -> int:
    enable_utf8_output()
    parser = argparse.ArgumentParser(description="Админка ревью redactrail")
    parser.add_argument("--port", type=int, default=int(os.environ.get("REDACTRAIL_ADMIN_PORT", DEFAULT_PORT)))
    parser.add_argument("--root", default=os.environ.get("REDACTRAIL_ROOT", "."))
    parser.add_argument("--no-browser", action="store_true", help="не открывать браузер автоматически")
    args = parser.parse_args(argv)

    server = build_server(port=args.port, root=args.root)
    url = f"http://127.0.0.1:{server.port}/?token={server.token}"
    url_file = Path(args.root) / "state" / "admin-url.txt"
    try:
        url_file.parent.mkdir(parents=True, exist_ok=True)
        url_file.write_text(url + "\n", encoding="utf-8")
    except OSError:
        url_file = None
    print(f"[redactrail admin] {url}")
    if url_file is not None:
        print(f"[redactrail admin] ссылка сохранена: {url_file}")
    if not args.no_browser:
        threading.Timer(0.7, _open_browser, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[redactrail admin] остановлен")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
