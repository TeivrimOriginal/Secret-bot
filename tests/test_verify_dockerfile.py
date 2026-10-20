"""Тесты валидатора Dockerfile (`scripts/verify_dockerfile.py`).

Docker на этой машине нет, поэтому образ не собрать. Но Dockerfile всё
равно можно проверить — и нужно, потому что ошибка в нём выглядит
непонятно: «COPY failed: file not found» на шаге, который с виду
выглядит безобидно.

Тест проверяет две вещи: что валидатор ловит настоящие ошибки, и что
реальный Dockerfile проходит.

Ловится ошибка или нет — определяется тем, что валидатор возвращает 1
(есть непроход��нные проверки) или 0 (все прошли).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_dockerfile.py"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("secretbot_docker_verifier", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = _load()


#: Рабочий Dockerfile: все проверки на нём проходят.
#: Healthcheck читает порт из PORT — так же, как настоящий: порт задаёт
#: платформа, и зашитый 8080 в проверке означал бы «сервис здоров» на
#: неправильном порту.
GOOD_DOCKERFILE = """\
FROM python:3.12-slim-bookworm
WORKDIR /app
ENV DB_PATH=/data/links.db
EXPOSE 8080
RUN mkdir -p /data && chmod 777 /data
USER app
HEALTHCHECK CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/healthz')"
CMD ["python", "-u", "launcher.py"]
"""

#: config.py, на который смотрит валидатор: порт 8080 и чтение PORT.
GOOD_CONFIG = (
    "BOT_TOKEN = os.getenv('BOT_TOKEN', '')\n"
    'WEB_PORT = int(os.getenv("WEB_PORT") or os.getenv("PORT") or "8080")\n'
)


def _project(tmp_path: Path, dockerfile: str = GOOD_DOCKERFILE,
             config: str = GOOD_CONFIG,
             web_app: str = 'app.add_api_route("/healthz", healthz)\n',
             ignore: str = "*.db\n.venv/\nsecret-bot.env\ntests/\nandroid/\n") -> None:
    """Создает минимальный проект, который валидатор считает рабочим."""
    (tmp_path / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    (tmp_path / "config.py").write_text(config, encoding="utf-8")
    (tmp_path / "web_app.py").write_text(web_app, encoding="utf-8")
    (tmp_path / ".dockerignore").write_text(ignore, encoding="utf-8")


def _run_against(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    """Прогоняет валидатор на файлах из tmp_path."""
    monkeypatch.setattr(verifier, "ROOT", tmp_path)
    monkeypatch.setattr(verifier, "DOCKERFILE", tmp_path / "Dockerfile")
    monkeypatch.setattr(verifier, "DOCKERIGNORE", tmp_path / ".dockerignore")
    monkeypatch.setattr(verifier, "CONFIG", tmp_path / "config.py")
    return verifier.main()


class TestTheRealDockerfile:
    def test_the_real_dockerfile_passes(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Dockerfile, который поедет на хостинг, должен проходить проверку."""
        assert verifier.main() == 0, capsys.readouterr().out


class TestTheFixtureItself:
    def test_a_good_project_passes(self, tmp_path: Path,
                                   monkeypatch: pytest.MonkeyPatch) -> None:
        """Если эталон не проходит, все остальные тесты бессмысленны.

        Это проверка самих тестов: эталонный Dockerfile собран так, чтобы
        проходить все проверки валидатора. Если он не проходит — чинить
        нужно эталон, а не код.
        """
        _project(tmp_path)
        assert _run_against(tmp_path, monkeypatch) == 0


class TestWhatTheValidatorCatches:
    def test_a_missing_copy_source_is_caught(self, tmp_path: Path,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
        """Файл, которого нет, — самая частая ошибка в Dockerfile.

        Ошибка проявляется на `docker build` и звучит как проблема Docker,
        хотя дело в пути к файлу.
        """
        _project(
            tmp_path,
            dockerfile=GOOD_DOCKERFILE.replace(
                'CMD ["python", "-u", "launcher.py"]',
                'COPY нет-такого-файла.py ./\nCMD ["python", "-u", "launcher.py"]',
            ),
        )
        assert _run_against(tmp_path, monkeypatch) == 1

    def test_a_root_user_is_caught(self, tmp_path: Path,
                                   monkeypatch: pytest.MonkeyPatch) -> None:
        """Запуск под root — это лишние права, и проверка должна это видеть."""
        _project(tmp_path, dockerfile=GOOD_DOCKERFILE.replace("USER app", "USER root"))
        assert _run_against(tmp_path, monkeypatch) == 1

    def test_a_missing_data_directory_is_caught(self, tmp_path: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
        """Каталог с базой должен создаваться при сборке.

        Без этого первая же запись в базу падает с PermissionError в
        контейнере — ошибка, которая выглядит как баг кода.
        """
        _project(
            tmp_path,
            dockerfile=GOOD_DOCKERFILE.replace("RUN mkdir -p /data && chmod 777 /data\n", ""),
        )
        assert _run_against(tmp_path, monkeypatch) == 1

    def test_a_healthcheck_for_a_missing_route_is_caught(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Healthcheck должен бить в существующий маршрут.

        Платформа считает сервис здоровым, пока ходит по этому адресу.
        Если маршрута нет, деплой не проходит — или, что хуже, проходит
        и потом отваливается.
        """
        _project(
            tmp_path,
            dockerfile=GOOD_DOCKERFILE.replace("/healthz", "/нет-такого"),
            web_app="",
        )
        assert _run_against(tmp_path, monkeypatch) == 1

    def test_a_missing_expose_is_caught(self, tmp_path: Path,
                                        monkeypatch: pytest.MonkeyPatch) -> None:
        """Без EXPOSE платформа не знает, на каком порту слушать."""
        _project(tmp_path, dockerfile=GOOD_DOCKERFILE.replace("EXPOSE 8080\n", ""))
        assert _run_against(tmp_path, monkeypatch) == 1

    def test_a_wrong_entrypoint_is_caught(self, tmp_path: Path,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
        """Точка входа должна быть launcher.py — он поднимает бота и сайт."""
        _project(
            tmp_path,
            dockerfile=GOOD_DOCKERFILE.replace(
                'CMD ["python", "-u", "launcher.py"]', 'CMD ["python", "что-то-else.py"]'
            ),
        )
        assert _run_against(tmp_path, monkeypatch) == 1

    def test_a_secret_in_the_dockerignore_is_required(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`.env` с токеном не должен попасть в образ."""
        _project(tmp_path, ignore="*.db\n")
        assert _run_against(tmp_path, monkeypatch) == 1


class TestWhatIsActuallyChecked:
    def test_the_syntax_directive_does_not_break_the_check(self) -> None:
        """Директива `# syntax=` перед FROM — это норма, а не ошибка.

        Первый вариант валидатора проверял `text.startswith("FROM ")` и
        ругался на любой файл с директивой, хотя образ собирался бы
        нормально.
        """
        import re

        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert re.search(r"^FROM\s+\S+", text, re.MULTILINE) is not None
        assert text.startswith("FROM ") is False, "проверка на startswith была бы хрупкой"

    def test_config_reads_the_paas_port(self) -> None:
        """config.py должен читать PORT.

        Порт задаёт платформа, а не человек. Если код слушает только на
        8080, сервис поднимается, но платформа не видит его и роняет по
        таймауту — в логах ни слова о настоящей причине.
        """
        config = (ROOT / "config.py").read_text(encoding="utf-8")
        assert 'os.getenv("PORT")' in config
        assert 'os.getenv("WEB_PORT")' in config
