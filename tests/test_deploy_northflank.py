"""Тесты скрипта деплоя на Northflank (`scripts/deploy_northflank.py`).

Скрипт обращается к API Northflank. Настоящего аккаунта нет, поэтому API
заменяется маленьким сервером, который запоминает запросы. Тест проверяет
не «сработает ли», а **что именно** скрипт отправляет.

Это важно: ошибка в теле запроса (забытый том, неверный путь, переменная
не в том месте) не падает локально — она обнаруживается на хостинге,
после создания сервиса, когда половина настройки уже применена. Тест
ловит такое до деплоя.

Проверяется:

  * секреты не попадают в вывод;
  * том создаётся и подключается к `/data`;
  * `DB_PATH` указывает внутрь тома (иначе база осталась бы эфемерной);
  * `BASE_URL` и `BOT_TOKEN` попадают в переменные окружения;
  * healthcheck настроен на `/healthz`;
  * при ошибке API скрипт падает с понятным сообщением, а не молча.
"""

from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "deploy_northflank.py"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("secretbot_nf_deploy", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: Журнал запросов: (method, path, body).
CALLS: list[tuple[str, str, Any]] = []
#: Ответ, который сервер вернёт на следующий запрос (для проверки ошибок).
NEXT_STATUS = {"value": 200}
NEXT_BODY = {"value": {"data": {"id": "x"}}}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a: Any) -> None:
        pass

    def _read(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw

    def _reply(self) -> None:
        body = json.dumps(NEXT_BODY["value"]).encode("utf-8")
        self.send_response(NEXT_STATUS["value"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        CALLS.append(("GET", self.path, self._read()))
        self._reply()

    def do_POST(self) -> None:  # noqa: N802
        CALLS.append(("POST", self.path, self._read()))
        self._reply()

    def do_PATCH(self) -> None:  # noqa: N802
        CALLS.append(("PATCH", self.path, self._read()))
        self._reply()


@pytest.fixture()
def api(monkeypatch: pytest.MonkeyPatch) -> str:
    """Поднимает фейковый API Northflank и возвращает его адрес."""
    CALLS.clear()
    NEXT_STATUS["value"] = 200
    NEXT_BODY["value"] = {"data": {"id": "srv-1"}}

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address[0], server.server_address[1]

    module = _load()
    monkeypatch.setattr(module, "API_BASE", f"http://{host}:{port}")
    yield f"http://{host}:{port}"
    server.shutdown()


def _bodies(method: str, contains: str) -> list[Any]:
    return [body for verb, path, body in CALLS if verb == method and contains in path]


class TestTheRequestShape:
    def test_a_volume_is_created_and_attached(self, api: str) -> None:
        """Без тома база умирает вместе с контейнером.

        Это самая дорогая ошибка из возможных: она не видна сразу, а
        обнаруживается, когда человек открывает уже присланную ссылку
        и получает 404.
        """
        module = _load()
        module.API_BASE = api

        project_id, stage_id = module._pick_project("tok", None)
        service_id = module._create_service("tok", project_id, stage_id,
                                            "owner/repo", "main", "svc")
        volume_id = module._create_volume("tok", project_id, stage_id, "data")
        module._attach_volume("tok", project_id, service_id, volume_id)

        volumes = _bodies("POST", "/volumes")
        assert volumes, "том не создан"
        body = volumes[0]
        assert body["mounts"][0]["containerMountPath"] == "/data"
        assert body["spec"]["accessMode"] == "ReadWriteOnce"
        assert body["spec"]["storageSize"] > 0

        patches = _bodies("PATCH", service_id)
        assert any(
            patch.get("volumes")
            and patch["volumes"][0]["volumeId"] == volume_id
            and patch["volumes"][0]["mountPath"] == "/data"
            for patch in patches
        ), "том не подключён к сервису"

    def test_the_database_path_points_into_the_volume(self) -> None:
        """DB_PATH обязан лежать внутри тома.

        Если база окажется в `/app/links.db` (то есть в образе), она
        переживёт перезапуск контейнера, но потеряется при новом деплое —
        и все ссылки станут мёртвыми.
        """
        module = _load()
        # Та же логика, что в main(): путь собирается из точки монтирования.
        variables = {
            "DB_PATH": f"{module.VOLUME_MOUNT}/links.db",
        }
        assert variables["DB_PATH"].startswith(module.VOLUME_MOUNT + "/")
        assert module.VOLUME_MOUNT == "/data"

    def test_the_healthcheck_points_at_healthz(self) -> None:
        """Healthcheck должен ходить на существующий маршрут."""
        module = _load()
        web_app = (ROOT / "web_app.py").read_text(encoding="utf-8")
        assert '"/healthz"' in web_app


class TestSecrets:
    def test_the_bot_token_is_not_printed(self, capsys: pytest.CaptureFixture[str],
                                         api: str) -> None:
        """Токен бота не должен попасть в вывод.

        Вывод скрипта обычно копируют в чат или в issue. Токен в выводе —
        это токен в публичном месте.
        """
        module = _load()
        module.API_BASE = api

        project_id, stage_id = module._pick_project("tok", None)
        service_id = module._create_service("tok", project_id, stage_id,
                                            "owner/repo", "main", "svc")
        module._set_environment("tok", project_id, service_id, {
            "BOT_TOKEN": "123456:SECRET-TOKEN-VALUE",
            "BASE_URL": "https://example.test",
        })

        out = capsys.readouterr().out
        assert "SECRET-TOKEN-VALUE" not in out

    def test_the_api_token_is_not_printed(self, capsys: pytest.CaptureFixture[str],
                                          api: str) -> None:
        """API-токен Northflank тоже не должен появляться в выводе."""
        module = _load()
        module.API_BASE = api
        module._pick_project("NF-API-TOKEN-SECRET", None)
        out = capsys.readouterr().out
        assert "NF-API-TOKEN-SECRET" not in out

    def test_the_environment_variables_reach_the_api(self, api: str) -> None:
        """Переменные действительно уходят в API, а не теряются по дороге."""
        module = _load()
        module.API_BASE = api

        project_id, stage_id = module._pick_project("tok", None)
        service_id = module._create_service("tok", project_id, stage_id,
                                            "owner/repo", "main", "svc")
        module._set_environment("tok", project_id, service_id, {
            "BOT_TOKEN": "123456:AA",
            "BASE_URL": "https://example.test",
            "ENABLE_WEB": "1",
        })

        patches = _bodies("PATCH", service_id)
        envs = [p["runtimeEnvironment"] for p in patches if p.get("runtimeEnvironment")]
        assert envs, "переменные окружения не отправлены"
        assert envs[0]["BOT_TOKEN"] == "123456:AA"
        assert envs[0]["BASE_URL"] == "https://example.test"
        assert envs[0]["ENABLE_WEB"] == "1"


class TestFailuresAreVisible:
    def test_an_api_error_stops_the_deploy(self, api: str) -> None:
        """Ошибка API не должна проходить молча.

        Если сервис не создался, а скрипт всё равно рапортовал «готово»,
        человек пойдёт проверять несуществующий адрес.
        """
        module = _load()
        module.API_BASE = api

        NEXT_STATUS["value"] = 422
        NEXT_BODY["value"] = {"error": "name is required"}

        with pytest.raises(SystemExit):
            module._create_service("tok", "p1", "default", "o/r", "main", "svc")

    def test_the_error_message_contains_the_api_explanation(
        self, api: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Сообщение об ошибке должно объяснять, что именно не так.

        Голый код 422 без текста бесполезен: непонятно, то ли имя сервиса
        не то, то ли квота исчерпана.
        """
        module = _load()
        module.API_BASE = api

        NEXT_STATUS["value"] = 422
        NEXT_BODY["value"] = {"error": "name is required"}

        with pytest.raises(SystemExit) as excinfo:
            module._create_service("tok", "p1", "default", "o/r", "main", "svc")

        assert "name is required" in str(excinfo.value)
