"""Автоматический деплой Secret-bot на Northflank (тариф Sandbox, $0).

Скрипт делает всё, что иначе пришлось бы кликать в веб-интерфейсе Northflank:

1. находит или создаёт проект;
2. создаёт сервис из репозитория GitHub (сборка по Dockerfile);
3. создаёт постоянный том и подключает его к `/data`;
4. задаёт переменные окружения, включая `BOT_TOKEN` и `BASE_URL`;
5. включает HTTPS и healthcheck на `/healthz`;
6. печатает адрес, который надо вписать в `BASE_URL`.

Нужен API-токен Northflank: <https://app.northflank.com/s/account/settings/api/tokens/new>
и токен бота от @BotFather.

Запуск:
    set NF_API_TOKEN=...
    set BOT_TOKEN=123456:AA...
    python scripts/deploy_northflank.py

Или с аргументами:
    python scripts/deploy_northflank.py --api-token ... --bot-token ... --project-id ...

Скрипт НЕ хранит токены на диске и НЕ печатает их: секрет, который
попал в вывод, попал в историю терминала.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

API_BASE = "https://api.northflank.com"
DEFAULT_REPO = "TeivrimOriginal/Secret-bot"
DEFAULT_BRANCH = "main"
DEFAULT_SERVICE = "secretbot"
DEFAULT_VOLUME = "secretbot-data"
VOLUME_MOUNT = "/data"
DEPLOY_PLAN = "nf-compute-200"
STAGE = "default"


def _token_from_env() -> str:
    return os.environ.get("NF_API_TOKEN", "").strip()


def _request(method: str, path: str, token: str,
             body: dict[str, Any] | None = None) -> tuple[int, Any]:
    """Один запрос к API Northflank.

    Ошибка с телом ответа выводится целиком: у Northflank в JSON лежит
    поле `error` с понятным текстом, а HTTP-код вроде 422 без тела
    говорит ровно ничего.
    """
    url = f"{API_BASE}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            raw = response.read().decode("utf-8", "replace")
            return response.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"error": raw[:400]}
    except urllib.error.URLError as exc:
        raise SystemExit(f"Не удалось достучаться до Northflank: {exc.reason}") from exc


def _as_list(payload: Any, key: str = "data") -> list[dict[str, Any]]:
    """Достаёт список из ответа API.

    Northflank отвечает `{"data": [...]}` для списков и `{"data": {...}}`
    для одного объекта. Раньше код брал `data.get("data", [])` и на
    объекте получал словарь вместо списка — а дальше `projects[0]` падал
    с KeyError: 0. Ответ разбирается одинаково в обоих случаях: если под
    ключом лежит один объект, он оборачивается в список.
    """
    if not isinstance(payload, dict):
        return []
    data = payload.get(key)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def _data_obj(payload: Any) -> dict[str, Any]:
    """Достаёт объект из ответа API (`{"data": {...}}`)."""
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data")
    return data if isinstance(data, dict) else {}


def _stage_of(project: dict[str, Any]) -> str:
    """ID стадии (окружения) проекта.

    Стадии приходят списком, но API может вернуть и одного объекта —
    поэтому разбор через `_as_list`, а не `stages[0]`.
    """
    stages = _as_list(project.get("stages") or [])
    if stages:
        return stages[0].get("id") or STAGE
    return STAGE


def _projects(token: str) -> list[dict[str, Any]]:
    status, data = _request("GET", "/v1/projects", token)
    if status != 200:
        raise SystemExit(f"Не удалось получить список проектов: {status} {data}")
    return _as_list(data)


def _pick_project(token: str, wanted: str | None) -> tuple[str, str]:
    """Возвращает (projectId, stageId).

    Если проект указан — берём его. Если нет — берём первый существующий
    (их обычно один) или создаём новый.
    """
    projects = _projects(token)
    if wanted:
        for project in projects:
            if project.get("id") == wanted or project.get("name") == wanted:
                return project["id"], _stage_of(project)
        raise SystemExit(f"Проект {wanted!r} не найден. Доступны: "
                         f"{[p.get('name') for p in projects]}")

    if projects:
        project = projects[0]
        print(f"  проект: {project.get('name')} ({project.get('id')})")
        return project["id"], _stage_of(project)

    # Проекта нет — создаём.
    status, data = _request("POST", "/v1/projects", token, {
        "name": "secretbot",
        "type": "standard",
    })
    if status not in (200, 201):
        raise SystemExit(f"Не удалось создать проект: {status} {data}")
    project_id = _data_obj(data).get("id", "")
    print(f"  создан проект: {project_id}")
    return project_id, STAGE


def _service_exists(token: str, project_id: str, name: str) -> str | None:
    status, data = _request("GET", f"/v1/projects/{project_id}/services", token)
    if status != 200:
        return None
    for service in _as_list(data):
        if service.get("name") == name:
            return service.get("id")
    return None


def _create_service(token: str, project_id: str, stage_id: str,
                    repo: str, branch: str, name: str) -> str:
    """Создаёт сервис с Dockerfile-сборкой из репозитория GitHub."""
    body: dict[str, Any] = {
        "name": name,
        "description": "Secret-bot: шифрование файлов по ссылке + passkey",
        "billing": {"deploymentPlan": DEPLOY_PLAN},
        "deployment": {
            "type": "deployment",
            "instances": 1,
            "docker": {
                "configType": "default",
                "imagePath": f"ghcr.io/{repo.lower()}",
            },
            "build": {
                "dockerfile": {
                    "dockerFilePath": "/Dockerfile",
                    "dockerWorkDir": "/",
                },
                "source": {
                    "type": "git",
                    "repository": {
                        "type": "github",
                        "owner": repo.split("/")[0],
                        "repository": repo.split("/")[1],
                        "branch": branch,
                    },
                },
            },
        },
    }
    if stage_id:
        body["stageId"] = stage_id

    status, data = _request(
        "POST", f"/v1/projects/{project_id}/services/deployment", token, body
    )
    if status not in (200, 201):
        raise SystemExit(f"Не удалось создать сервис: {status} {data}")
    service_id = _data_obj(data).get("id", "")
    print(f"  создан сервис: {name} ({service_id})")
    return service_id


def _create_volume(token: str, project_id: str, stage_id: str,
                   name: str, size_mb: int = 1024) -> str:
    """Создаёт постоянный том и подключает его к `/data`.

    Без тома база SQLite живёт в эфемерной файловой системе контейнера и
    умирает вместе с ним — все ссылки, которые уже разосланы людям,
    перестают открываться.
    """
    body: dict[str, Any] = {
        "name": name,
        "mounts": [{"containerMountPath": VOLUME_MOUNT}],
        "spec": {
            "accessMode": "ReadWriteOnce",
            "storageSize": size_mb,
        },
    }
    if stage_id:
        body["stageId"] = stage_id

    status, data = _request("POST", f"/v1/projects/{project_id}/volumes", token, body)
    if status not in (200, 201):
        raise SystemExit(f"Не удалось создать том: {status} {data}")
    volume_id = _data_obj(data).get("id", "")
    print(f"  создан том: {name} ({volume_id}), монтируется в {VOLUME_MOUNT}")
    return volume_id


def _attach_volume(token: str, project_id: str, service_id: str,
                   volume_id: str) -> None:
    """Подключает том к сервису."""
    body = {
        "volumes": [{
            "volumeId": volume_id,
            "mountPath": VOLUME_MOUNT,
        }],
    }
    status, data = _request(
        "PATCH",
        f"/v1/projects/{project_id}/services/deployment/{service_id}",
        token,
        body,
    )
    if status not in (200, 202):
        raise SystemExit(f"Не удалось подключить том: {status} {data}")
    print(f"  том подключён к сервису")


def _set_environment(token: str, project_id: str, service_id: str,
                      variables: dict[str, str]) -> None:
    """Задаёт переменные окружения сервиса.

    Токен бота уходит сюда и больше нигде не появляется: ни в выводе,
    ни на диске. Именно так он и должен храниться.
    """
    body = {
        "runtimeEnvironment": variables,
        "runtimeFiles": {},
    }
    status, data = _request(
        "PATCH",
        f"/v1/projects/{project_id}/services/deployment/{service_id}",
        token,
        body,
    )
    if status not in (200, 202):
        raise SystemExit(f"Не удалось задать переменные окружения: {status} {data}")
    print(f"  заданы переменные: {', '.join(sorted(variables))}")


def _set_healthcheck(token: str, project_id: str, service_id: str) -> None:
    """Включает liveness- и readiness-проверку на `/healthz`."""
    body = {
        "healthChecks": [
            {
                "type": "livenessProbe",
                "protocol": "HTTP",
                "path": "/healthz",
                "port": 8080,
                "initialDelaySeconds": 20,
                "periodSeconds": 30,
                "timeoutSeconds": 5,
                "failureThreshold": 3,
            },
            {
                "type": "readinessProbe",
                "protocol": "HTTP",
                "path": "/healthz",
                "port": 8080,
                "initialDelaySeconds": 10,
                "periodSeconds": 15,
                "timeoutSeconds": 5,
                "failureThreshold": 3,
            },
        ],
    }
    status, data = _request(
        "PATCH",
        f"/v1/projects/{project_id}/services/deployment/{service_id}",
        token,
        body,
    )
    if status not in (200, 202):
        # Healthcheck не критичен: сервис поднимется и без него.
        print(f"  ВНИМАНИЕ: не удалось задать healthcheck: {status} {data}")
        return
    print("  healthcheck настроен на /healthz")


def _public_url(token: str, project_id: str, service_id: str) -> str:
    """Достаёт публичный адрес сервиса."""
    status, data = _request(
        "GET", f"/v1/projects/{project_id}/services/deployment/{service_id}", token
    )
    if status != 200:
        return ""
    service = _data_obj(data)
    domains = service.get("domains") or []
    for domain in domains:
        if domain.get("domain"):
            return f"https://{domain['domain']}"
    for port in service.get("ports", []) or []:
        if port.get("name") and port.get("public"):
            return f"https://{port['name']}"
    return ""


def _wait_for_deploy(token: str, project_id: str, service_id: str,
                     timeout: int = 600) -> str:
    """Ждёт, пока сборка и деплой закончатся.

    Сборка образа с pip-установками занимает пару минут, поэтому ждём
    и смотрим на статус деплоя, а не на статус сервиса.
    """
    print("  жду сборку и деплой…")
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        status, data = _request(
            "GET", f"/v1/projects/{project_id}/services/deployment/{service_id}", token
        )
        if status == 200:
            service = _data_obj(data)
            deployment = service.get("activeDeployment") or {}
            state = deployment.get("status") or service.get("status") or "?"
            if state != last:
                print(f"    статус: {state}")
                last = state
            if state in ("RUNNING", "running", "LIVE", "live", "READY", "ready"):
                return state
            if state in ("BUILD_FAILED", "DEPLOY_FAILED", "ERROR", "error"):
                raise SystemExit(f"Деплой упал: {state}")
        time.sleep(10)
    print("    ВНИМАНИЕ: деплой не завершился за отведённое время")
    return last


def main() -> int:
    parser = argparse.ArgumentParser(description="Деплой Secret-bot на Northflank")
    parser.add_argument("--api-token", default=None, help="API-токен Northflank")
    parser.add_argument("--bot-token", default=None, help="токен бота от @BotFather")
    parser.add_argument("--project-id", default=None, help="ID проекта Northflank")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="репозиторий GitHub")
    parser.add_argument("--branch", default=DEFAULT_BRANCH, help="ветка")
    parser.add_argument("--service", default=DEFAULT_SERVICE, help="имя сервиса")
    parser.add_argument(
        "--base-url",
        default=None,
        help="публичный адрес сайта (https://...). Нужен для passkey: "
             "из него берётся rpId. После первого деплоя адрес известен — "
             "впишите его и запустите скрипт ещё раз.",
    )
    args = parser.parse_args()

    api_token = args.api_token or _token_from_env()
    bot_token = args.bot_token or os.environ.get("BOT_TOKEN", "").strip()

    if not api_token:
        raise SystemExit(
            "Нужен API-токен Northflank.\n"
            "Создайте: https://app.northflank.com/s/account/settings/api/tokens/new\n"
            "Передайте: set NF_API_TOKEN=... (Windows) или export NF_API_TOKEN=... (Linux)"
        )
    if not bot_token:
        raise SystemExit(
            "Нужен токен бота от @BotFather.\n"
            "Передайте: set BOT_TOKEN=123456:AA..."
        )

    print("=== деплой Secret-bot на Northflank ===")
    project_id, stage_id = _pick_project(api_token, args.project_id)

    service_id = _service_exists(api_token, project_id, args.service)
    if service_id:
        print(f"  сервис уже есть: {args.service} ({service_id})")
    else:
        service_id = _create_service(
            api_token, project_id, stage_id, args.repo, args.branch, args.service
        )

    # Том: проверяем, не создан ли уже.
    status, data = _request("GET", f"/v1/projects/{project_id}/volumes", api_token)
    volume_id = ""
    if status == 200:
        for volume in _as_list(data):
            if volume.get("name") == DEFAULT_VOLUME:
                volume_id = volume.get("id", "")
                print(f"  том уже есть: {DEFAULT_VOLUME} ({volume_id})")
                break
    if not volume_id:
        volume_id = _create_volume(api_token, project_id, stage_id, DEFAULT_VOLUME)
    if volume_id:
        _attach_volume(api_token, project_id, service_id, volume_id)

    # Переменные окружения.
    #
    # BASE_URL обязателен для passkey: из него берётся rpId, и если он не
    # совпадёт с реальным адресом сайта, браузер отклонит проверку
    # подписи, а кнопки «Создать passkey» не появятся. На первом запуске
    # адреса ещё нет, поэтому подставляем заведомо рабочее значение, а
    # пользователь после деплоя вписывает настоящий и запускает скрипт
    # ещё раз — сервис пересоздастся с правильным BASE_URL.
    variables = {
        "BOT_TOKEN": bot_token,
        "ENABLE_WEB": "1",
        "DB_PATH": f"{VOLUME_MOUNT}/links.db",
        "WEB_HOST": "0.0.0.0",
        "LOG_LEVEL": "INFO",
        "BASE_URL": args.base_url or "https://example.invalid",
    }
    _set_environment(api_token, project_id, service_id, variables)
    _set_healthcheck(api_token, project_id, service_id)

    _wait_for_deploy(api_token, project_id, service_id)

    url = _public_url(api_token, project_id, service_id)
    print()
    print("=== готово ===")
    print(f"  сервис:  https://app.northflank.com/s/project/services/{service_id}")
    if url:
        print(f"  адрес:   {url}")
        print()
        print("  ОСТАЛОСЬ: вписать этот адрес в BASE_URL и перезапустить деплой:")
        print(f"    python scripts/deploy_northflank.py --base-url {url}")
    else:
        print("  адрес появится в консоли Northflank, когда сервис поднимется.")
    print("  Проверка:  curl -sS <адрес>/healthz   ->  {\"ok\":true}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
