"""Готовит артефакты релиза и (по флагу) публикует их на GitHub.

Запуск:
    python build\\release.py              только собрать артефакты
    python build\\release.py --publish    ещё и создать релиз через gh

Что делает:
    build\\dist\\SecretBot-<ver>-setup.exe        (уже собран build.py)
    build\\dist\\SecretBot-<ver>-portable.zip     портативная версия
    build\\dist\\SHA256SUMS.txt                   контрольные суммы

Портативный архив собирается из dist\\SecretBot и дополняется README.md и
шаблоном настроек, чтобы программу можно было запустить без установки.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile

BUILD_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BUILD_DIR)
DIST = os.path.join(BUILD_DIR, "dist")
PORTABLE_SRC = os.path.join(DIST, "SecretBot")
NOTES = os.path.join(BUILD_DIR, "release-notes.md")


def notes_for(ver: str) -> str:
    """Заменяет %%VERSION%% в шаблоне заметок и пишет результат во временный файл."""
    with open(NOTES, encoding="utf-8") as handle:
        text = handle.read().replace("%%VERSION%%", ver)
    path = os.path.join(DIST, "RELEASE_NOTES.md")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def version() -> str:
    with open(os.path.join(ROOT, "launcher.py"), encoding="utf-8") as handle:
        match = re.search(r'^VERSION\s*=\s*"([^"]+)"', handle.read(), re.M)
    if not match:
        sys.exit('в launcher.py не найдена строка VERSION = "..."')
    return match.group(1)


def build_portable(ver: str) -> str:
    """Складывает dist/SecretBot + README + шаблон настроек в один zip."""
    target = os.path.join(DIST, f"SecretBot-{ver}-portable.zip")
    if os.path.exists(target):
        os.remove(target)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for dirpath, _dirnames, filenames in os.walk(PORTABLE_SRC):
            for name in filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, DIST)
                archive.write(full, rel)
        archive.write(os.path.join(ROOT, "README.md"), "SecretBot/README.md")
        archive.write(os.path.join(BUILD_DIR, "secret-bot.env.template"),
                      "SecretBot/secret-bot.env")
        archive.write(os.path.join(BUILD_DIR, "LICENSE.txt"),
                      "SecretBot/LICENSE.txt")
    return target


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sums(paths: list[str]) -> str:
    target = os.path.join(DIST, "SHA256SUMS.txt")
    lines = []
    for path in paths:
        lines.append(f"{sha256(path)}  {os.path.basename(path)}")
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    return target


def origin_repo() -> str:
    """owner/name из git-remote origin.

    Нужен явный --repo: если в репозитории есть и origin, и upstream, gh в
    этом каталоге уверенно выбирает upstream (проверено: `gh repo view`
    отдавал Kir13ll/Secret-bot), и все команды уходят не в тот репозиторий.
    """
    result = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=ROOT, capture_output=True, text=True,
    )
    url = result.stdout.strip()
    match = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<name>[^/]+?)(?:\.git)?$", url)
    if not match:
        sys.exit(f"не удалось разобрать origin: {url!r}")
    return f"{match.group('owner')}/{match.group('name')}"


def publish(ver: str, assets: list[str], tag: str, repo: str) -> int:
    if shutil.which("gh") is None:
        print("gh не найден — публикацию пропускаю")
        return 1
    # Тег создаём и отправляем сами через git. Если тег создаёт gh, GitHub
    # требует scope "workflow" — и упирается в него, даже когда Actions в
    # репозитории нет. С уже существующим тегом gh не создаёт ref, и
    # достаточно --verify-tag.
    have = subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if have.returncode != 0:
        print(f"Создаю тег {tag}...")
        if subprocess.run(
            ["git", "tag", "-a", tag, "-m", f"Secret-bot {ver}"], cwd=ROOT
        ).returncode:
            print("не удалось создать тег")
            return 1
    print(f"Отправляю тег {tag}...")
    if subprocess.run(["git", "push", "origin", tag], cwd=ROOT).returncode:
        print("не удалось отправить тег")
        return 1

    print(f"Репозиторий релиза: {repo}")
    notes = notes_for(ver)
    exists = subprocess.run(
        ["gh", "release", "view", tag, "--repo", repo],
        cwd=ROOT, capture_output=True, text=True,
    )
    if exists.returncode == 0:
        print(f"релиз {tag} уже есть — добавляю/обновляю файлы")
        return subprocess.run(
            ["gh", "release", "upload", tag, *assets, "--repo", repo, "--clobber"],
            cwd=ROOT,
        ).returncode
    return subprocess.run(
        ["gh", "release", "create", tag, "--verify-tag", *assets,
         "--repo", repo, "--title", f"Secret-bot {ver}", "--notes-file", notes],
        cwd=ROOT,
    ).returncode


def main(argv: list[str]) -> int:
    ver = version()
    setup = os.path.join(DIST, f"SecretBot-{ver}-setup.exe")
    if not os.path.isfile(setup):
        sys.exit(f"нет установщика {setup} — сначала запустите build.py")

    print(f"Версия {ver}")
    print("Собираю портативный архив...")
    portable = build_portable(ver)
    print(f"  {portable} ({os.path.getsize(portable) / 1024 / 1024:.1f} МБ)")

    sums = write_sums([setup, portable])
    print(f"Контрольные суммы: {sums}")
    with open(sums, encoding="utf-8") as handle:
        print(handle.read().rstrip())

    if "--publish" in argv:
        tag = f"v{ver}"
        repo = origin_repo()
        print(f"Публикую релиз {tag}...")
        code = publish(ver, [setup, portable, sums], tag, repo)
        if code:
            print("публикация не удалась (см. вывод gh выше)")
        return code
    print("\nГотово. Публикация: python build\\release.py --publish")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
