"""Генерирует иконки запуска Android (ic_launcher + ic_launcher_round)
для всех плотностей экрана из общего рисунка замка.

Запуск: python android/make-icons.py

Без этого шага проект не собирается: AndroidManifest.xml ссылается на
@mipmap/ic_launcher и @mipmap/ic_launcher_round, а генерируются они здесь.
"""

import importlib.util
import os

from PIL import Image, ImageDraw  # noqa: E402

# Рисунок замка лежит в build/make-icon.py — имя с дефисом, обычным
# импортом он не берётся, поэтому грузим по пути.
_ICON = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "build", "make-icon.py")
_spec = importlib.util.spec_from_file_location("make_icon", _ICON)
_make_icon = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_make_icon)
draw = _make_icon.draw

RES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "app", "src", "main", "res")

# Плотности Android и размер иконки в px
DENSITIES = {
    "mdpi": 48,
    "hdpi": 72,
    "xhdpi": 96,
    "xxhdpi": 144,
    "xxxhdpi": 192,
}


def round_icon(img: Image.Image) -> Image.Image:
    """Обрезает иконку в круг (для ic_launcher_round)."""
    mask = Image.new("L", img.size, 0)
    ImageDraw.Draw(mask).ellipse((0, 0, img.size[0], img.size[1]), fill=255)
    out = img.copy()
    out.putalpha(mask)
    return out


def main() -> None:
    img = draw()
    for density, size in DENSITIES.items():
        folder = os.path.join(RES, f"mipmap-{density}")
        os.makedirs(folder, exist_ok=True)
        small = img.resize((size, size), Image.LANCZOS)
        small.save(os.path.join(folder, "ic_launcher.png"))
        round_icon(small).save(os.path.join(folder, "ic_launcher_round.png"))
        print(f"mipmap-{density}: {size}x{size}")

    # Самопроверка: файлы, на которые ссылается AndroidManifest.xml, должны
    # существовать и быть настоящими PNG нужного размера.
    missing = []
    for density, size in DENSITIES.items():
        for name in ("ic_launcher.png", "ic_launcher_round.png"):
            path = os.path.join(RES, f"mipmap-{density}", name)
            if not os.path.isfile(path):
                missing.append(path)
                continue
            with Image.open(path) as check:
                if check.size != (size, size) or check.format != "PNG":
                    missing.append(f"{path}: {check.format} {check.size}")
    if missing:
        raise SystemExit("иконки не получились:\n  " + "\n  ".join(missing))
    total = len(DENSITIES) * 2
    print(f"проверка: {total} иконок на месте, размеры совпадают")


if __name__ == "__main__":
    main()
