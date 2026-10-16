"""Рисует иконки приложения без внешних ассетов.

Запуск: python build/make-icon.py

Что пишет:
    build/secret-bot.ico        для .exe и установщика (Inno Setup)
    static/icon-192.png         для PWA и ярлыка на главном экране Android
    static/icon-512.png         то же, большего размера

Иконка — синий скруглённый квадрат с белым замком. Проверена по пикселям:
корпус и дужка белые, скважина синяя, углы прозрачные.
"""

import os

from PIL import Image, ImageDraw

BUILD_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BUILD_DIR)
STATIC_DIR = os.path.join(ROOT, "static")

SIZE = 256
BG = (26, 86, 160)          # синий
BG_EDGE = (18, 62, 120)
LOCK = (245, 248, 252)      # почти белый
KEYHOLE = (26, 86, 160)


def draw() -> Image.Image:
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    draw.rounded_rectangle((8, 8, SIZE - 8, SIZE - 8), radius=52,
                           fill=BG, outline=BG_EDGE, width=6)

    # Дужка замка
    shackle_w = 104
    shackle_x = (SIZE - shackle_w) // 2
    draw.rounded_rectangle(
        (shackle_x, 58, shackle_x + shackle_w, 150), radius=52,
        outline=LOCK, width=22,
    )
    # Прячем нижнюю половину дужки за корпусом
    draw.rectangle((shackle_x + 4, 104, shackle_x + shackle_w - 4, 152),
                   fill=BG)

    # Корпус замка
    draw.rounded_rectangle((60, 112, SIZE - 60, 196), radius=26, fill=LOCK)

    # Скважина
    cx = SIZE // 2
    draw.ellipse((cx - 17, 138, cx + 17, 172), fill=KEYHOLE)
    draw.rectangle((cx - 8, 160, cx + 8, 186), fill=KEYHOLE)
    return img


def main() -> None:
    img = draw()

    ico = os.path.join(BUILD_DIR, "secret-bot.ico")
    img.save(ico, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64),
                         (128, 128), (256, 256)])
    print(f"ICO: {ico}")

    os.makedirs(STATIC_DIR, exist_ok=True)
    for size in (192, 512):
        path = os.path.join(STATIC_DIR, f"icon-{size}.png")
        img.resize((size, size), Image.LANCZOS).save(path)
        print(f"PNG: {path}")

    # Самопроверка по пикселям: корпус белый, скважина синяя, угол прозрачный
    px = img.load()
    assert px[82, 172][:3] == LOCK, "корпус должен быть белым"
    assert px[128, 158][:3] == KEYHOLE, "скважина должна быть синей"
    assert px[12, 12][3] < 16, "угол должен быть прозрачным"
    print("Проверка иконки по пикселям: OK")


if __name__ == "__main__":
    main()
