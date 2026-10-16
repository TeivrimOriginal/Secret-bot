"""Рисует иконку приложения (build/secret-bot.ico) без внешних ассетов.

Запуск: python build/make-icon.py
Иконка попадает и в .exe (PyInstaller), и в установщик (Inno Setup).
"""

import os

from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret-bot.ico")
SIZE = 256
BG = (26, 86, 160)          # синий
BG_EDGE = (18, 62, 120)
LOCK = (245, 248, 252)      # почти белый
KEYHOLE = (26, 86, 160)


def rounded_square(draw, box, radius, fill, outline=None, width=0):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline,
                           width=width)


def main() -> None:
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    rounded_square(draw, (8, 8, SIZE - 8, SIZE - 8), radius=52, fill=BG,
                   outline=BG_EDGE, width=6)

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
    body = (60, 112, SIZE - 60, 196)
    rounded_square(draw, body, radius=26, fill=LOCK)

    # Скважина
    cx = SIZE // 2
    draw.ellipse((cx - 17, 138, cx + 17, 172), fill=KEYHOLE)
    draw.rectangle((cx - 8, 160, cx + 8, 186), fill=KEYHOLE)

    img.save(OUT, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64),
                         (128, 128), (256, 256)])
    print(f"Иконка: {OUT}")
    for size in (16, 32, 128, 256):
        print(f"  {size}x{size}: {img.resize((size, size)).size}")


if __name__ == "__main__":
    main()
