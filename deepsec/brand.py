"""Логотип DeepSec — пиксельный «Большой глаз» на тёмной плитке с красными лучами.

Рисуется кодом по сетке N×N, поэтому чёткий на любом размере: иконка exe и установщика (build.ps1
собирает .ico через `python -m deepsec.brand`), ярлык в «Пуск» и окно DeepSec.
"""
from __future__ import annotations

import io
import math
import struct
import sys
from pathlib import Path

TILE = (21, 20, 25)
RAY_LIGHT = (92, 14, 18)
RAY_DARK = (38, 8, 10)
OUTLINE = (12, 5, 6)
SCLERA = (232, 220, 192)
SCLERA_SHADE = (186, 168, 138)
IRIS = (178, 24, 32)
IRIS_DARK = (48, 7, 10)
IRIS_HOT = (236, 56, 60)
PUPIL = (6, 4, 4)
SHINE = (255, 250, 240)
RAYS = 12

# Размер иконки -> сетка «пикселей»: мелкие рисуются один в один, крупные — увеличенные в 2–8 раз.
ICON_GRIDS = {16: 16, 24: 24, 32: 16, 48: 24, 64: 32, 128: 32, 256: 32}


def logo(grid: int):
    """Логотип grid×grid пикселей, RGBA."""
    from PIL import Image

    image = Image.new("RGBA", (grid, grid), (0, 0, 0, 0))
    px = image.load()
    c = grid / 2
    radius = max(2.0, grid / 5)  # скругление плитки
    eye_w, eye_h = grid * 0.86, grid * 0.25  # ширина и полувысота глаза
    iris = grid * 0.2
    for y in range(grid):
        for x in range(grid):
            fx, fy = x + 0.5, y + 0.5
            if not _in_tile(fx, fy, grid, radius):
                continue
            px[x, y] = (*_eye(fx, fy, c, eye_w, eye_h, iris, grid), 255)
    return image


def _in_tile(x: float, y: float, size: int, r: float) -> bool:
    dx = max(r - x, 0, x - (size - r))
    dy = max(r - y, 0, y - (size - r))
    return dx * dx + dy * dy <= r * r


def _half(x: float, c: float, w: float, h: float) -> float:
    t = (x - (c - w / 2)) / w
    return h * math.sin(math.pi * t) ** 0.7 if 0 < t < 1 else 0.0


def _eye(x: float, y: float, c: float, w: float, h: float, iris: float, grid: int) -> tuple[int, int, int]:
    half = _half(x, c, w, h)
    edge = 1.0 if grid < 24 else 1.4  # толщина контура в «пикселях»
    if abs(y - c) >= half:
        if abs(y - c) < half + edge and half > 0:
            return OUTLINE
        if grid < 24:
            return TILE  # на 16×16 лучи превращаются в шум — только плитка
        sector = int((math.atan2(y - c, x - c) + math.pi) / (2 * math.pi / RAYS)) % 2
        return RAY_LIGHT if sector == 0 else RAY_DARK
    d = math.hypot(x - c, y - c)
    if grid >= 24 and math.hypot(x - (c - iris * 0.38), y - (c - iris * 0.38)) < iris * 0.2:
        return SHINE
    if d < iris * 0.42:
        return PUPIL
    if d < iris * 0.62:
        return IRIS_HOT if grid >= 24 else IRIS
    if d < iris * 0.78:
        return IRIS_DARK if grid >= 24 else IRIS
    if d < iris:
        return IRIS
    if d < iris + 0.9:
        return IRIS_DARK
    if y < c - half + edge + 1.2:
        return SCLERA_SHADE  # тень от верхнего века — взгляд тяжелее
    return SCLERA


def icon_image(size: int):
    from PIL import Image

    grid = ICON_GRIDS.get(size, 32)
    return logo(grid).resize((size, size), Image.NEAREST)


def write_ico(path: Path) -> None:
    """ICO со своей картинкой на каждый размер (PNG внутри — так Windows умеет с Vista)."""
    sizes = sorted(ICON_GRIDS)
    blobs = []
    for size in sizes:
        buffer = io.BytesIO()
        icon_image(size).save(buffer, "PNG")
        blobs.append(buffer.getvalue())
    offset = 6 + 16 * len(sizes)
    header = struct.pack("<HHH", 0, 1, len(sizes))
    entries = b""
    for size, blob in zip(sizes, blobs):
        side = 0 if size >= 256 else size  # 0 означает 256
        entries += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    path.write_bytes(header + entries + b"".join(blobs))


def write_wizard_image(path: Path, size: int = 110) -> None:
    """Картинка в шапке мастера установки (BMP на белом фоне — так требует Inno Setup)."""
    from PIL import Image

    canvas = Image.new("RGB", (size, size), (255, 255, 255))
    mark = logo(32).resize((size, size), Image.NEAREST)
    canvas.paste(mark, (0, 0), mark)
    canvas.save(path, "BMP")


if __name__ == "__main__":  # python -m deepsec.brand build  — иконка и картинка для сборки
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "build")
    out.mkdir(parents=True, exist_ok=True)
    write_ico(out / "deepsec.ico")
    write_wizard_image(out / "wizard-small.bmp")
    print(f"{out / 'deepsec.ico'}, {out / 'wizard-small.bmp'}")
