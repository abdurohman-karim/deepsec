"""Пиксельный «Большой глаз» в правом нижнем углу экрана — владелец включает его из бота, когда за ПК друзья.

Окно Win32 без рамки поверх всех окон: прозрачное для мыши (клики уходят в игру), никогда не становится
активным (полноэкранная игра не свернётся) и не видно на панели задач. Кадры рисует Pillow, на экран они
попадают через UpdateLayeredWindow — с настоящей прозрачностью.
Запускается агентом в сеансе пользователя: `DeepSecAgent.exe pet watch --text "…"`.
"""
from __future__ import annotations

import ctypes
import math
import os
import random
import time
from ctypes import wintypes

from .protocol import PET_MAX_TEXT, PET_MOODS, PET_TEXTS

MAX_MINUTES = 240
FPS = 12

# Сетка в «пикселях»: миндалевидный глаз 46×22 на фоне тёмно-красных лучей.
GW, GH = 60, 36
EYE_W, EYE_HALF = 46, 11
EYE_X0 = (GW - EYE_W) / 2
CX, CY = GW / 2, GH / 2
IRIS_R = 9.5
RAYS = 16

OUTLINE = (14, 6, 7, 255)
LID = (40, 9, 11, 255)
SCLERA = (232, 220, 192, 255)
SCLERA_SHADE = (190, 172, 142, 255)
VEIN = (168, 26, 32, 255)
IRIS = (172, 22, 30, 255)
IRIS_DARK = (42, 6, 9, 255)
IRIS_HOT = (232, 52, 56, 255)
PUPIL = (6, 4, 4, 255)
SHINE = (255, 250, 240, 255)
RAY_LIGHT = (112, 14, 18)
RAY_DARK = (34, 6, 8)
TEXT = "#efe3c8"

# Веко по настроению: (верх, низ) — какая доля глаза закрыта. Тяжёлое верхнее веко делает взгляд серьёзным.
LIDS = {"watch": (0.14, 0.04), "happy": (0.10, 0.28), "angry": (0.30, 0.12), "sleep": (1.0, 0.0)}


def gaze(dx: float, dy: float) -> tuple[float, float]:
    """Смещение радужки в «пикселях» сетки к курсору; dx, dy — от центра глаза в пикселях экрана."""
    def squash(v: float) -> float:
        return v / (1 + abs(v))

    return 11 * squash(dx / 500), 4 * squash(dy / 350)


def _half_height(x: int) -> float:
    t = (x + 0.5 - EYE_X0) / EYE_W
    return EYE_HALF * math.sin(math.pi * t) ** 0.7 if 0 < t < 1 else 0.0


def _veins() -> frozenset[tuple[int, int]]:
    """Красные прожилки злого глаза: короткие ломаные от уголков к радужке (всегда одинаковые)."""
    rng = random.Random(13)
    points = set()
    for i in range(10):
        left = i % 2 == 0
        x = round(EYE_X0 + rng.uniform(3, 11)) if left else round(EYE_X0 + EYE_W - rng.uniform(3, 11))
        y = round(CY + rng.uniform(-0.6, 0.6) * EYE_HALF)
        for _ in range(rng.randint(5, 9)):
            points.add((x, y))
            x += 1 if left else -1
            y += rng.choice((-1, 0, 0, 1))
    return frozenset(points)


class Pet:
    def __init__(self, mood: str, text: str, scale: int):
        from PIL import ImageFont

        self.mood = mood if mood in PET_MOODS else "watch"
        self.text = (" ".join(text.split()) or PET_TEXTS[self.mood])[:PET_MAX_TEXT]
        self.cell = max(3, round(scale * 0.6))  # размер одного «пикселя» глаза на экране
        self.font = _font(round(scale * 3.4), ImageFont)
        self.small_font = _font(round(scale * 2.4), ImageFont)
        self.stroke = max(2, scale // 3)
        left, top, right, bottom = self.font.getbbox(self.text, stroke_width=self.stroke)
        self.text_w = right - left
        self.eye_x = self.text_w + scale * 2
        self.size = (self.eye_x + GW * self.cell, GH * self.cell)
        self.half = [_half_height(x) for x in range(GW)]
        self.veins = _veins()
        self.look = (0.0, 0.0)
        self.started = time.monotonic()
        self.next_blink = self.started + random.uniform(2.5, 6)

    def frame(self, cursor: tuple[int, int] = (0, 0), origin: tuple[int, int] = (0, 0)):
        """Кадр RGBA. cursor и origin (левый верх окна на экране) нужны, чтобы смотреть на курсор."""
        from PIL import Image, ImageDraw

        now = time.monotonic()
        t = now - self.started
        target = gaze(cursor[0] - (origin[0] + self.eye_x + CX * self.cell),
                      cursor[1] - (origin[1] + CY * self.cell))
        # Взгляд догоняет курсор медленно — «тяжело», так страшнее
        self.look = tuple(c + (g - c) * 0.18 for c, g in zip(self.look, target))
        top, bottom = self.lids(now, t)

        grid = Image.new("RGBA", (GW, GH), (0, 0, 0, 0))
        pixels = grid.load()
        rotation = t * (0.5 if self.mood == "angry" else 0.12)
        glow = 1.0 + (0.25 * math.sin(t * 6) if self.mood == "angry" else 0.0)
        for y in range(GH):
            for x in range(GW):
                color = self.eye_pixel(x, y, top, bottom, t)
                if color is None:
                    color = self.ray_pixel(x, y, rotation, glow)
                if color is not None:
                    pixels[x, y] = color

        image = Image.new("RGBA", self.size, (0, 0, 0, 0))
        shake = random.choice((-1, 0, 1)) * self.cell // 2 if self.mood == "angry" else 0
        image.alpha_composite(grid.resize((GW * self.cell, GH * self.cell), Image.NEAREST),
                              (self.eye_x + shake, 0))
        draw = ImageDraw.Draw(image)
        draw.text((self.eye_x + self.cell * 3, CY * self.cell), self.text, font=self.font, anchor="rm",
                  fill=TEXT, stroke_width=self.stroke, stroke_fill="#000000")
        if self.mood == "sleep":
            for i in range(3):
                phase = (t * 0.35 + i / 3) % 1
                x = self.eye_x + (EYE_X0 + EYE_W - 6 + phase * 6) * self.cell
                y = (CY - EYE_HALF + 2 - phase * 8) * self.cell
                draw.text((x, y), "z", font=self.small_font, anchor="mm", fill=TEXT,
                          stroke_width=self.stroke, stroke_fill="#000000")
        return image

    def lids(self, now: float, t: float) -> tuple[float, float]:
        top, bottom = LIDS[self.mood]
        if self.mood == "sleep":
            # Спит — но иногда приоткрывает глаз и подсматривает
            phase = t % 7
            if 5.0 < phase < 6.6:
                opening = min(1.0, (phase - 5.0) / 0.3, (6.6 - phase) / 0.3)
                top = 1.0 - 0.5 * opening
            return top, bottom
        if now >= self.next_blink:
            progress = (now - self.next_blink) / 0.3
            if progress >= 1:
                self.next_blink = now + random.uniform(2.5, 6)
            else:
                top = max(top, 1 - abs(2 * progress - 1))
        return top, bottom

    def inside(self, x: int, y: int) -> bool:
        return 0 <= x < GW and 0 <= y < GH and abs(y + 0.5 - CY) < self.half[x]

    def eye_pixel(self, x: int, y: int, top: float, bottom: float, t: float):
        if not self.inside(x, y):
            return None
        h = self.half[x]
        lid_top = CY - h + 2 * h * top
        lid_bottom = CY + h - 2 * h * bottom

        def covered(yy: int) -> bool:
            return yy + 0.5 < lid_top or yy + 0.5 > lid_bottom

        if not (self.inside(x - 1, y) and self.inside(x + 1, y) and self.inside(x, y - 2) and self.inside(x, y + 1)):
            return OUTLINE  # контур, сверху — в два пикселя
        if covered(y):
            return LID
        if covered(y - 1) or covered(y + 1):
            return OUTLINE  # край века
        icx, icy = CX + self.look[0], CY + self.look[1]
        dx, dy = x + 0.5 - icx, y + 0.5 - icy
        d = math.hypot(dx, dy)
        if d < IRIS_R:
            return self.iris_pixel(dx, dy, d, t)
        if covered(y - 2) or covered(y - 3):
            return SCLERA_SHADE  # тень от века
        if self.mood == "angry" and (x, y) in self.veins:
            return VEIN
        return SCLERA

    def iris_pixel(self, dx: float, dy: float, d: float, t: float):
        if math.hypot(dx + 3, dy + 3) < 1.3:
            return SHINE
        if self.mood == "angry":
            if abs(dy) < 5.5 and abs(dx) < 1.3 * (1 - (dy / 6) ** 2):
                return PUPIL  # вертикальный зрачок, как у змеи
            pupil = 0.0
        else:
            pupil = {"happy": 4.2, "sleep": 3.0}.get(self.mood, 2.7 + 0.5 * math.sin(t * 1.1))
        if d < pupil:
            return PUPIL
        if d < pupil + 1.3:
            return IRIS_HOT
        if d < pupil + 2.7:
            return IRIS_DARK
        if d < IRIS_R - 1.2:
            return IRIS
        return IRIS_DARK

    def ray_pixel(self, x: int, y: int, rotation: float, glow: float):
        nx, ny = (x + 0.5 - CX) / CX, (y + 0.5 - CY) / CY
        r = math.hypot(nx, ny)
        if r >= 1:
            return None
        sector = int((math.atan2(ny, nx) + rotation) / (2 * math.pi / RAYS)) % 2
        base = RAY_LIGHT if sector == 0 else RAY_DARK
        alpha = (200 if sector == 0 else 150) if r < 0.75 else (110 if sector == 0 else 70)
        return (*(min(255, round(c * glow)) for c in base), alpha)


def _font(size: int, image_font):
    fonts = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Fonts")
    for name in ("consolab.ttf", "consola.ttf", "courbd.ttf"):
        try:
            return image_font.truetype(os.path.join(fonts, name), size)
        except OSError:
            continue
    return image_font.load_default(size)


# ---------- окно Win32 ----------

WS_POPUP = 0x80000000
WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_EX_TOOLWINDOW = 0x8, 0x20, 0x80
WS_EX_LAYERED, WS_EX_NOACTIVATE = 0x80000, 0x08000000
WM_TIMER, WM_DESTROY = 0x113, 0x2
SW_SHOWNOACTIVATE = 4
FRAME_TIMER, LIFETIME_TIMER = 1, 2


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]


class BLENDFUNCTION(ctypes.Structure):
    _fields_ = [("BlendOp", ctypes.c_byte), ("BlendFlags", ctypes.c_byte), ("SourceConstantAlpha", ctypes.c_ubyte),
                ("AlphaFormat", ctypes.c_byte)]


class Overlay:
    """Слоистое окно, которое показывает кадры питомца и никогда не берёт фокус."""

    def __init__(self, pet: Pet, minutes: float):
        import win32api
        import win32gui

        self.pet = pet
        self.user32, self.gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
        self.user32.UpdateLayeredWindow.argtypes = [
            wintypes.HWND, wintypes.HDC, ctypes.POINTER(wintypes.POINT), ctypes.POINTER(wintypes.SIZE),
            wintypes.HDC, ctypes.POINTER(wintypes.POINT), wintypes.COLORREF, ctypes.POINTER(BLENDFUNCTION),
            wintypes.DWORD]
        self.gdi32.CreateDIBSection.restype = wintypes.HBITMAP
        self.gdi32.CreateDIBSection.argtypes = [wintypes.HDC, ctypes.c_void_p, wintypes.UINT,
                                                ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.DWORD]
        self.gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
        self.gdi32.CreateCompatibleDC.restype = wintypes.HDC
        self.gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
        self.user32.GetDC.restype = wintypes.HDC
        self.user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND] + [ctypes.c_int] * 4 + [wintypes.UINT]
        self.user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, ctypes.c_void_p]

        width, height = pet.size
        left, top, right, bottom = _work_area()
        self.pos = wintypes.POINT(right - width - 8, bottom - height - 8)

        wc = win32gui.WNDCLASS()
        wc.lpszClassName = "DeepSecPet"
        wc.hInstance = win32api.GetModuleHandle(None)
        wc.lpfnWndProc = {WM_TIMER: self._on_timer, WM_DESTROY: lambda *a: win32gui.PostQuitMessage(0)}
        win32gui.RegisterClass(wc)
        ex = WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST
        self.hwnd = win32gui.CreateWindowEx(ex, wc.lpszClassName, "DeepSec", WS_POPUP, self.pos.x, self.pos.y,
                                            width, height, 0, 0, wc.hInstance, None)

        self.screen_dc = self.user32.GetDC(None)
        self.mem_dc = self.gdi32.CreateCompatibleDC(self.screen_dc)
        header = BITMAPINFOHEADER(ctypes.sizeof(BITMAPINFOHEADER), width, -height, 1, 32, 0, 0, 0, 0, 0, 0)
        self.bits = ctypes.c_void_p()
        bitmap = self.gdi32.CreateDIBSection(self.mem_dc, ctypes.byref(header), 0, ctypes.byref(self.bits), None, 0)
        self.gdi32.SelectObject(self.mem_dc, bitmap)

        self.show_frame()
        self.user32.ShowWindow(wintypes.HWND(self.hwnd), SW_SHOWNOACTIVATE)
        self.user32.SetTimer(self.hwnd, FRAME_TIMER, 1000 // FPS, None)
        self.user32.SetTimer(self.hwnd, LIFETIME_TIMER, int(min(minutes, MAX_MINUTES) * 60_000), None)

    def _on_timer(self, hwnd, msg, wparam, lparam) -> int:
        import win32gui

        if wparam == LIFETIME_TIMER:
            win32gui.DestroyWindow(hwnd)
            return 0
        self.show_frame()
        # Игры в окне без рамки тоже бывают «поверх всех» — поднимаемся обратно, не забирая фокус.
        self.user32.SetWindowPos(self.hwnd, wintypes.HWND(-1), 0, 0, 0, 0, 0x1 | 0x2 | 0x10)
        return 0

    def show_frame(self) -> None:
        import win32api
        from PIL import Image, ImageChops

        image = self.pet.frame(win32api.GetCursorPos(), (self.pos.x, self.pos.y))
        r, g, b, a = image.split()  # UpdateLayeredWindow ждёт цвета, уже умноженные на прозрачность
        data = (ImageChops.multiply(b, a), ImageChops.multiply(g, a), ImageChops.multiply(r, a), a)
        raw = Image.merge("RGBA", data).tobytes()  # каналы уже в порядке BGRA
        ctypes.memmove(self.bits, raw, len(raw))
        size = wintypes.SIZE(*self.pet.size)
        blend = BLENDFUNCTION(0, 0, 255, 1)  # AC_SRC_OVER, AC_SRC_ALPHA
        self.user32.UpdateLayeredWindow(self.hwnd, self.screen_dc, ctypes.byref(self.pos), ctypes.byref(size),
                                        self.mem_dc, ctypes.byref(wintypes.POINT(0, 0)), 0, ctypes.byref(blend),
                                        2)  # ULW_ALPHA

    def run(self) -> None:
        import win32gui

        win32gui.PumpMessages()


def _system_dpi() -> int:
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        return int(ctypes.windll.user32.GetDpiForSystem())
    except (AttributeError, OSError):
        return 96


def _work_area() -> tuple[int, int, int, int]:
    """Рабочая область главного монитора — без панели задач."""
    rect = wintypes.RECT()
    ctypes.windll.user32.SystemParametersInfoW(0x30, 0, ctypes.byref(rect), 0)  # SPI_GETWORKAREA
    return rect.left, rect.top, rect.right, rect.bottom


def main(mood: str, text: str, minutes: float) -> int:
    scale = max(4, round(6 * _system_dpi() / 96))
    Overlay(Pet(mood, text, scale), minutes).run()
    return 0
