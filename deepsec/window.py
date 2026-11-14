"""Окно DeepSec (меню «Пуск» → DeepSec): версия, работает ли агент, проверка и установка обновлений.

Окно работает от пользователя. Настройки агента (.env) ему не видны — они доступны только SYSTEM и
администраторам — и не нужны: «Обновить» запускает `DeepSecAgent.exe update` с правами администратора
(окно UAC), а тот ставит новую версию тихо, сохраняя адрес сервера, токен, ловушки и задачу агента.

Окно без стандартной рамки Windows: своя шапка (перетаскивание, свернуть, закрыть), значок на панели
задач и скруглённые углы Windows 11.
"""
from __future__ import annotations

import ctypes
import sys
import threading

import psutil

from . import __version__, brand, update
from .desktop import helper_args

BG, PANEL, BORDER = "#15161a", "#0f1013", "#2a2b31"
FG, MUTED, DIM = "#ece6d6", "#8a8f98", "#5d616b"
ACCENT, ACCENT_HOVER, OK = "#c0262d", "#9e1d23", "#4caf50"
BUTTON, BUTTON_HOVER = "#26272d", "#30323a"
FONT = "Segoe UI"
GWL_EXSTYLE, WS_EX_TOOLWINDOW, WS_EX_APPWINDOW = -20, 0x80, 0x40000


def agent_running() -> bool:
    """Есть ли процесс агента. Его командная строка пользователю не видна (он от SYSTEM) — так и узнаём;
    помощники (скриншот, глаз) и само окно запущены от пользователя, их командная строка видна."""
    for p in psutil.process_iter(["name"]):
        if (p.info["name"] or "").lower() != "deepsecagent.exe" or p.pid == psutil.Process().pid:
            continue
        try:
            if helper_args(p.cmdline())[:1] in (["run"], []):
                return True
        except psutil.AccessDenied:
            return True
        except psutil.Error:
            continue
    return False


def update_button_state(release: update.Release | None, error: str, current: str = __version__) -> tuple[bool, str]:
    """(можно ли нажать «Обновить», надпись на кнопке) по результату проверки релизов."""
    if error:
        return False, "Обновление недоступно"
    if release is not None and update.is_newer(release.version, current):
        return True, f"⬆  Обновить до {release.version}"
    return False, "Обновлений нет"


class FlatButton:
    """Плоская кнопка с наведением; у неактивной — серый фон и тусклый текст, чтобы не казалась нажимаемой."""

    def __init__(self, parent, text: str, command, primary: bool = False):
        import tkinter as tk

        self.primary, self.command, self.enabled = primary, command, True
        self.label = tk.Label(parent, text=text, font=(FONT, 10, "bold" if primary else "normal"),
                              padx=16, pady=7, cursor="hand2")
        self.label.bind("<Enter>", lambda e: self._paint(hover=True))
        self.label.bind("<Leave>", lambda e: self._paint())
        self.label.bind("<Button-1>", lambda e: self.enabled and self.command())
        self._paint()

    def set(self, enabled: bool, text: str | None = None) -> None:
        self.enabled = enabled
        if text is not None:
            self.label.config(text=text)
        self._paint()

    def _paint(self, hover: bool = False) -> None:
        if not self.enabled:
            self.label.config(bg=BUTTON, fg=DIM, cursor="arrow")
        elif self.primary:
            self.label.config(bg=ACCENT_HOVER if hover else ACCENT, fg="white", cursor="hand2")
        else:
            self.label.config(bg=BUTTON_HOVER if hover else BUTTON, fg=FG, cursor="hand2")


class Window:
    def __init__(self) -> None:
        import tkinter as tk
        from PIL import Image, ImageTk

        self.tk = tk
        self.root = tk.Tk()
        self.root.title("DeepSec")
        self.root.overrideredirect(True)
        self.root.configure(bg=BORDER)
        self.root.resizable(False, False)
        self.scale = max(1.0, self.root.winfo_fpixels("1i") / 96)  # 150% в Windows — картинки тоже крупнее
        icon = brand.icon_image(256)
        self._icons = [ImageTk.PhotoImage(icon), ImageTk.PhotoImage(brand.icon_image(32))]
        self.root.iconphoto(True, *self._icons)

        frame = tk.Frame(self.root, bg=BG)
        frame.pack(fill="both", expand=True, padx=1, pady=1)  # 1 px рамка цветом BORDER
        self._title_bar(frame)

        body = tk.Frame(frame, bg=BG, padx=24, pady=18)
        body.pack(fill="both", expand=True)
        side = 32 * max(3, round(3.5 * self.scale))  # целое увеличение — пиксели остаются квадратными
        self._logo = ImageTk.PhotoImage(brand.logo(32).resize((side, side), Image.NEAREST))
        tk.Label(body, image=self._logo, bg=BG).pack(side="left", anchor="n", padx=(0, 22))

        info = tk.Frame(body, bg=BG)
        info.pack(side="left", fill="both", expand=True)
        tk.Label(info, text="DeepSec Agent", bg=BG, fg=FG, font=(FONT, 17, "bold"), anchor="w").pack(fill="x")
        tk.Label(info, text="Защита сессий Telegram Desktop", bg=BG, fg=MUTED, font=(FONT, 10),
                 anchor="w").pack(fill="x", pady=(0, 12))
        self.agent = self._status_row(info)
        self.version = self._status_row(info)
        self.latest = self._status_row(info)

        buttons = tk.Frame(frame, bg=BG, padx=24)
        buttons.pack(fill="x", pady=(0, 6))
        self.update_btn = FlatButton(buttons, "Проверяю…", self.start_update, primary=True)
        self.update_btn.label.pack(side="left")
        self.check_btn = FlatButton(buttons, "Проверить снова", self.refresh)
        self.check_btn.label.pack(side="left", padx=10)
        tk.Label(frame, text="Адрес сервера, токен и ловушки при обновлении сохраняются.", bg=BG, fg=DIM,
                 font=(FONT, 9), anchor="w", padx=24).pack(fill="x", pady=(4, 16))

        self.root.update_idletasks()
        w, h = max(round(540 * self.scale), self.root.winfo_reqwidth()), self.root.winfo_reqheight()
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 3
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.bind("<Escape>", lambda e: self.root.destroy())
        self.root.after(10, self._as_app_window)
        self.refresh()

    # ---------- своя шапка вместо рамки Windows ----------

    def _title_bar(self, parent) -> None:
        from PIL import Image, ImageTk

        tk = self.tk
        bar = tk.Frame(parent, bg=PANEL, height=round(38 * self.scale))
        bar.pack(fill="x")
        bar.pack_propagate(False)
        mark = 16 * max(1, round(1.25 * self.scale))
        self._mark = ImageTk.PhotoImage(brand.logo(16).resize((mark, mark), Image.NEAREST))
        tk.Label(bar, image=self._mark, bg=PANEL).pack(side="left", padx=(12, 8))
        title = tk.Label(bar, text="DeepSec", bg=PANEL, fg=MUTED, font=(FONT, 10))
        title.pack(side="left")
        for text, command, hover in (("✕", self.root.destroy, ACCENT), ("—", self.minimize, BUTTON_HOVER)):
            button = tk.Label(bar, text=text, bg=PANEL, fg=MUTED, font=(FONT, 11), width=5, cursor="hand2")
            button.pack(side="right", fill="y")
            button.bind("<Enter>", lambda e, b=button, c=hover: b.config(bg=c, fg="white"))
            button.bind("<Leave>", lambda e, b=button: b.config(bg=PANEL, fg=MUTED))
            button.bind("<Button-1>", lambda e, c=command: c())
        for widget in (bar, title):
            widget.bind("<ButtonPress-1>", self._drag_start)
            widget.bind("<B1-Motion>", self._drag)

    def _drag_start(self, event) -> None:
        self._offset = (event.x_root - self.root.winfo_x(), event.y_root - self.root.winfo_y())

    def _drag(self, event) -> None:
        self.root.geometry(f"+{event.x_root - self._offset[0]}+{event.y_root - self._offset[1]}")

    def _as_app_window(self) -> None:
        """Окно без рамки Windows по умолчанию не попадает на панель задач — возвращаем его туда
        и просим Windows 11 скруглить углы."""
        hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
        style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, (style & ~WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW)
        try:
            corner = ctypes.c_int(2)  # DWMWCP_ROUND
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(corner), ctypes.sizeof(corner))
        except OSError:
            pass  # Windows 10 — углы останутся прямыми
        self.root.withdraw()
        self.root.after(10, self.root.deiconify)

    def minimize(self) -> None:
        # Окно без рамки свернуть нельзя — на время возвращаем рамку, а при разворачивании снова убираем.
        self.root.overrideredirect(False)
        self.root.iconify()
        self.root.bind("<Map>", self._restore)

    def _restore(self, event) -> None:
        if self.root.state() == "normal":
            self.root.unbind("<Map>")
            self.root.overrideredirect(True)
            self.root.after(10, self._as_app_window)

    # ---------- содержимое ----------

    def _status_row(self, parent):
        row = self.tk.Frame(parent, bg=BG)
        row.pack(fill="x", pady=2)
        dot = self.tk.Label(row, text="●", bg=BG, fg=DIM, font=(FONT, 10))
        dot.pack(side="left")
        text = self.tk.Label(row, text="", bg=BG, fg=FG, font=(FONT, 10), anchor="w")
        text.pack(side="left", padx=(6, 0))
        return dot, text

    @staticmethod
    def _set(row, text: str, color: str) -> None:
        dot, label = row
        dot.config(fg=color)
        label.config(text=text)

    def refresh(self) -> None:
        running = agent_running()
        self._set(self.agent, "Агент работает" if running else "Агент не запущен", OK if running else ACCENT)
        self._set(self.version, f"Версия {__version__}", MUTED)
        self._set(self.latest, "Проверяю обновления…", DIM)
        self.update_btn.set(False, "Проверяю…")
        threading.Thread(target=self._check, daemon=True).start()

    def _check(self) -> None:
        try:
            release, error = update.latest_release(), ""
        except update.UpdateError as e:
            release, error = None, str(e)
        self.root.after(0, self._show, release, error)

    def _show(self, release: update.Release | None, error: str) -> None:
        self.release = release
        enabled, label = update_button_state(release, error)
        self.update_btn.set(enabled, label)
        if error:
            self._set(self.latest, f"Не удалось проверить: {error}"[:70], ACCENT)
        elif enabled:
            self._set(self.latest, f"Вышла версия {release.version}", ACCENT)
        elif release is None:
            self._set(self.latest, "В релизах GitHub пока нет установщика", DIM)
        else:
            self._set(self.latest, "Установлена последняя версия", OK)

    def start_update(self) -> None:
        # Установка — дело администратора: окно UAC, затем консоль с ходом обновления
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "update --pause", None, 1)
        if result > 32:
            self.update_btn.set(False, "Обновление запущено…")
            self._set(self.latest, "Следите за окном консоли — агент перезапустится", FG)
        else:
            self._set(self.latest, "Отменено: нужны права администратора", ACCENT)

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    try:
        ctypes.windll.kernel32.FreeConsole()  # exe консольный: из меню «Пуск» без лишнего чёрного окна
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        # Свой AppUserModelID — иначе на панели задач окно сгруппируется с python/консолью и возьмёт их значок
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("DeepSec.Agent")
    except (AttributeError, OSError):
        pass
    Window().run()
    return 0


def update_main() -> int:
    """`DeepSecAgent.exe update`: проверить и поставить новую версию (от администратора)."""
    from .config import Config

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Запустите от имени администратора (окно DeepSec делает это само).")
        return 1
    cfg = Config.load()
    print(f"Сейчас стоит {__version__}. Проверяю релизы GitHub…")
    print(update.update(__version__, cfg.data_dir, cfg.update_repo))
    return 0
