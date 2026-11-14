"""Окно DeepSec (меню «Пуск» → DeepSec): состояние агента и обновление с прогрессом прямо в окне.

Окно работает от пользователя и без прав администратора: обновляет агент (SYSTEM), а окно говорит с ним
через локальный канал (control.py) — «Скачать», полоса загрузки с процентами, затем «Перезапустить и
обновить». Установщик закрывает все процессы DeepSec, ставит новую версию с прежними настройками, а агент
после перезапуска сам открывает окно снова — с сообщением «Обновлено».

Окно без стандартной рамки Windows: своя шапка (перетаскивание, свернуть, закрыть), значок на панели
задач и скруглённые углы Windows 11.
"""
from __future__ import annotations

import ctypes
import sys
import threading
from dataclasses import dataclass

from . import __version__, brand, control, update

BG, PANEL, BORDER = "#15161a", "#0f1013", "#2a2b31"
FG, MUTED, DIM = "#ece6d6", "#8a8f98", "#5d616b"
ACCENT, ACCENT_HOVER, OK = "#c0262d", "#9e1d23", "#4caf50"
BUTTON, BUTTON_HOVER = "#26272d", "#30323a"
FONT = "Segoe UI"
GWL_EXSTYLE, WS_EX_TOOLWINDOW, WS_EX_APPWINDOW = -20, 0x80, 0x40000
POLL_MS = 300
MB = 1024 * 1024


@dataclass(frozen=True)
class View:
    """Что показать по состоянию обновления в агенте: строка статуса, кнопка, полоса загрузки."""
    status: str
    color: str
    button: str
    action: str | None  # что делает кнопка: check | download | install; None — неактивна
    progress: float | None = None  # 0..1 — показать полосу
    detail: str = ""


def view(snap: dict | None) -> View:
    if snap is None:
        return View("Агент не отвечает — обновить через окно нельзя", ACCENT, "Обновить", None)
    state, new = snap.get("state"), snap.get("available") or snap.get("latest") or ""
    if state in ("idle", "checking"):
        return View("Проверяю обновления…", DIM, "Проверяю…", None)
    if state == "downloading":
        done, total = int(snap.get("done") or 0), int(snap.get("total") or 0)
        share = done / total if total else 0.0
        detail = f"{share:.0%} · {done / MB:.1f} из {total / MB:.1f} МБ" if total else f"{done / MB:.1f} МБ"
        return View(f"Скачиваю версию {new}…", FG, "Скачивание…", None, share, detail)
    if state == "ready":
        return View(f"Версия {new} скачана, SHA-256 проверен", OK, "Перезапустить и обновить", "install", 1.0,
                    "100% · готово к установке")
    if state == "installing":
        return View(f"Устанавливаю {new}…", FG, "Устанавливаю…", None, 1.0, "окно откроется снова")
    if state == "error":
        return View(f"Ошибка: {snap.get('error') or 'неизвестно'}"[:90], ACCENT, "Повторить", "check")
    if snap.get("available"):
        return View(f"Вышла версия {new}", ACCENT, f"Скачать {new}", "download")
    return View("Установлена последняя версия", OK, "Обновлений нет", None)


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
    def __init__(self, updated_from: str = "") -> None:
        import tkinter as tk
        from PIL import Image, ImageTk

        self.tk = tk
        self.root = tk.Tk()
        self.root.title("DeepSec")
        self.root.overrideredirect(True)
        self.root.configure(bg=BORDER)
        self.root.resizable(False, False)
        self.scale = max(1.0, self.root.winfo_fpixels("1i") / 96)  # 150% в Windows — картинки тоже крупнее
        self._icons = [ImageTk.PhotoImage(brand.icon_image(256)), ImageTk.PhotoImage(brand.icon_image(32))]
        self.root.iconphoto(True, *self._icons)
        self.action: str | None = None
        self.polling = False

        frame = tk.Frame(self.root, bg=BG)
        frame.pack(fill="both", expand=True, padx=1, pady=1)  # 1 px рамка цветом BORDER
        self._title_bar(frame)
        if updated_from:
            tk.Label(frame, text=f"✓  Обновлено: {updated_from} → {__version__}. Настройки сохранены.",
                     bg="#1d3a24", fg="#cfe9d3", font=(FONT, 10), anchor="w", padx=24, pady=8).pack(fill="x")

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
        self.bar = tk.Canvas(info, height=round(8 * self.scale), bg=BG, highlightthickness=0)
        self.bar.bind("<Configure>", self._draw_bar)
        self.detail = tk.Label(info, text="", bg=BG, fg=MUTED, font=(FONT, 9), anchor="w")

        buttons = tk.Frame(frame, bg=BG, padx=24)
        buttons.pack(fill="x", pady=(0, 6))
        self.update_btn = FlatButton(buttons, "Проверяю…", self.on_primary, primary=True)
        self.update_btn.label.pack(side="left")
        self.check_btn = FlatButton(buttons, "Проверить снова", lambda: self.request("/update/check"))
        self.check_btn.label.pack(side="left", padx=10)
        tk.Label(frame, text="Адрес сервера, токен и ловушки при обновлении сохраняются.", bg=BG, fg=DIM,
                 font=(FONT, 9), anchor="w", padx=24).pack(fill="x", pady=(4, 16))

        self.root.update_idletasks()
        self.width = w = max(round(560 * self.scale), self.root.winfo_reqwidth())
        h = self.root.winfo_reqheight()
        self.root.geometry(f"{w}x{h}+{(self.root.winfo_screenwidth() - w) // 2}"
                           f"+{(self.root.winfo_screenheight() - h) // 3}")
        self.root.bind("<Escape>", lambda e: self.root.destroy())
        self.root.after(10, self._as_app_window)
        self.request("/update/check")

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

    # ---------- обновление через агента ----------

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

    def request(self, path: str, method: str = "POST") -> None:
        """Запрос к агенту в фоне (проверка обновлений идёт до секунды, установка — пару секунд)."""
        self.update_btn.set(False)
        self.check_btn.set(False)

        def work() -> None:
            try:
                snap = control.call(path, method, timeout=60)
            except OSError:
                snap = None
            self.root.after(0, self.show, snap)

        threading.Thread(target=work, daemon=True).start()

    def show(self, snap: dict | None) -> None:
        v = view(snap)
        self.action = v.action
        running = snap is not None
        self._set(self.agent, "Агент работает" if running else "Агент не запущен", OK if running else ACCENT)
        self._set(self.version, f"Версия {(snap or {}).get('version') or __version__}", MUTED)
        self._set(self.latest, v.status, v.color)
        self.update_btn.set(v.action is not None, v.button)
        state = (snap or {}).get("state")
        self.check_btn.set(state not in update.Updater.BUSY and state != "ready")
        self._progress(v)
        if state in update.Updater.BUSY and state != "installing":
            self.root.after(POLL_MS, lambda: self.request("/update", "GET"))
        if state == "installing":
            # Установщик закроет все процессы DeepSec, а агент после перезапуска откроет окно снова
            self.root.after(1500, self.root.destroy)

    def _progress(self, v: View) -> None:
        self.shown = v
        if v.progress is None:
            self.bar.pack_forget()
            self.detail.pack_forget()
        else:
            self.bar.pack(fill="x", pady=(10, 2))
            self.detail.pack(fill="x")
            self.detail.config(text=v.detail)
            self._draw_bar()
        self._fit()

    def _draw_bar(self, event=None) -> None:
        # Ширина полосы известна только после раскладки — перерисовываем и по <Configure>
        v = getattr(self, "shown", None)
        if v is None or v.progress is None:
            return
        width, height = self.bar.winfo_width(), int(self.bar["height"])
        self.bar.delete("all")
        self.bar.create_rectangle(0, 0, width, height, fill=BUTTON, outline="")
        fill = OK if v.progress >= 1 else ACCENT
        self.bar.create_rectangle(0, 0, max(2, int(width * v.progress)), height, fill=fill, outline="")

    def _fit(self) -> None:
        """Высота окна — по содержимому: полоса загрузки то появляется, то исчезает."""
        self.root.update_idletasks()
        height = self.root.winfo_reqheight()
        if height != self.root.winfo_height():
            self.root.geometry(f"{self.width}x{height}+{self.root.winfo_x()}+{self.root.winfo_y()}")

    def on_primary(self) -> None:
        if self.action == "check":
            self.request("/update/check")
        elif self.action == "download":
            self.request("/update/download")
        elif self.action == "install":
            self.request("/update/install")

    def run(self) -> None:
        self.root.mainloop()


def main(updated_from: str = "") -> int:
    try:
        ctypes.windll.kernel32.FreeConsole()  # exe консольный: из меню «Пуск» без лишнего чёрного окна
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        # Свой AppUserModelID — иначе на панели задач окно сгруппируется с python/консолью и возьмёт их значок
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("DeepSec.Agent")
    except (AttributeError, OSError):
        pass
    Window(updated_from).run()
    return 0


def update_main() -> int:
    """`DeepSecAgent.exe update`: проверить и поставить новую версию из консоли (от администратора)."""
    from .config import Config

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Запустите от имени администратора — или обновите из окна DeepSec, там права не нужны.")
        return 1
    cfg = Config.load()
    print(f"Сейчас стоит {__version__}. Проверяю релизы GitHub…")
    print(update.update(__version__, cfg.data_dir, cfg.update_repo))
    return 0


if __name__ == "__main__":
    sys.exit(main())
