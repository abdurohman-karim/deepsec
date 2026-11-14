"""Окно DeepSec (меню «Пуск» → DeepSec): версия, работает ли агент, проверка и установка обновлений.

Окно работает от пользователя. Настройки агента (.env) ему не видны — они доступны только SYSTEM и
администраторам — и не нужны: «Обновить» запускает `DeepSecAgent.exe update` с правами администратора
(окно UAC), а тот ставит новую версию тихо, сохраняя адрес сервера, токен, ловушки и задачу агента.
"""
from __future__ import annotations

import ctypes
import sys
import threading

import psutil

from . import __version__, update
from .desktop import helper_args

BG, FG, MUTED, ACCENT, OK = "#15161a", "#ece6d6", "#8a8f98", "#c0262d", "#4caf50"


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


class Window:
    def __init__(self) -> None:
        import tkinter as tk

        self.tk = tk
        self.root = tk.Tk()
        self.root.title("DeepSec")
        self.root.configure(bg=BG, padx=22, pady=18)
        self.root.resizable(False, False)
        self.release: update.Release | None = None

        def label(text: str = "", size: int = 11, color: str = FG, bold: bool = False) -> tk.Label:
            widget = tk.Label(self.root, text=text, bg=BG, fg=color, anchor="w", justify="left",
                              font=("Segoe UI", size, "bold" if bold else "normal"))
            widget.pack(fill="x", pady=2)
            return widget

        label("👁 DeepSec", 16, FG, bold=True)
        label(f"Версия агента: {__version__}")
        self.agent = label()
        self.latest = label("Последняя версия: проверяю…", color=MUTED)
        label("Настройки (сервер, токен, ловушки) при обновлении сохраняются.", 9, MUTED)
        buttons = tk.Frame(self.root, bg=BG)
        buttons.pack(fill="x", pady=(12, 0))
        self.update_btn = tk.Button(buttons, text="⬆ Обновить", command=self.start_update, state="disabled",
                                    bg=ACCENT, fg="white", activebackground="#a01e24", relief="flat", padx=14, pady=4)
        self.update_btn.pack(side="left")
        tk.Button(buttons, text="Проверить снова", command=self.refresh, bg="#2a2c33", fg=FG,
                  activebackground="#383b44", relief="flat", padx=14, pady=4).pack(side="left", padx=8)
        self.refresh()

    def refresh(self) -> None:
        running = agent_running()
        # Цветные эмодзи Tk рисует штриховкой — состояние показываем цветом текста
        self.agent.config(text="Агент: ● работает" if running else "Агент: ● не запущен",
                          fg=OK if running else ACCENT)
        self.latest.config(text="Последняя версия: проверяю…", fg=MUTED)
        self.update_btn.config(state="disabled")
        threading.Thread(target=self._check, daemon=True).start()

    def _check(self) -> None:
        try:
            release, error = update.latest_release(), ""
        except update.UpdateError as e:
            release, error = None, str(e)
        self.root.after(0, self._show, release, error)

    def _show(self, release: update.Release | None, error: str) -> None:
        self.release = release
        if error:
            self.latest.config(text=f"Не удалось проверить: {error}"[:90], fg=ACCENT)
        elif release is None:
            self.latest.config(text="В релизах GitHub пока нет установщика", fg=MUTED)
        elif update.is_newer(release.version, __version__):
            self.latest.config(text=f"Доступна версия {release.version}", fg=FG)
            self.update_btn.config(state="normal")
        else:
            self.latest.config(text=f"У вас последняя версия ({release.version})", fg=MUTED)

    def start_update(self) -> None:
        # Установка — дело администратора: окно UAC, затем консоль с ходом обновления
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "update --pause", None, 1)
        if result > 32:
            self.latest.config(text="Обновление запущено — следите за окном консоли", fg=FG)
            self.update_btn.config(state="disabled")
        else:
            self.latest.config(text="Обновление отменено (нужны права администратора)", fg=ACCENT)

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    try:
        ctypes.windll.kernel32.FreeConsole()  # exe консольный: из меню «Пуск» без лишнего чёрного окна
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
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
