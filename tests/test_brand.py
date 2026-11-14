from __future__ import annotations

import pytest

PIL = pytest.importorskip("PIL")


def test_icon_has_every_size_and_draws_the_eye(tmp_path):
    from PIL import Image

    from deepsec import brand

    brand.write_ico(tmp_path / "deepsec.ico")
    with Image.open(tmp_path / "deepsec.ico") as ico:
        assert set(ico.info["sizes"]) == {(s, s) for s in brand.ICON_GRIDS}
    for size in brand.ICON_GRIDS:
        image = brand.icon_image(size)
        assert image.size == (size, size)
        center = image.getpixel((size // 2, size // 2))
        assert center[3] == 255 and center[:3] in (brand.PUPIL, brand.IRIS, brand.IRIS_HOT)  # в центре — зрачок
        assert image.getpixel((0, 0))[3] == 0  # скруглённый угол прозрачный

    brand.write_wizard_image(tmp_path / "wizard.bmp")
    with Image.open(tmp_path / "wizard.bmp") as bmp:
        assert bmp.format == "BMP" and bmp.getpixel((0, 0)) == (255, 255, 255)


def test_window_view_for_each_update_state():
    from deepsec.window import view

    snap = {"version": "0.6.2", "latest": "0.7.0", "available": "0.7.0", "done": 0, "total": 0, "error": ""}
    assert view(None).action is None and "не отвечает" in view(None).status
    assert view({**snap, "state": "checking"}).action is None
    available = view({**snap, "state": "available"})
    assert available.action == "download" and available.button == "Скачать 0.7.0" and available.progress is None
    half = view({**snap, "state": "downloading", "done": 10 * 1024 * 1024, "total": 20 * 1024 * 1024})
    assert half.action is None and half.progress == 0.5 and half.detail == "50% · 10.0 из 20.0 МБ"
    ready = view({**snap, "state": "ready"})
    assert ready.action == "install" and "Перезапустить" in ready.button and ready.progress == 1.0
    assert view({**snap, "state": "error", "error": "нет сети"}).action == "check"
    latest = view({**snap, "state": "latest", "available": "", "latest": "0.6.2"})
    assert latest.action is None and latest.button == "Обновлений нет"  # неактивная кнопка — серая
