from __future__ import annotations

import pytest

from deepsec import update

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


def test_update_button_is_only_active_for_a_newer_release():
    from deepsec.window import update_button_state

    newer = update.Release("0.7.0", "u", "h", "DeepSecSetup-0.7.0.exe")
    same = update.Release("0.6.1", "u", "h", "DeepSecSetup-0.6.1.exe")
    assert update_button_state(newer, "", "0.6.1") == (True, "⬆  Обновить до 0.7.0")
    assert update_button_state(same, "", "0.6.1") == (False, "Обновлений нет")
    assert update_button_state(None, "", "0.6.1") == (False, "Обновлений нет")
    assert update_button_state(newer, "GitHub не ответил", "0.6.1") == (False, "Обновление недоступно")
