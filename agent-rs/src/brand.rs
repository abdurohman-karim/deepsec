//! Логотип DeepSec — пиксельный «Большой глаз» на тёмной плитке с красными лучами (как deepsec/brand.py).
//!
//! Только стандартная библиотека: этот же файл подключает build.rs, чтобы нарисовать иконку exe
//! (`#[path = "src/brand.rs"]`), а окно DeepSec — логотип в шапке и в карточке.

#![allow(dead_code)]

use std::f64::consts::PI;

type Rgb = [u8; 3];
const TILE: Rgb = [21, 20, 25];
const RAY_LIGHT: Rgb = [92, 14, 18];
const RAY_DARK: Rgb = [38, 8, 10];
const OUTLINE: Rgb = [12, 5, 6];
const SCLERA: Rgb = [232, 220, 192];
const SCLERA_SHADE: Rgb = [186, 168, 138];
const IRIS: Rgb = [178, 24, 32];
const IRIS_DARK: Rgb = [48, 7, 10];
const IRIS_HOT: Rgb = [236, 56, 60];
const PUPIL: Rgb = [6, 4, 4];
const SHINE: Rgb = [255, 250, 240];
const RAYS: f64 = 12.0;

/// Размер иконки -> сетка «пикселей»: мелкие рисуются один в один, крупные — увеличенные в 2–8 раз.
pub const ICON_GRIDS: [(usize, usize); 7] = [(16, 16), (24, 24), (32, 16), (48, 24), (64, 32), (128, 32), (256, 32)];

/// Логотип grid×grid пикселей, RGBA построчно сверху вниз.
pub fn logo(grid: usize) -> Vec<u8> {
    let g = grid as f64;
    let c = g / 2.0;
    let radius = (g / 5.0).max(2.0); // скругление плитки
    let (eye_w, eye_h, iris) = (g * 0.86, g * 0.25, g * 0.2);
    let mut rgba = vec![0u8; grid * grid * 4];
    for y in 0..grid {
        for x in 0..grid {
            let (fx, fy) = (x as f64 + 0.5, y as f64 + 0.5);
            if !in_tile(fx, fy, g, radius) {
                continue;
            }
            let color = eye(fx, fy, c, eye_w, eye_h, iris, grid);
            rgba[(y * grid + x) * 4..][..4].copy_from_slice(&[color[0], color[1], color[2], 255]);
        }
    }
    rgba
}

fn in_tile(x: f64, y: f64, size: f64, r: f64) -> bool {
    let dx = (r - x).max(0.0).max(x - (size - r));
    let dy = (r - y).max(0.0).max(y - (size - r));
    dx * dx + dy * dy <= r * r
}

fn half(x: f64, c: f64, w: f64, h: f64) -> f64 {
    let t = (x - (c - w / 2.0)) / w;
    if 0.0 < t && t < 1.0 { h * (PI * t).sin().powf(0.7) } else { 0.0 }
}

fn eye(x: f64, y: f64, c: f64, w: f64, h: f64, iris: f64, grid: usize) -> Rgb {
    let half = half(x, c, w, h);
    let edge = if grid < 24 { 1.0 } else { 1.4 }; // толщина контура в «пикселях»
    if (y - c).abs() >= half {
        if (y - c).abs() < half + edge && half > 0.0 {
            return OUTLINE;
        }
        if grid < 24 {
            return TILE; // на 16×16 лучи превращаются в шум — только плитка
        }
        let sector = (((y - c).atan2(x - c) + PI) / (2.0 * PI / RAYS)).trunc() as i64 % 2;
        return if sector == 0 { RAY_LIGHT } else { RAY_DARK };
    }
    let d = (x - c).hypot(y - c);
    if grid >= 24 && (x - (c - iris * 0.38)).hypot(y - (c - iris * 0.38)) < iris * 0.2 {
        return SHINE;
    }
    if d < iris * 0.42 {
        PUPIL
    } else if d < iris * 0.62 {
        if grid >= 24 { IRIS_HOT } else { IRIS }
    } else if d < iris * 0.78 {
        if grid >= 24 { IRIS_DARK } else { IRIS }
    } else if d < iris {
        IRIS
    } else if d < iris + 0.9 {
        IRIS_DARK
    } else if y < c - half + edge + 1.2 {
        SCLERA_SHADE // тень от верхнего века — взгляд тяжелее
    } else {
        SCLERA
    }
}

/// Увеличение без сглаживания — пиксели остаются квадратными.
pub fn scale_nearest(rgba: &[u8], from: usize, to: usize) -> Vec<u8> {
    let mut out = vec![0u8; to * to * 4];
    for y in 0..to {
        for x in 0..to {
            let (sx, sy) = (x * from / to, y * from / to);
            out[(y * to + x) * 4..][..4].copy_from_slice(&rgba[(sy * from + sx) * 4..][..4]);
        }
    }
    out
}

pub fn icon_image(size: usize) -> Vec<u8> {
    let grid = ICON_GRIDS.iter().find(|(s, _)| *s == size).map_or(32, |(_, g)| *g);
    scale_nearest(&logo(grid), grid, size)
}

/// ICO со своей картинкой на каждый размер: 32-битные BMP с альфой (AND-маска пустая).
pub fn ico_bytes() -> Vec<u8> {
    let mut images = Vec::new();
    for (size, _) in ICON_GRIDS {
        let rgba = icon_image(size);
        let mut bmp = Vec::new();
        bmp.extend_from_slice(&40u32.to_le_bytes());
        bmp.extend_from_slice(&(size as i32).to_le_bytes());
        bmp.extend_from_slice(&((size * 2) as i32).to_le_bytes()); // высота XOR + AND
        bmp.extend_from_slice(&1u16.to_le_bytes());
        bmp.extend_from_slice(&32u16.to_le_bytes());
        bmp.extend_from_slice(&[0u8; 24]);
        for y in (0..size).rev() {
            for x in 0..size {
                let p = &rgba[(y * size + x) * 4..][..4];
                bmp.extend_from_slice(&[p[2], p[1], p[0], p[3]]);
            }
        }
        bmp.extend(std::iter::repeat_n(0u8, size.div_ceil(32) * 4 * size));
        images.push((size, bmp));
    }
    let mut ico = Vec::new();
    ico.extend_from_slice(&[0, 0, 1, 0]);
    ico.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len();
    for (size, bmp) in &images {
        let side = if *size >= 256 { 0 } else { *size as u8 };
        ico.extend_from_slice(&[side, side, 0, 0]);
        ico.extend_from_slice(&1u16.to_le_bytes());
        ico.extend_from_slice(&32u16.to_le_bytes());
        ico.extend_from_slice(&(bmp.len() as u32).to_le_bytes());
        ico.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += bmp.len();
    }
    for (_, bmp) in images {
        ico.extend(bmp);
    }
    ico
}

/// Картинка в шапке мастера установки: 24-битный BMP на белом фоне — так требует Inno Setup.
pub fn wizard_bmp(size: usize) -> Vec<u8> {
    let rgba = scale_nearest(&logo(32), 32, size);
    let row = (size * 3).div_ceil(4) * 4;
    let mut bmp = Vec::new();
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&((54 + row * size) as u32).to_le_bytes());
    bmp.extend_from_slice(&[0, 0, 0, 0]);
    bmp.extend_from_slice(&54u32.to_le_bytes());
    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&(size as i32).to_le_bytes());
    bmp.extend_from_slice(&(size as i32).to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&24u16.to_le_bytes());
    bmp.extend_from_slice(&[0u8; 24]);
    for y in (0..size).rev() {
        let start = bmp.len();
        for x in 0..size {
            let p = &rgba[(y * size + x) * 4..][..4];
            let a = p[3] as u32;
            let mix = |c: u8| ((c as u32 * a + 255 * (255 - a)) / 255) as u8;
            bmp.extend_from_slice(&[mix(p[2]), mix(p[1]), mix(p[0])]);
        }
        bmp.resize(start + row, 0);
    }
    bmp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_has_every_size_and_the_eye_in_the_middle() {
        let ico = ico_bytes();
        assert_eq!(u16::from_le_bytes([ico[4], ico[5]]) as usize, ICON_GRIDS.len());
        for (size, _) in ICON_GRIDS {
            let img = icon_image(size);
            let center = &img[((size / 2) * size + size / 2) * 4..][..3];
            assert!([PUPIL, IRIS, IRIS_HOT].iter().any(|c| c == center), "{size}: {center:?}"); // в центре — зрачок
            assert_eq!(img[3], 0); // скруглённый угол прозрачный
        }
        let bmp = wizard_bmp(110);
        assert_eq!(&bmp[..2], b"BM");
        assert_eq!(&bmp[54..57], &[255, 255, 255]); // угол — белый фон
    }
}
