//! Пиксельный «Большой глаз» в правом нижнем углу экрана — владелец включает его из бота (как deepsec/pet.py).
//!
//! Окно Win32 без рамки поверх всех окон: прозрачное для мыши (клики уходят в игру), никогда не становится
//! активным (полноэкранная игра не свернётся) и не видно на панели задач. Кадр рисуем сами и отдаём
//! в UpdateLayeredWindow — с настоящей прозрачностью.

use std::cell::RefCell;
use std::f64::consts::PI;
use std::ffi::c_void;
use std::time::Instant;

use ab_glyph::{Font, FontVec, PxScale, ScaleFont};
use anyhow::{Context, Result};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, SIZE, WPARAM};
use windows::Win32::Graphics::Gdi::{
    AC_SRC_ALPHA, AC_SRC_OVER, BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BLENDFUNCTION, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS, GetDC,
    HDC, SelectObject,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForSystem, SetProcessDpiAwarenessContext};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, HWND_TOPMOST, MSG, PostQuitMessage,
    RegisterClassW, SPI_GETWORKAREA, SW_SHOWNOACTIVATE, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SetTimer,
    SetWindowPos, ShowWindow, SystemParametersInfoW, TranslateMessage, ULW_ALPHA, UpdateLayeredWindow, WM_DESTROY, WM_TIMER, WNDCLASSW,
    WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
};
use windows::core::w;

use crate::protocol::{PET_MAX_TEXT, PET_MOODS, pet_text};

const MAX_MINUTES: f64 = 240.0;
const FPS: u32 = 12;

// Сетка в «пикселях»: миндалевидный глаз 46×22 на фоне тёмно-красных лучей.
const GW: usize = 60;
const GH: usize = 36;
const EYE_W: f64 = 46.0;
const EYE_HALF: f64 = 11.0;
const EYE_X0: f64 = (GW as f64 - EYE_W) / 2.0;
const CX: f64 = GW as f64 / 2.0;
const CY: f64 = GH as f64 / 2.0;
const IRIS_R: f64 = 9.5;
const RAYS: f64 = 16.0;

type Rgba = [u8; 4];
const OUTLINE: Rgba = [14, 6, 7, 255];
const LID: Rgba = [40, 9, 11, 255];
const SCLERA: Rgba = [232, 220, 192, 255];
const SCLERA_SHADE: Rgba = [190, 172, 142, 255];
const VEIN: Rgba = [168, 26, 32, 255];
const IRIS: Rgba = [172, 22, 30, 255];
const IRIS_DARK: Rgba = [42, 6, 9, 255];
const IRIS_HOT: Rgba = [232, 52, 56, 255];
const PUPIL: Rgba = [6, 4, 4, 255];
const SHINE: Rgba = [255, 250, 240, 255];
const RAY_LIGHT: [u8; 3] = [112, 14, 18];
const RAY_DARK: [u8; 3] = [34, 6, 8];
const TEXT: [u8; 3] = [0xef, 0xe3, 0xc8];

/// Веко по настроению: (верх, низ) — какая доля глаза закрыта. Тяжёлое верхнее веко делает взгляд серьёзным.
fn lids_for(mood: &str) -> (f64, f64) {
    match mood {
        "happy" => (0.10, 0.28),
        "angry" => (0.30, 0.12),
        "sleep" => (1.0, 0.0),
        _ => (0.14, 0.04),
    }
}

/// Смещение радужки в «пикселях» сетки к курсору; dx, dy — от центра глаза в пикселях экрана.
pub fn gaze(dx: f64, dy: f64) -> (f64, f64) {
    let squash = |v: f64| v / (1.0 + v.abs());
    (11.0 * squash(dx / 500.0), 4.0 * squash(dy / 350.0))
}

fn half_height(x: usize) -> f64 {
    let t = (x as f64 + 0.5 - EYE_X0) / EYE_W;
    if 0.0 < t && t < 1.0 { EYE_HALF * (PI * t).sin().powf(0.7) } else { 0.0 }
}

/// Красные прожилки злого глаза: короткие ломаные от уголков к радужке (всегда одинаковые).
fn veins() -> Vec<(i64, i64)> {
    let mut seed: u64 = 13;
    let mut next = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) as f64 / (1u64 << 31) as f64
    };
    let mut points = Vec::new();
    for i in 0..10 {
        let left = i % 2 == 0;
        let offset = 3.0 + next() * 8.0;
        let mut x = if left { (EYE_X0 + offset).round() } else { (EYE_X0 + EYE_W - offset).round() } as i64;
        let mut y = (CY + (next() * 1.2 - 0.6) * EYE_HALF).round() as i64;
        for _ in 0..(5 + (next() * 5.0) as usize) {
            points.push((x, y));
            x += if left { 1 } else { -1 };
            y += [-1, 0, 0, 1][(next() * 4.0) as usize % 4];
        }
    }
    points
}

/// Монохромная маска текста с обводкой: (ширина, высота, заливка, обводка) — альфа 0..255.
struct TextMask {
    width: usize,
    height: usize,
    fill: Vec<u8>,
    stroke: Vec<u8>,
}

fn render_text(font: &FontVec, text: &str, size: f32, stroke: usize) -> TextMask {
    let scaled = font.as_scaled(PxScale::from(size));
    let mut x = 0.0f32;
    let mut glyphs = Vec::new();
    let mut last = None;
    for ch in text.chars() {
        let id = scaled.glyph_id(ch);
        if let Some(prev) = last {
            x += scaled.kern(prev, id);
        }
        glyphs.push(id.with_scale_and_position(PxScale::from(size), ab_glyph::point(x, scaled.ascent())));
        x += scaled.h_advance(id);
        last = Some(id);
    }
    let pad = stroke + 1;
    let (width, height) = (x.ceil() as usize + 2 * pad, (scaled.ascent() - scaled.descent()).ceil() as usize + 2 * pad);
    let mut fill = vec![0u8; width * height];
    for glyph in glyphs {
        if let Some(outline) = font.outline_glyph(glyph) {
            let bounds = outline.px_bounds();
            outline.draw(|gx, gy, c| {
                let px = bounds.min.x as i64 + gx as i64 + pad as i64;
                let py = bounds.min.y as i64 + gy as i64 + pad as i64;
                if px >= 0 && py >= 0 && (px as usize) < width && (py as usize) < height {
                    let cell = &mut fill[py as usize * width + px as usize];
                    *cell = (*cell).max((c * 255.0) as u8);
                }
            });
        }
    }
    // Обводка — расширение маски на радиус stroke (диск)
    let mut out = vec![0u8; width * height];
    let r = stroke as i64;
    for y in 0..height as i64 {
        for x in 0..width as i64 {
            let mut best = 0u8;
            for dy in -r..=r {
                for dx in -r..=r {
                    if dx * dx + dy * dy > r * r + r {
                        continue;
                    }
                    let (sx, sy) = (x + dx, y + dy);
                    if sx >= 0 && sy >= 0 && sx < width as i64 && sy < height as i64 {
                        best = best.max(fill[sy as usize * width + sx as usize]);
                    }
                }
            }
            out[y as usize * width + x as usize] = best;
        }
    }
    TextMask { width, height, fill, stroke: out }
}

pub struct Pet {
    mood: &'static str,
    cell: usize,
    text: TextMask,
    z: Option<TextMask>,
    eye_x: usize,
    pub width: usize,
    pub height: usize,
    half: [f64; GW],
    veins: Vec<(i64, i64)>,
    look: (f64, f64),
    started: Instant,
    next_blink: f64,
}

impl Pet {
    pub fn new(mood: &str, text: &str, scale: usize) -> Result<Pet> {
        let mood = PET_MOODS.iter().copied().find(|m| *m == mood).unwrap_or("watch");
        let clean: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let text: String = if clean.is_empty() { pet_text(mood).to_string() } else { clean }.chars().take(PET_MAX_TEXT).collect();
        let font = load_font()?;
        let stroke = (scale / 3).max(2);
        let mask = render_text(&font, &text, (scale as f32 * 3.4).round(), stroke);
        let z = (mood == "sleep").then(|| render_text(&font, "z", (scale as f32 * 2.4).round(), stroke));
        let cell = ((scale as f64 * 0.6).round() as usize).max(3);
        let eye_x = mask.width + scale * 2;
        let mut half = [0.0; GW];
        for (x, h) in half.iter_mut().enumerate() {
            *h = half_height(x);
        }
        Ok(Pet {
            mood,
            cell,
            eye_x,
            width: eye_x + GW * cell,
            height: (GH * cell).max(mask.height),
            text: mask,
            z,
            half,
            veins: veins(),
            look: (0.0, 0.0),
            started: Instant::now(),
            next_blink: 2.5 + rand::random::<f64>() * 3.5,
        })
    }

    fn inside(&self, x: i64, y: i64) -> bool {
        x >= 0 && y >= 0 && (x as usize) < GW && (y as usize) < GH && ((y as f64 + 0.5) - CY).abs() < self.half[x as usize]
    }

    fn lids(&mut self, t: f64) -> (f64, f64) {
        let (mut top, bottom) = lids_for(self.mood);
        if self.mood == "sleep" {
            // Спит — но иногда приоткрывает глаз и подсматривает
            let phase = t % 7.0;
            if 5.0 < phase && phase < 6.6 {
                let opening = ((phase - 5.0) / 0.3).min((6.6 - phase) / 0.3).min(1.0);
                top = 1.0 - 0.5 * opening;
            }
            return (top, bottom);
        }
        if t >= self.next_blink {
            let progress = (t - self.next_blink) / 0.3;
            if progress >= 1.0 {
                self.next_blink = t + 2.5 + rand::random::<f64>() * 3.5;
            } else {
                top = top.max(1.0 - (2.0 * progress - 1.0).abs());
            }
        }
        (top, bottom)
    }

    fn eye_pixel(&self, x: i64, y: i64, top: f64, bottom: f64, t: f64) -> Option<Rgba> {
        if !self.inside(x, y) {
            return None;
        }
        let h = self.half[x as usize];
        let (lid_top, lid_bottom) = (CY - h + 2.0 * h * top, CY + h - 2.0 * h * bottom);
        let covered = |yy: i64| (yy as f64 + 0.5) < lid_top || (yy as f64 + 0.5) > lid_bottom;
        if !(self.inside(x - 1, y) && self.inside(x + 1, y) && self.inside(x, y - 2) && self.inside(x, y + 1)) {
            return Some(OUTLINE); // контур, сверху — в два пикселя
        }
        if covered(y) {
            return Some(LID);
        }
        if covered(y - 1) || covered(y + 1) {
            return Some(OUTLINE); // край века
        }
        let (dx, dy) = (x as f64 + 0.5 - (CX + self.look.0), y as f64 + 0.5 - (CY + self.look.1));
        let d = dx.hypot(dy);
        if d < IRIS_R {
            return Some(self.iris_pixel(dx, dy, d, t));
        }
        if covered(y - 2) || covered(y - 3) {
            return Some(SCLERA_SHADE); // тень от века
        }
        if self.mood == "angry" && self.veins.contains(&(x, y)) {
            return Some(VEIN);
        }
        Some(SCLERA)
    }

    fn iris_pixel(&self, dx: f64, dy: f64, d: f64, t: f64) -> Rgba {
        if (dx + 3.0).hypot(dy + 3.0) < 1.3 {
            return SHINE;
        }
        let pupil = match self.mood {
            "angry" => {
                if dy.abs() < 5.5 && dx.abs() < 1.3 * (1.0 - (dy / 6.0).powi(2)) {
                    return PUPIL; // вертикальный зрачок, как у змеи
                }
                0.0
            }
            "happy" => 4.2,
            "sleep" => 3.0,
            _ => 2.7 + 0.5 * (t * 1.1).sin(),
        };
        if d < pupil {
            PUPIL
        } else if d < pupil + 1.3 {
            IRIS_HOT
        } else if d < pupil + 2.7 {
            IRIS_DARK
        } else if d < IRIS_R - 1.2 {
            IRIS
        } else {
            IRIS_DARK
        }
    }

    fn ray_pixel(x: usize, y: usize, rotation: f64, glow: f64) -> Option<Rgba> {
        let (nx, ny) = ((x as f64 + 0.5 - CX) / CX, (y as f64 + 0.5 - CY) / CY);
        let r = nx.hypot(ny);
        if r >= 1.0 {
            return None;
        }
        let sector = (((ny.atan2(nx) + rotation) / (2.0 * PI / RAYS)).trunc() as i64).rem_euclid(2);
        let base = if sector == 0 { RAY_LIGHT } else { RAY_DARK };
        let alpha = match (sector == 0, r < 0.75) {
            (true, true) => 200,
            (false, true) => 150,
            (true, false) => 110,
            (false, false) => 70,
        };
        let c = |v: u8| ((v as f64 * glow).round() as u32).min(255) as u8;
        Some([c(base[0]), c(base[1]), c(base[2]), alpha])
    }

    /// Кадр RGBA (без умножения на альфу). cursor и origin (левый верх окна) — чтобы смотреть на курсор.
    pub fn frame(&mut self, cursor: (i32, i32), origin: (i32, i32)) -> Vec<u8> {
        let t = self.started.elapsed().as_secs_f64();
        let cell = self.cell as f64;
        let target = gaze(
            cursor.0 as f64 - (origin.0 as f64 + self.eye_x as f64 + CX * cell),
            cursor.1 as f64 - (origin.1 as f64 + CY * cell),
        );
        // Взгляд догоняет курсор медленно — «тяжело», так страшнее
        self.look = (self.look.0 + (target.0 - self.look.0) * 0.18, self.look.1 + (target.1 - self.look.1) * 0.18);
        let (top, bottom) = self.lids(t);
        let angry = self.mood == "angry";
        let rotation = t * if angry { 0.5 } else { 0.12 };
        let glow = 1.0 + if angry { 0.25 * (t * 6.0).sin() } else { 0.0 };

        let mut image = vec![0u8; self.width * self.height * 4];
        let shake = if angry { [-1i64, 0, 1][rand::random_range(0..3)] * (self.cell as i64 / 2) } else { 0 };
        for gy in 0..GH {
            for gx in 0..GW {
                let color = self.eye_pixel(gx as i64, gy as i64, top, bottom, t).or_else(|| Self::ray_pixel(gx, gy, rotation, glow));
                let Some(color) = color else { continue };
                for py in gy * self.cell..(gy + 1) * self.cell {
                    for px in gx * self.cell..(gx + 1) * self.cell {
                        let x = self.eye_x as i64 + px as i64 + shake;
                        if x >= 0 && (x as usize) < self.width && py < self.height {
                            let i = (py * self.width + x as usize) * 4;
                            image[i..i + 4].copy_from_slice(&color);
                        }
                    }
                }
            }
        }
        // Надпись справа выровнена по глазу, вертикально — по центру
        let right = self.eye_x + self.cell * 3;
        let center = (CY * cell) as usize;
        blit(&mut image, self.width, self.height, &self.text, right as i64 - self.text.width as i64, center as i64 - self.text.height as i64 / 2);
        if let Some(z) = &self.z {
            for i in 0..3 {
                let phase = (t * 0.35 + i as f64 / 3.0) % 1.0;
                let x = self.eye_x as f64 + (EYE_X0 + EYE_W - 6.0 + phase * 6.0) * cell;
                let y = (CY - EYE_HALF + 2.0 - phase * 8.0) * cell;
                blit(&mut image, self.width, self.height, z, x as i64 - z.width as i64 / 2, y as i64 - z.height as i64 / 2);
            }
        }
        image
    }
}

/// Чёрная обводка, затем заливка цветом надписи — поверх того, что уже нарисовано.
fn blit(image: &mut [u8], width: usize, height: usize, mask: &TextMask, left: i64, top: i64) {
    for y in 0..mask.height {
        for x in 0..mask.width {
            let (px, py) = (left + x as i64, top + y as i64);
            if px < 0 || py < 0 || px as usize >= width || py as usize >= height {
                continue;
            }
            let i = (py as usize * width + px as usize) * 4;
            for (alpha, color) in [(mask.stroke[y * mask.width + x], [0u8, 0, 0]), (mask.fill[y * mask.width + x], TEXT)] {
                if alpha == 0 {
                    continue;
                }
                let a = alpha as u32;
                let dst_a = image[i + 3] as u32;
                let out_a = a + dst_a * (255 - a) / 255;
                for c in 0..3 {
                    let blended = (color[c] as u32 * a + image[i + c] as u32 * dst_a * (255 - a) / 255) / out_a.max(1);
                    image[i + c] = blended.min(255) as u8;
                }
                image[i + 3] = out_a as u8;
            }
        }
    }
}

fn load_font() -> Result<FontVec> {
    let fonts = std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join("Fonts");
    for name in ["consolab.ttf", "consola.ttf", "courbd.ttf", "arialbd.ttf"] {
        if let Ok(data) = std::fs::read(fonts.join(name))
            && let Ok(font) = FontVec::try_from_vec(data)
        {
            return Ok(font);
        }
    }
    anyhow::bail!("не найден моноширинный шрифт Windows")
}

// ---------- окно Win32 ----------

struct Overlay {
    pet: Pet,
    hwnd: HWND,
    screen_dc: HDC,
    mem_dc: HDC,
    bits: *mut u8,
    pos: POINT,
}

thread_local! {
    static OVERLAY: RefCell<Option<Overlay>> = const { RefCell::new(None) };
}

const FRAME_TIMER: usize = 1;
const LIFETIME_TIMER: usize = 2;

fn show_frame(o: &mut Overlay) {
    let mut cursor = POINT::default();
    unsafe {
        let _ = GetCursorPos(&mut cursor);
    }
    let rgba = o.pet.frame((cursor.x, cursor.y), (o.pos.x, o.pos.y));
    // UpdateLayeredWindow ждёт BGRA с цветами, уже умноженными на прозрачность
    let bgra = unsafe { std::slice::from_raw_parts_mut(o.bits, rgba.len()) };
    for (src, dst) in rgba.chunks_exact(4).zip(bgra.chunks_exact_mut(4)) {
        let a = src[3] as u32;
        dst[0] = (src[2] as u32 * a / 255) as u8;
        dst[1] = (src[1] as u32 * a / 255) as u8;
        dst[2] = (src[0] as u32 * a / 255) as u8;
        dst[3] = src[3];
    }
    let size = SIZE { cx: o.pet.width as i32, cy: o.pet.height as i32 };
    let blend = BLENDFUNCTION { BlendOp: AC_SRC_OVER as u8, BlendFlags: 0, SourceConstantAlpha: 255, AlphaFormat: AC_SRC_ALPHA as u8 };
    unsafe {
        let _ = UpdateLayeredWindow(o.hwnd, Some(o.screen_dc), Some(&o.pos), Some(&size), Some(o.mem_dc), Some(&POINT::default()), COLORREF(0), Some(&blend), ULW_ALPHA);
        // Игры в окне без рамки тоже бывают «поверх всех» — поднимаемся обратно, не забирая фокус
        let _ = SetWindowPos(o.hwnd, Some(HWND_TOPMOST), 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE);
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TIMER if wparam.0 == LIFETIME_TIMER => {
            unsafe {
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(0)
        }
        WM_TIMER => {
            OVERLAY.with(|o| {
                if let Some(o) = o.borrow_mut().as_mut() {
                    show_frame(o);
                }
            });
            LRESULT(0)
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

pub fn main(mood: &str, text: &str, minutes: f64) -> i32 {
    match run(mood, text, minutes) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    }
}

fn run(mood: &str, text: &str, minutes: f64) -> Result<()> {
    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let dpi = GetDpiForSystem().max(96) as f64;
        let scale = ((6.0 * dpi / 96.0).round() as usize).max(4);
        let pet = Pet::new(mood, text, scale)?;
        let (width, height) = (pet.width as i32, pet.height as i32);
        let mut area = RECT::default();
        SystemParametersInfoW(SPI_GETWORKAREA, 0, Some(&mut area as *mut _ as *mut c_void), SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0))?;
        let pos = POINT { x: area.right - width - 8, y: area.bottom - height - 8 };

        let instance = GetModuleHandleW(None)?;
        let class = WNDCLASSW { lpfnWndProc: Some(wndproc), hInstance: instance.into(), lpszClassName: w!("DeepSecPet"), ..Default::default() };
        RegisterClassW(&class);
        let ex = WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST;
        let hwnd = CreateWindowExW(ex, w!("DeepSecPet"), w!("DeepSec"), WS_POPUP, pos.x, pos.y, width, height, None, None, Some(instance.into()), None)
            .context("окно глаза не создано")?;

        let screen_dc = GetDC(None);
        let mem_dc = CreateCompatibleDC(Some(screen_dc));
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits: *mut c_void = std::ptr::null_mut();
        let bitmap = CreateDIBSection(Some(mem_dc), &info, DIB_RGB_COLORS, &mut bits, None, 0)?;
        SelectObject(mem_dc, bitmap.into());

        let mut overlay = Overlay { pet, hwnd, screen_dc, mem_dc, bits: bits as *mut u8, pos };
        show_frame(&mut overlay);
        OVERLAY.with(|o| *o.borrow_mut() = Some(overlay));
        let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        SetTimer(Some(hwnd), FRAME_TIMER, 1000 / FPS, None);
        SetTimer(Some(hwnd), LIFETIME_TIMER, (minutes.min(MAX_MINUTES) * 60_000.0) as u32, None);
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eye_looks_toward_cursor_within_the_eye() {
        let (left, up) = gaze(-5000.0, -5000.0);
        assert!(-11.0 < left && left < -9.0 && -4.0 < up && up < -3.0);
        assert_eq!(gaze(0.0, 0.0), (0.0, 0.0));
        assert!(gaze(300.0, 0.0).0 > 0.0);
    }

    #[test]
    fn every_mood_draws_a_frame_with_the_iris_in_the_middle() {
        for mood in PET_MOODS {
            let mut pet = Pet::new(mood, "", 9).unwrap();
            let frame = pet.frame((0, 0), (0, 0));
            assert_eq!(frame.len(), pet.width * pet.height * 4);
            assert!(frame.chunks_exact(4).any(|p| p[3] == 255), "{mood}");
            if mood != "sleep" {
                // в центре глаза — зрачок или радужка (красное/тёмное), а не белок
                let (cx, cy) = (pet.eye_x + (CX * pet.cell as f64) as usize, (CY * pet.cell as f64) as usize);
                let i = (cy * pet.width + cx) * 4;
                assert!(frame[i] < 240 && frame[i + 3] == 255, "{mood}: {:?}", &frame[i..i + 4]);
            }
        }
        assert_eq!(Pet::new("watch", &"x".repeat(200), 4).unwrap().text.width, Pet::new("watch", &"x".repeat(60), 4).unwrap().text.width);
    }
}
