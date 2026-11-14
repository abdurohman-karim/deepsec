//! Окно DeepSec (меню «Пуск» → DeepSec): состояние агента и обновление с прогрессом прямо в окне
//! (как deepsec/window.py). Окно работает от пользователя и без прав администратора: обновляет агент
//! (SYSTEM), окно говорит с ним через локальный канал (control.rs). Без стандартной рамки Windows —
//! своя шапка: перетаскивание, свернуть, закрыть.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, RichText, Sense, Stroke, TextureHandle, Vec2};
use serde_json::Value;

use crate::{VERSION, brand, control};

const BG: Color32 = Color32::from_rgb(0x15, 0x16, 0x1a);
const PANEL: Color32 = Color32::from_rgb(0x0f, 0x10, 0x13);
const BORDER: Color32 = Color32::from_rgb(0x2a, 0x2b, 0x31);
const FG: Color32 = Color32::from_rgb(0xec, 0xe6, 0xd6);
const MUTED: Color32 = Color32::from_rgb(0x8a, 0x8f, 0x98);
const DIM: Color32 = Color32::from_rgb(0x5d, 0x61, 0x6b);
const ACCENT: Color32 = Color32::from_rgb(0xc0, 0x26, 0x2d);
const ACCENT_HOVER: Color32 = Color32::from_rgb(0x9e, 0x1d, 0x23);
const OK: Color32 = Color32::from_rgb(0x4c, 0xaf, 0x50);
const BUTTON: Color32 = Color32::from_rgb(0x26, 0x27, 0x2d);
const BUTTON_HOVER: Color32 = Color32::from_rgb(0x30, 0x32, 0x3a);
const POLL: Duration = Duration::from_millis(300);
const MB: f64 = 1024.0 * 1024.0;

/// Что показать по состоянию обновления в агенте: строка статуса, кнопка, полоса загрузки.
#[derive(Clone, Debug, PartialEq)]
pub struct View {
    pub status: String,
    pub color: Color32,
    pub button: String,
    /// Что делает кнопка: check | download | install; None — неактивна.
    pub action: Option<&'static str>,
    pub progress: Option<f32>,
    pub detail: String,
}

fn v(status: impl Into<String>, color: Color32, button: impl Into<String>, action: Option<&'static str>) -> View {
    View { status: status.into(), color, button: button.into(), action, progress: None, detail: String::new() }
}

pub fn view(snap: Option<&Value>) -> View {
    let Some(snap) = snap else { return v("Агент не отвечает — обновить через окно нельзя", ACCENT, "Обновить", None) };
    let state = snap["state"].as_str().unwrap_or("");
    let available = snap["available"].as_str().unwrap_or("");
    let new = if available.is_empty() { snap["latest"].as_str().unwrap_or("") } else { available };
    match state {
        "idle" | "checking" => v("Проверяю обновления…", DIM, "Проверяю…", None),
        "downloading" => {
            let (done, total) = (snap["done"].as_u64().unwrap_or(0) as f64, snap["total"].as_u64().unwrap_or(0) as f64);
            let share = if total > 0.0 { done / total } else { 0.0 };
            let detail = if total > 0.0 {
                format!("{:.0}% · {:.1} из {:.1} МБ", share * 100.0, done / MB, total / MB)
            } else {
                format!("{:.1} МБ", done / MB)
            };
            View { progress: Some(share as f32), detail, ..v(format!("Скачиваю версию {new}…"), FG, "Скачивание…", None) }
        }
        "ready" => View {
            progress: Some(1.0),
            detail: "100% · готово к установке".into(),
            ..v(format!("Версия {new} скачана, SHA-256 проверен"), OK, "Перезапустить и обновить", Some("install"))
        },
        "installing" => View { progress: Some(1.0), detail: "окно откроется снова".into(), ..v(format!("Устанавливаю {new}…"), FG, "Устанавливаю…", None) },
        "error" => {
            let error: String = format!("Ошибка: {}", snap["error"].as_str().unwrap_or("неизвестно")).chars().take(90).collect();
            v(error, ACCENT, "Повторить", Some("check"))
        }
        _ if !available.is_empty() => v(format!("Вышла версия {new}"), ACCENT, format!("Скачать {new}"), Some("download")),
        _ => v("Установлена последняя версия", OK, "Обновлений нет", None),
    }
}

struct App {
    updated_from: String,
    snap: Arc<Mutex<Option<Value>>>,
    busy: Arc<Mutex<bool>>,
    next_poll: Option<Instant>,
    close_at: Option<Instant>,
    logo: TextureHandle,
    mark: TextureHandle,
}

impl App {
    fn request(&mut self, ctx: &egui::Context, path: &'static str, post: bool) {
        let (snap, busy, ctx) = (self.snap.clone(), self.busy.clone(), ctx.clone());
        *busy.lock().unwrap() = true;
        std::thread::spawn(move || {
            *snap.lock().unwrap() = control::call(path, post, Duration::from_secs(60)).ok();
            *busy.lock().unwrap() = false;
            ctx.request_repaint();
        });
    }

    fn title_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let bar = ui.allocate_response(Vec2::new(ui.available_width(), 38.0), Sense::click_and_drag());
        ui.painter().rect_filled(bar.rect, CornerRadius::ZERO, PANEL);
        if bar.drag_started() {
            ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }
        let mut child = ui.new_child(egui::UiBuilder::new().max_rect(bar.rect.shrink2(Vec2::new(12.0, 0.0))));
        child.horizontal_centered(|ui| {
            ui.add(egui::Image::new(&self.mark).fit_to_exact_size(Vec2::splat(20.0)));
            ui.label(RichText::new("DeepSec").color(MUTED).size(13.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                for (text, hover, close) in [("✕", ACCENT, true), ("—", BUTTON_HOVER, false)] {
                    let (rect, response) = ui.allocate_exact_size(Vec2::new(46.0, 38.0), Sense::click());
                    let hovered = response.hovered();
                    if hovered {
                        ui.painter().rect_filled(rect, CornerRadius::ZERO, hover);
                    }
                    ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, text, FontId::proportional(14.0), if hovered { Color32::WHITE } else { MUTED });
                    if response.clicked() {
                        ctx.send_viewport_cmd(if close { egui::ViewportCommand::Close } else { egui::ViewportCommand::Minimized(true) });
                    }
                }
            });
        });
    }
}

fn flat_button(ui: &mut egui::Ui, text: &str, enabled: bool, primary: bool) -> bool {
    let font = FontId::new(14.0, if primary { FontFamily::Name("bold".into()) } else { FontFamily::Proportional });
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, Color32::WHITE);
    let size = galley.size() + Vec2::new(32.0, 16.0);
    let (rect, response) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    // У неактивной — серый фон и тусклый текст, чтобы не казалась нажимаемой
    let (fill, color) = match (enabled, primary, response.hovered()) {
        (false, _, _) => (BUTTON, DIM),
        (true, true, hover) => (if hover { ACCENT_HOVER } else { ACCENT }, Color32::WHITE),
        (true, false, hover) => (if hover { BUTTON_HOVER } else { BUTTON }, FG),
    };
    ui.painter().rect_filled(rect, CornerRadius::same(2), fill);
    ui.painter().galley_with_override_text_color(rect.center() - galley.size() / 2.0, galley, color);
    if enabled && response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    enabled && response.clicked()
}

fn status_row(ui: &mut egui::Ui, text: &str, color: Color32) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("●").color(color).size(13.0));
        ui.label(RichText::new(text).color(FG).size(14.0));
    });
}

impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &root.ctx().clone();
        let snap = self.snap.lock().unwrap().clone();
        let busy = *self.busy.lock().unwrap();
        let state = snap.as_ref().and_then(|s| s["state"].as_str()).unwrap_or("").to_string();
        // Пока агент качает или ставит — опрашиваем его; во время установки окно закроется само
        if !busy && matches!(state.as_str(), "checking" | "downloading") && self.next_poll.is_none_or(|t| Instant::now() >= t) {
            self.next_poll = Some(Instant::now() + POLL);
            self.request(ctx, "/update", false);
        }
        if state == "installing" && self.close_at.is_none() {
            // Установщик закроет все процессы DeepSec, а агент после перезапуска откроет окно снова
            self.close_at = Some(Instant::now() + Duration::from_millis(1500));
        }
        if self.close_at.is_some_and(|t| Instant::now() >= t) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        let view = if busy && snap.is_none() { v("Проверяю обновления…", DIM, "Проверяю…", None) } else { view(snap.as_ref()) };

        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG).stroke(Stroke::new(1.0, BORDER))).show(root, |ui| {
            ui.spacing_mut().item_spacing = Vec2::new(8.0, 4.0);
            self.title_bar(ui, ctx);
            if !self.updated_from.is_empty() {
                egui::Frame::new().fill(Color32::from_rgb(0x1d, 0x3a, 0x24)).inner_margin(egui::Margin::symmetric(24, 8)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!("✓  Обновлено: {} → {VERSION}. Настройки сохранены.", self.updated_from)).color(Color32::from_rgb(0xcf, 0xe9, 0xd3)).size(13.0));
                });
            }
            egui::Frame::new().inner_margin(egui::Margin { left: 24, right: 24, top: 18, bottom: 6 }).show(ui, |ui| {
                ui.horizontal_top(|ui| {
                    ui.add(egui::Image::new(&self.logo).fit_to_exact_size(Vec2::splat(112.0)));
                    ui.add_space(14.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("DeepSec Agent").color(FG).size(22.0).family(FontFamily::Name("bold".into())));
                        ui.label(RichText::new("Защита сессий Telegram Desktop").color(MUTED).size(13.0));
                        ui.add_space(8.0);
                        let running = snap.is_some();
                        status_row(ui, if running { "Агент работает" } else if busy { "Связываюсь с агентом…" } else { "Агент не запущен" },
                            if running { OK } else if busy { DIM } else { ACCENT });
                        let version = snap.as_ref().and_then(|s| s["version"].as_str()).unwrap_or(VERSION).to_string();
                        status_row(ui, &format!("Версия {version}"), MUTED);
                        status_row(ui, &view.status, view.color);
                        if let Some(progress) = view.progress {
                            ui.add_space(6.0);
                            let fill = if progress >= 1.0 { OK } else { ACCENT };
                            ui.add(egui::ProgressBar::new(progress).desired_height(8.0).fill(fill).corner_radius(CornerRadius::ZERO));
                            ui.label(RichText::new(&view.detail).color(MUTED).size(12.0));
                        }
                    });
                });
            });
            egui::Frame::new().inner_margin(egui::Margin { left: 24, right: 24, top: 8, bottom: 4 }).show(ui, |ui| {
                ui.horizontal(|ui| {
                    if flat_button(ui, &view.button, view.action.is_some() && !busy, true) {
                        match view.action {
                            Some("check") => self.request(ctx, "/update/check", true),
                            Some("download") => self.request(ctx, "/update/download", true),
                            Some("install") => self.request(ctx, "/update/install", true),
                            _ => {}
                        }
                    }
                    ui.add_space(4.0);
                    let can_check = !busy && !matches!(state.as_str(), "checking" | "downloading" | "installing" | "ready");
                    if flat_button(ui, "Проверить снова", can_check, false) {
                        self.request(ctx, "/update/check", true);
                    }
                });
                ui.add_space(8.0);
                ui.label(RichText::new("Адрес сервера, токен и ловушки при обновлении сохраняются.").color(DIM).size(12.0));
            });
        });
        if busy || self.close_at.is_some() || matches!(state.as_str(), "checking" | "downloading") {
            ctx.request_repaint_after(POLL);
        }
    }
}

fn fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    let dir = std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join("Fonts");
    let mut bold = Vec::new();
    for (name, file) in [("segoe", "segoeui.ttf"), ("segoe_bold", "segoeuib.ttf"), ("segoe_symbol", "seguisym.ttf")] {
        if let Ok(data) = std::fs::read(dir.join(file)) {
            fonts.font_data.insert(name.into(), Arc::new(FontData::from_owned(data)));
            match name {
                "segoe" => fonts.families.entry(FontFamily::Proportional).or_default().insert(0, name.into()),
                "segoe_bold" => bold.push(name.to_string()),
                _ => fonts.families.entry(FontFamily::Proportional).or_default().push(name.into()),
            }
        }
    }
    let mut bold_family = bold;
    bold_family.extend(fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default());
    fonts.families.insert(FontFamily::Name("bold".into()), bold_family);
    fonts
}

pub fn main(updated_from: &str) -> i32 {
    unsafe {
        // exe консольный: из меню «Пуск» без лишнего чёрного окна
        let _ = windows::Win32::System::Console::FreeConsole();
    }
    let icon = egui::IconData { rgba: brand::icon_image(256), width: 256, height: 256 };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("DeepSec")
            .with_decorations(false)
            .with_resizable(false)
            .with_inner_size([560.0, if updated_from.is_empty() { 296.0 } else { 332.0 }])
            .with_icon(Arc::new(icon))
            .with_app_id("DeepSec.Agent"),
        centered: true,
        ..Default::default()
    };
    let updated_from = updated_from.to_string();
    let result = eframe::run_native(
        "DeepSec",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_fonts(fonts());
            let texture = |name: &str, grid: usize, size: usize| {
                let rgba = brand::scale_nearest(&brand::logo(grid), grid, size);
                cc.egui_ctx.load_texture(name, egui::ColorImage::from_rgba_unmultiplied([size, size], &rgba), egui::TextureOptions::NEAREST)
            };
            let mut app = App {
                updated_from,
                snap: Arc::new(Mutex::new(None)),
                busy: Arc::new(Mutex::new(false)),
                next_poll: None,
                close_at: None,
                logo: texture("logo", 32, 224),
                mark: texture("mark", 16, 32),
            };
            app.request(&cc.egui_ctx, "/update/check", true);
            Ok(Box::new(app))
        }),
    );
    i32::from(result.is_err())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn view_for_each_update_state() {
        let snap = |state: &str, extra: Value| {
            let mut s = json!({"version": "0.7.0", "latest": "0.8.0", "available": "0.8.0", "done": 0, "total": 0, "error": ""});
            s["state"] = state.into();
            for (k, val) in extra.as_object().unwrap() {
                s[k] = val.clone();
            }
            s
        };
        assert!(view(None).action.is_none() && view(None).status.contains("не отвечает"));
        assert!(view(Some(&snap("checking", json!({})))).action.is_none());
        let available = view(Some(&snap("available", json!({}))));
        assert_eq!((available.action, available.button.as_str()), (Some("download"), "Скачать 0.8.0"));
        let half = view(Some(&snap("downloading", json!({"done": 10 * 1024 * 1024, "total": 20 * 1024 * 1024}))));
        assert_eq!((half.progress, half.detail.as_str()), (Some(0.5), "50% · 10.0 из 20.0 МБ"));
        let ready = view(Some(&snap("ready", json!({}))));
        assert!(ready.action == Some("install") && ready.button.contains("Перезапустить"));
        assert_eq!(view(Some(&snap("error", json!({"error": "нет сети"})))).action, Some("check"));
        let latest = view(Some(&snap("latest", json!({"available": "", "latest": "0.7.0"}))));
        assert_eq!((latest.action, latest.button.as_str()), (None, "Обновлений нет")); // неактивная — серая
    }
}
