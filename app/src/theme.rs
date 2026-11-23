//! Визуальная тема приложения: палитра, типографика, тени.
//!
//! Палитра повторяет референс Dark Slate UI: графитовый сайдбар, сланцевая
//! рабочая область, приподнятые карточки и электрический индиго-акцент.

use eframe::egui::{
    self, Color32, FontData, FontFamily, FontId, Rounding, Stroke, TextStyle, Vec2,
};
use std::sync::Arc;

// --- Поверхности ---------------------------------------------------------

pub const BG_WINDOW: Color32 = Color32::from_rgb(0x23, 0x25, 0x30);
pub const BG_TITLEBAR: Color32 = Color32::from_rgb(0x2A, 0x2C, 0x39);
pub const BG_WORKSPACE: Color32 = Color32::from_rgb(0x2B, 0x2D, 0x3A);
pub const BG_CARD: Color32 = Color32::from_rgb(0x35, 0x38, 0x49);
pub const BG_CARD_HOVER: Color32 = Color32::from_rgb(0x3B, 0x3E, 0x51);
pub const BG_SUNKEN: Color32 = Color32::from_rgb(0x2F, 0x31, 0x40);
pub const BG_PANEL: Color32 = Color32::from_rgb(0x30, 0x33, 0x41);
pub const BG_CHIP: Color32 = Color32::from_rgb(0x2E, 0x31, 0x42);
pub const BG_ROW_HOVER: Color32 = Color32::from_rgb(0x30, 0x33, 0x42);
pub const BG_ACTIVE_ROW: Color32 = Color32::from_rgb(0x2A, 0x2C, 0x38);

// --- Акцент и текст ------------------------------------------------------

pub const ACCENT: Color32 = Color32::from_rgb(0x4B, 0x6B, 0xFB);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0x5F, 0x7D, 0xFF);
pub const ACCENT_SOFT: Color32 = Color32::from_rgb(0x33, 0x3C, 0x66);

pub const TEXT: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xFF);
pub const TEXT_SOFT: Color32 = Color32::from_rgb(0xC6, 0xCA, 0xD8);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x8E, 0x92, 0xA4);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x6B, 0x6F, 0x82);

pub const DIVIDER: Color32 = Color32::from_rgb(0x3A, 0x3D, 0x4D);
pub const DIVIDER_SOFT: Color32 = Color32::from_rgb(0x32, 0x35, 0x44);

// --- Семантические цвета -------------------------------------------------

pub const GREEN: Color32 = Color32::from_rgb(0x3D, 0xD6, 0x8C);
pub const AMBER: Color32 = Color32::from_rgb(0xF2, 0xB8, 0x4B);
pub const RED: Color32 = Color32::from_rgb(0xE8, 0x5D, 0x5D);
pub const TEAL: Color32 = Color32::from_rgb(0x3E, 0xA9, 0xC9);
pub const PURPLE: Color32 = Color32::from_rgb(0x7A, 0x5A, 0xF8);
pub const PDF_RED: Color32 = Color32::from_rgb(0xE0, 0x4F, 0x5F);
pub const ZIP_YELLOW: Color32 = Color32::from_rgb(0xE3, 0xBE, 0x4E);

// --- Типографика ---------------------------------------------------------

const MEDIUM_FAMILY: &str = "ui-medium";

pub fn medium_family() -> FontFamily {
    FontFamily::Name(Arc::from(MEDIUM_FAMILY))
}

/// Полужирное начертание (Roboto Medium / Segoe UI Bold) для заголовков.
pub fn medium(size: f32) -> FontId {
    FontId::new(size, medium_family())
}

/// Обычное начертание (Roboto / Segoe UI) для основного текста.
pub fn regular(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}

pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

// --- Тени ----------------------------------------------------------------

/// Мягкая рассеянная тень для приподнятых карточек.
pub fn card_shadow() -> egui::epaint::Shadow {
    egui::epaint::Shadow {
        offset: Vec2::new(0.0, 10.0),
        blur: 28.0,
        spread: 0.0,
        color: Color32::from_black_alpha(70),
    }
}

/// Едва заметная тень для карточек внутри колонок.
pub fn soft_shadow() -> egui::epaint::Shadow {
    egui::epaint::Shadow {
        offset: Vec2::new(0.0, 6.0),
        blur: 18.0,
        spread: 0.0,
        color: Color32::from_black_alpha(45),
    }
}

/// Крупная тень для плавающей панели действий.
pub fn floating_shadow() -> egui::epaint::Shadow {
    egui::epaint::Shadow {
        offset: Vec2::new(0.0, 22.0),
        blur: 60.0,
        spread: 0.0,
        color: Color32::from_black_alpha(130),
    }
}

// --- Установка темы ------------------------------------------------------

/// Идемпотентная установка темы (вызывается каждый кадр, применяется один раз).
pub fn ensure(ctx: &egui::Context) {
    let id = egui::Id::new("cryptoline_theme_v1");
    if ctx.data(|d| d.get_temp::<bool>(id).unwrap_or(false)) {
        return;
    }
    ctx.data_mut(|d| d.insert_temp(id, true));
    install(ctx);
}

fn install(ctx: &egui::Context) {
    install_fonts(ctx);

    let mut style = (*ctx.style()).clone();

    style.text_styles = [
        (TextStyle::Heading, medium(22.0)),
        (TextStyle::Body, regular(14.0)),
        (TextStyle::Monospace, mono(12.0)),
        (TextStyle::Button, regular(14.0)),
        (TextStyle::Small, regular(12.0)),
    ]
    .into();

    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(12.0, 8.0);
    style.spacing.interact_size = Vec2::new(32.0, 32.0);
    style.spacing.scroll.bar_width = 7.0;
    style.spacing.scroll.bar_inner_margin = 4.0;
    style.spacing.scroll.floating = true;

    let mut v = egui::Visuals::dark();
    v.dark_mode = true;
    v.panel_fill = BG_WINDOW;
    v.window_fill = Color32::from_rgb(0x2E, 0x30, 0x3D);
    v.extreme_bg_color = BG_SUNKEN;
    v.faint_bg_color = Color32::from_rgb(0x2E, 0x30, 0x3C);
    v.code_bg_color = BG_SUNKEN;
    v.window_stroke = Stroke::new(1.0_f32, DIVIDER);
    v.window_rounding = Rounding::same(14.0);
    v.menu_rounding = Rounding::same(10.0);
    v.window_shadow = card_shadow();
    v.popup_shadow = soft_shadow();
    v.selection.bg_fill = Color32::from_rgb(0x3A, 0x4C, 0xA8);
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = AMBER;
    v.error_fg_color = RED;
    v.override_text_color = None;

    v.widgets.noninteractive.bg_fill = BG_CARD;
    v.widgets.noninteractive.weak_bg_fill = BG_CARD;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, DIVIDER_SOFT);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.noninteractive.rounding = Rounding::same(10.0);

    v.widgets.inactive.bg_fill = BG_SUNKEN;
    v.widgets.inactive.weak_bg_fill = BG_SUNKEN;
    v.widgets.inactive.bg_stroke = Stroke::NONE;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT_SOFT);
    v.widgets.inactive.rounding = Rounding::same(10.0);
    v.widgets.inactive.expansion = 0.0;

    v.widgets.hovered.bg_fill = BG_CARD_HOVER;
    v.widgets.hovered.weak_bg_fill = BG_CARD_HOVER;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(0x46, 0x4A, 0x5E));
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.hovered.rounding = Rounding::same(10.0);
    v.widgets.hovered.expansion = 0.0;

    v.widgets.active.bg_fill = ACCENT;
    v.widgets.active.weak_bg_fill = ACCENT;
    v.widgets.active.bg_stroke = Stroke::NONE;
    v.widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    v.widgets.active.rounding = Rounding::same(10.0);
    v.widgets.active.expansion = 0.0;

    v.widgets.open.bg_fill = BG_CARD_HOVER;
    v.widgets.open.weak_bg_fill = BG_CARD_HOVER;
    v.widgets.open.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(0x46, 0x4A, 0x5E));
    v.widgets.open.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.open.rounding = Rounding::same(10.0);

    style.visuals = v;
    ctx.set_style(style);
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Inter, если установлен, иначе Roboto (геометрический гротеск),
    // иначе Segoe UI. Все три покрывают кириллицу.
    let regular_candidates = [
        r"C:\Windows\Fonts\Inter-Regular.ttf",
        r"C:\Windows\Fonts\Inter.ttf",
        r"C:\Windows\Fonts\Roboto-Regular.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
    ];
    let medium_candidates = [
        r"C:\Windows\Fonts\Inter-SemiBold.ttf",
        r"C:\Windows\Fonts\Inter-Medium.ttf",
        r"C:\Windows\Fonts\Roboto-Medium.ttf",
        r"C:\Windows\Fonts\seguisb.ttf",
        r"C:\Windows\Fonts\segoeuib.ttf",
    ];

    if let Some(bytes) = regular_candidates
        .iter()
        .find_map(|p| std::fs::read(p).ok())
    {
        fonts
            .font_data
            .insert("ui".to_owned(), FontData::from_owned(bytes));
        if let Some(list) = fonts.families.get_mut(&FontFamily::Proportional) {
            list.insert(0, "ui".to_owned());
        }
    }

    let mut medium_list: Vec<String> = Vec::new();
    if let Some(bytes) = medium_candidates
        .iter()
        .find_map(|p| std::fs::read(p).ok())
    {
        fonts
            .font_data
            .insert(MEDIUM_FAMILY.to_owned(), FontData::from_owned(bytes));
        medium_list.push(MEDIUM_FAMILY.to_owned());
    }
    // Фолбэк на обычное начертание и эмодзи-шрифты egui.
    if let Some(list) = fonts.families.get(&FontFamily::Proportional) {
        medium_list.extend(list.iter().cloned());
    }
    fonts
        .families
        .insert(medium_family(), medium_list);

    ctx.set_fonts(fonts);
}
