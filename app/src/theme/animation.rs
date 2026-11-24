//! Анимации и микроинтеракции: длительности, сглаживание, цветовые переходы.
//!
//! Всё построено на встроенных `Context::animate_*`, которые сами просят
//! перерисовку только на время перехода и не грузят CPU в простое.

use eframe::egui::{self, Color32};

/// Быстрые отклики: наведение, мелкие подсказки.
pub const FAST: f32 = 0.16;
/// Обычные переходы: карточки, тумблеры, смена контента.
pub const NORMAL: f32 = 0.22;
/// Панели и крупные появления.
pub const PANEL: f32 = 0.30;

/// Глобальный флаг «меньше движения» (например, для слабых машин).
static REDUCED_MOTION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_reduced_motion(value: bool) {
    REDUCED_MOTION.store(value, std::sync::atomic::Ordering::Relaxed);
}

pub fn reduced_motion() -> bool {
    REDUCED_MOTION.load(std::sync::atomic::Ordering::Relaxed)
}

/// Длительность с учётом reduced_motion: при включённом флаге — 0.
pub fn dur(base: f32) -> f32 {
    if reduced_motion() {
        0.0
    } else {
        base
    }
}

/// Плавное торможение в конце — основная кривая интерфейса.
pub fn ease_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

/// Мягкое начало и конец — для панелей.
pub fn ease_in_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    if t < 0.5 {
        4.0 * t * t * t
    } else {
        1.0 - (-2.0 * t + 2.0).powi(3) / 2.0
    }
}

/// Интерполяция цвета по каналам (в 0.27 нет `lerp_to_gamma`).
pub fn lerp_color(from: Color32, to: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * t).round() as u8;
    Color32::from_rgba_unmultiplied(
        mix(from.r(), to.r()),
        mix(from.g(), to.g()),
        mix(from.b(), to.b()),
        mix(from.a(), to.a()),
    )
}

/// Цвет с масштабированной прозрачностью — для появления и исчезновения.
pub fn with_alpha(color: Color32, factor: f32) -> Color32 {
    color.gamma_multiply(factor.clamp(0.0, 1.0))
}

/// Анимированное булево с кривой ease-out.
pub fn animate_bool(ctx: &egui::Context, id: egui::Id, state: bool, base: f32) -> f32 {
    ease_out_cubic(ctx.animate_bool_with_time(id, state, dur(base)))
}

/// Анимированное значение с кривой ease-out.
pub fn animate_value(ctx: &egui::Context, id: egui::Id, target: f32, base: f32) -> f32 {
    ease_out_cubic(ctx.animate_value_with_time(id, target, dur(base)))
}
