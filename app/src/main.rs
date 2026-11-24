#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod icons;
mod report;
mod theme;
mod win;

use app::CryptoLineApp;
use eframe::egui;

/// Иконка приложения: RGBA 256×256, сгенерирована из assets/app_icon.png.
pub(crate) const ICON_RGBA: &[u8] = include_bytes!("../assets/app_icon_256.rgba");
pub(crate) const ICON_SIZE: u32 = 256;
/// Логотип для сайдбара: обрезанный по содержимому, RGBA 192×255.
pub(crate) const LOGO_RGBA: &[u8] = include_bytes!("../assets/app_logo.rgba");
pub(crate) const LOGO_W: u32 = 192;
pub(crate) const LOGO_H: u32 = 244;
/// Маска росчерка для анимации заставки: белая, RGBA 420×265.
pub(crate) const SIG_RGBA: &[u8] = include_bytes!("../assets/app_sig.rgba");
pub(crate) const SIG_W: u32 = 420;
pub(crate) const SIG_H: u32 = 265;

fn main() -> Result<(), eframe::Error> {
    // Пути к документам можно передать аргументами (например, «Открыть с помощью»).
    let paths: Vec<std::path::PathBuf> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .map(std::path::PathBuf::from)
        .collect();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1360.0, 860.0])
            .with_min_inner_size([1120.0, 700.0])
            .with_title("Просто Подпись")
            .with_decorations(false)
            .with_resizable(true)
            .with_icon(egui::IconData {
                rgba: ICON_RGBA.to_vec(),
                width: ICON_SIZE,
                height: ICON_SIZE,
            }),
        ..Default::default()
    };

    eframe::run_native(
        "prosto-podpis",
        options,
        Box::new(move |cc| {
            theme::ensure(&cc.egui_ctx);
            Box::new(CryptoLineApp::with_paths(paths))
        }),
    )
}
