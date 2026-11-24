//! Интерфейс «Просто подпись»: тёмная матовая тема, три колонки и плавающая
//! панель подписания.
//!
//! Логика подписи вынесена в CLI (`Podpis-cli.exe`), который лежит рядом
//! с GUI: закрытый ключ остаётся в контейнере КриптоПро CSP.

use eframe::egui::{
    self, Align, Align2, Color32, FontId, Layout, Margin, Pos2, Rect, Response, RichText,
    Rounding, Sense, Stroke, Ui, Vec2,
};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use crate::icons::{self, Icon};
use crate::report::ReportRow;
use crate::theme::{self, *};

/// Файлы больше 50 МБ подписываем только после подтверждения.
const LARGE_FILE_BYTES: u64 = 50 * 1024 * 1024;

/// Строгая проверка подписей — не больше 80 МБ на файл.
const VERIFY_MAX_BYTES: u64 = 80 * 1024 * 1024;

/// Размер кнопок на полосе заголовка.
const CAPTION_BUTTON_W: f32 = 46.0;
const CAPTION_BUTTON_H: f32 = 34.0;

/// Длительность заставки при запуске, секунды.
const SPLASH_LEN: f32 = 2.7;

// ---------------------------------------------------------------------------
// Модель данных
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Nav {
    Docs,
    Encrypt,
    Verify,
    Certs,
    Zip,
    Settings,
}

impl Nav {
    fn title(self) -> &'static str {
        match self {
            Nav::Docs => "Документы",
            Nav::Encrypt => "Шифрование",
            Nav::Verify => "Проверка ЭП",
            Nav::Certs => "Сертификаты",
            Nav::Zip => "Архив ZIP",
            Nav::Settings => "Настройки",
        }
    }

    fn icon(self) -> Icon {
        match self {
            Nav::Docs => Icon::Docs,
            Nav::Encrypt => Icon::Lock,
            Nav::Verify => Icon::BadgeCheck,
            Nav::Certs => Icon::Cert,
            Nav::Zip => Icon::Archive,
            Nav::Settings => Icon::Settings,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortMode {
    Recent,
    Name,
    Size,
}

impl SortMode {
    fn label(self) -> &'static str {
        match self {
            SortMode::Recent => "Недавние",
            SortMode::Name => "По имени",
            SortMode::Size => "По размеру",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SigFormat {
    Sig,
    P7s,
}

impl SigFormat {
    fn label(self) -> &'static str {
        match self {
            SigFormat::Sig => ".sig",
            SigFormat::P7s => ".p7s",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            SigFormat::Sig => "sig",
            SigFormat::P7s => "p7s",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SigEncoding {
    Base64,
    Der,
}

impl SigEncoding {
    fn label(self) -> &'static str {
        match self {
            SigEncoding::Base64 => "Base64",
            SigEncoding::Der => "DER",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Pdf,
    Xml,
    Docx,
    Txt,
    Other,
}

impl FileKind {
    fn from_name(name: &str) -> Self {
        match name
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "pdf" => FileKind::Pdf,
            "xml" => FileKind::Xml,
            "docx" | "doc" => FileKind::Docx,
            "txt" | "rtf" | "odt" => FileKind::Txt,
            _ => FileKind::Other,
        }
    }

    fn label(self) -> &'static str {
        match self {
            FileKind::Pdf => "PDF",
            FileKind::Xml => "XML",
            FileKind::Docx => "DOCX",
            FileKind::Txt => "TXT",
            FileKind::Other => "FILE",
        }
    }

    fn color(self) -> Color32 {
        match self {
            FileKind::Pdf => PDF_RED,
            FileKind::Xml => TEAL,
            FileKind::Docx => ACCENT,
            FileKind::Txt => Color32::from_rgb(0x7F, 0x8A, 0xA8),
            FileKind::Other => Color32::from_rgb(0x6E, 0x73, 0x8C),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileStatus {
    Pending,
    Signed,
    Encrypted,
}

impl FileStatus {
    fn label(self) -> &'static str {
        match self {
            FileStatus::Pending => "Ожидает ЭП",
            FileStatus::Signed => "Подписан",
            FileStatus::Encrypted => "Зашифрован",
        }
    }

    fn dot(self) -> Color32 {
        match self {
            FileStatus::Pending => AMBER,
            FileStatus::Signed => GREEN,
            FileStatus::Encrypted => ACCENT,
        }
    }
}

#[derive(Clone)]
struct SignatureInfo {
    subject: String,
    path: Option<PathBuf>,
    signed_at: String,
}

#[derive(Clone)]
struct FileEntry {
    path: PathBuf,
    name: String,
    size: u64,
    modified: String,
    kind: FileKind,
    status: FileStatus,
    signatures: Vec<SignatureInfo>,
    hash: Option<String>,
}

impl FileEntry {
    fn from_path(path: PathBuf) -> Option<Self> {
        let name = path.file_name()?.to_string_lossy().to_string();
        let meta = std::fs::metadata(&path).ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(|t| {
                let dt: chrono::DateTime<chrono::Local> = t.into();
                dt.format("%d.%m.%Y · %H:%M").to_string()
            })
            .unwrap_or_else(|| "—".to_string());
        let kind = FileKind::from_name(&name);
        let status = if name.to_ascii_lowercase().ends_with(".enc") {
            FileStatus::Encrypted
        } else {
            FileStatus::Pending
        };
        Some(Self {
            path,
            name,
            size,
            modified,
            kind,
            status,
            signatures: Vec::new(),
            hash: None,
        })
    }

    fn existing_signature(&self) -> Option<&PathBuf> {
        self.signatures.iter().find_map(|s| s.path.as_ref())
    }

    fn zip_path(&self) -> PathBuf {
        let stem = self
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("signatures");
        self.path
            .with_file_name(format!("{}_signatures.zip", stem))
    }
}

#[derive(Clone)]
struct CertEntry {
    subject: String,
    thumbprint: String,
    issuer: String,
    valid_until: String,
    /// `Some` для импортированного из файла сертификата.
    file_path: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Приложение
// ---------------------------------------------------------------------------

pub struct CryptoLineApp {
    files: Vec<FileEntry>,
    certificates: Vec<CertEntry>,
    message: String,

    active_nav: Nav,
    active_file: Option<usize>,
    selected_files: Vec<usize>,
    selected_certs: Vec<usize>,

    search: String,
    sort: SortMode,

    panel_open: bool,
    panel_collapsed: bool,
    sidebar_open: bool,
    detached: bool,
    separate_files: bool,
    pack_zip: bool,
    format: SigFormat,
    encoding: SigEncoding,

    hash_pending: Option<usize>,
    hash_rx: Option<mpsc::Receiver<(usize, String)>>,
    sign_rx: Option<mpsc::Receiver<SignOutcome>>,
    signing: Option<SignState>,

    verify_docs: Vec<PathBuf>,
    verify_sigs: Vec<PathBuf>,
    verify_items: Vec<VerifyItem>,

    confirm_delete: bool,
    titlebar_applied: bool,
    logo: Option<egui::TextureHandle>,
    sig_tex: Option<egui::TextureHandle>,
    splash_start: Option<f64>,
    splash_skip: bool,
    resize_drag: Option<ResizeDrag>,
    ctrl_a_was_down: bool,
    last_signed_dir: Option<PathBuf>,
    large_sign_files: Option<Vec<String>>,
    update_latest: Option<String>,
    update_url: Option<String>,
    update_error: Option<String>,
}

/// Пара «документ — подпись» на экране массовой проверки.
#[derive(Clone)]
struct VerifyItem {
    doc: Option<PathBuf>,
    sig: Option<PathBuf>,
    /// Сходство имён 0..1 (порог 0.8).
    score: f32,
    result: Option<(bool, String)>,
}

/// Сертификат, подготовленный к вызову CLI (путь к DER + владелец).
#[derive(Clone)]
struct PreparedCert {
    path: PathBuf,
    subject: String,
    imported: bool,
}

/// Результат подписания одного документа из фонового потока.
struct SignOutcome {
    idx: usize,
    created: Vec<(String, PathBuf)>,
    errors: Vec<String>,
}

/// Состояние идущего подписания — для анимации и прогресса.
struct SignState {
    total: usize,
    done: usize,
    started: f64,
    dirs: Vec<PathBuf>,
    errors: usize,
    temp_certs: Vec<PathBuf>,
}

#[derive(Clone, Copy)]
struct ResizeDrag {
    dir: egui::viewport::ResizeDirection,
    /// Геометрия окна и курсор в физических пикселях (Win32).
    start_rect: Option<(i32, i32, i32, i32)>,
    start_cursor: Option<(i32, i32)>,
}

impl Default for CryptoLineApp {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            certificates: Vec::new(),
            message: "Готово. Перетащите документы в окно или нажмите «+».".to_string(),
            active_nav: Nav::Docs,
            active_file: None,
            selected_files: Vec::new(),
            selected_certs: Vec::new(),
            search: String::new(),
            sort: SortMode::Recent,
            panel_open: true,
            panel_collapsed: false,
            sidebar_open: true,
            detached: true,
            separate_files: false,
            pack_zip: false,
            format: SigFormat::Sig,
            encoding: SigEncoding::Base64,
            hash_pending: None,
            hash_rx: None,
            sign_rx: None,
            signing: None,
            verify_docs: Vec::new(),
            verify_sigs: Vec::new(),
            verify_items: Vec::new(),
            confirm_delete: false,
            titlebar_applied: false,
            logo: None,
            sig_tex: None,
            splash_start: None,
            splash_skip: false,
            resize_drag: None,
            ctrl_a_was_down: false,
            last_signed_dir: None,
            large_sign_files: None,
            update_latest: None,
            update_url: None,
            update_error: None,
        }
    }
}

impl CryptoLineApp {
    /// Открытие с файлами из командной строки: подписи уходят в раздел
    /// проверки, документы — в очередь подписи (или в проверку, если есть .sig).
    pub fn with_paths(paths: Vec<PathBuf>) -> Self {
        let mut app = Self::default();
        let has_signature = paths.iter().any(|path| is_signature_path(path));

        if has_signature {
            for path in paths {
                if !path.is_file() {
                    continue;
                }
                if is_signature_path(&path) {
                    if !app.verify_sigs.contains(&path) {
                        app.verify_sigs.push(path);
                    }
                } else if !app.verify_docs.contains(&path) {
                    app.verify_docs.push(path);
                }
            }
            app.rebuild_verify_items();
            app.active_nav = Nav::Verify;
        } else {
            for path in paths {
                if path.is_file() {
                    app.push_file(path);
                }
            }
        }

        app
    }
}

impl eframe::App for CryptoLineApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        theme::ensure(ctx);
        self.handle_shortcuts(ctx);
        if !self.titlebar_applied {
            #[cfg(windows)]
            {
                use raw_window_handle::{HasWindowHandle, RawWindowHandle};
                if let Ok(handle) = frame.window_handle() {
                    if let RawWindowHandle::Win32(w) = handle.as_raw() {
                        crate::win::set_handle(w.hwnd.get());
                    }
                }
            }
            self.titlebar_applied = crate::win::enable_dark_titlebar();
        }
        self.poll_hash();
        self.poll_signing(ctx);
        self.handle_dropped(ctx);

        // Заставка: пока она видна, остальной интерфейс не рисуем и не опрашиваем.
        if !self.splash_skip {
            let now = ctx.input(|i| i.time);
            let start = *self.splash_start.get_or_insert(now);
            let t = (now - start) as f32;
            if t < SPLASH_LEN {
                if ctx.input(|i| i.pointer.any_click() || i.key_pressed(egui::Key::Escape)) {
                    self.splash_skip = true;
                } else {
                    self.draw_splash(ctx, t);
                    return;
                }
            }
        }

        if self.hash_pending.is_some() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        // Заголовок окна — отдельной узкой полосой, как в мессенджерах.
        egui::TopBottomPanel::top("titlebar")
            .exact_height(34.0)
            .frame(
                egui::Frame::none()
                    .fill(BG_TITLEBAR)
                    .inner_margin(Margin {
                        left: 10.0,
                        right: 0.0,
                        top: 0.0,
                        bottom: 0.0,
                    }),
            )
            .show(ctx, |ui| self.title_bar(ui));

        // Сайдбар — на всю высоту под заголовком.
        if self.sidebar_open {
            egui::SidePanel::left("sidebar")
                .exact_width(212.0)
                .resizable(false)
                .frame(
                    egui::Frame::none()
                        .fill(BG_WINDOW)
                        .inner_margin(Margin {
                            left: 0.0,
                            right: 14.0,
                            top: 14.0,
                            bottom: 14.0,
                        }),
                )
                .show(ctx, |ui| self.sidebar(ui));
        }

        egui::TopBottomPanel::top("topbar")
            .exact_height(60.0)
            .frame(
                egui::Frame::none()
                    .fill(BG_WINDOW)
                    .inner_margin(Margin {
                        left: 18.0,
                        right: 20.0,
                        top: 12.0,
                        bottom: 10.0,
                    }),
            )
            .show(ctx, |ui| self.topbar(ui));

        if self.active_nav == Nav::Docs {
            egui::SidePanel::right("inspector")
                .exact_width(374.0)
                .resizable(false)
                .frame(
                    egui::Frame::none()
                        .fill(BG_WORKSPACE)
                        .inner_margin(Margin {
                            left: 20.0,
                            right: 20.0,
                            top: 8.0,
                            bottom: 16.0,
                        }),
                )
                .show(ctx, |ui| self.inspector(ui));
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG_WORKSPACE)
                    .inner_margin(Margin {
                        left: 24.0,
                        right: 20.0,
                        top: 8.0,
                        bottom: 14.0,
                    }),
            )
            .show(ctx, |ui| match self.active_nav {
                Nav::Docs => self.docs_screen(ui),
                Nav::Certs => self.certs_screen(ui),
                Nav::Verify => self.verify_screen(ui),
                Nav::Zip => self.zip_screen(ui),
                Nav::Settings => self.settings_screen(ui),
                Nav::Encrypt => self.encrypt_screen(ui),
            });

        if self.active_nav == Nav::Docs {
            self.floating_panel(ctx);
        }
        self.signing_overlay(ctx);
        self.confirm_delete_dialog(ctx);
        self.large_sign_dialog(ctx);
        self.drop_overlay(ctx);
        self.resize_borders(ctx);
    }
}

// ---------------------------------------------------------------------------
// Сайдбар
// ---------------------------------------------------------------------------

impl CryptoLineApp {
    /// Анимированный логотип-заставка: контур листа → росчерк → строки → пульс.
    fn draw_splash(&mut self, ctx: &egui::Context, t: f32) {
        let fade = ((SPLASH_LEN - t) / 0.45).clamp(0.0, 1.0);
        let screen = ctx.screen_rect();
        let layer = egui::LayerId::new(egui::Order::Foreground, egui::Id::new("splash"));
        let p = ctx.layer_painter(layer);
        p.rect_filled(screen, 0.0, fade_col(BG_WINDOW, fade));

        // лёгкий импульс на этапе подтверждения
        let pulse = if (1.4..1.75).contains(&t) {
            1.0 + 0.030 * (((t - 1.4) / 0.35) * std::f32::consts::PI).sin()
        } else {
            1.0
        };
        let page_h = 240.0 * pulse;
        let page_w = page_h * 0.623;
        let page = Rect::from_center_size(
            screen.center() + Vec2::new(0.0, -6.0),
            Vec2::new(page_w, page_h),
        );

        // 1. контур листа по часовой стрелке
        let fp = (t / 0.4).clamp(0.0, 1.0);
        if fp > 0.0 {
            let pts = rounded_rect_path(page, page_w * 0.095);
            let total: f32 = pts.windows(2).map(|w| w[0].distance(w[1])).sum();
            let mut acc = 0.0f32;
            let mut out: Vec<Pos2> = Vec::with_capacity(pts.len());
            for w in pts.windows(2) {
                let seg = w[0].distance(w[1]);
                if acc + seg >= total * fp {
                    let k = ((total * fp - acc) / seg.max(1e-4)).clamp(0.0, 1.0);
                    out.push(w[0]);
                    out.push(Pos2::new(
                        w[0].x + (w[1].x - w[0].x) * k,
                        w[0].y + (w[1].y - w[0].y) * k,
                    ));
                    break;
                }
                out.push(w[0]);
                acc += seg;
            }
            if out.len() > 1 {
                p.add(egui::Shape::line(
                    out,
                    Stroke::new(page_w * 0.075, fade_col(ACCENT, fade)),
                ));
            }
        }

        // 2. росчерк: мягкая волна слева направо
        if t > 0.4 {
            let tex = self
                .sig_tex
                .get_or_insert_with(|| {
                    ctx.load_texture(
                        "app_sig",
                        egui::ColorImage::from_rgba_unmultiplied(
                            [crate::SIG_W as usize, crate::SIG_H as usize],
                            crate::SIG_RGBA,
                        ),
                        egui::TextureOptions::LINEAR,
                    )
                })
                .clone();
            let sp = ((t - 0.4) / 0.7).clamp(0.0, 1.0);
            let sig_rect = Rect::from_min_max(
                Pos2::new(
                    page.left() + page.width() * 0.164,
                    page.top() + page.height() * 0.285,
                ),
                Pos2::new(
                    page.left() + page.width() * 1.21,
                    page.top() + page.height() * 0.695,
                ),
            );
            let steps = 56;
            for i in 0..steps {
                let f0 = i as f32 / steps as f32;
                let f1 = (i + 1) as f32 / steps as f32;
                let a = ((sp * 1.15 - f0) / 0.14).clamp(0.0, 1.0) * fade;
                if a <= 0.004 {
                    continue;
                }
                let x0 = sig_rect.left() + sig_rect.width() * f0;
                let x1 = sig_rect.left() + sig_rect.width() * f1;
                p.image(
                    tex.id(),
                    Rect::from_min_max(
                        Pos2::new(x0, sig_rect.top()),
                        Pos2::new(x1, sig_rect.bottom()),
                    ),
                    Rect::from_min_max(Pos2::new(f0, 0.0), Pos2::new(f1, 1.0)),
                    Color32::from_white_alpha((a * 255.0) as u8),
                );
            }
        }

        // 3. строки документа
        if t > 1.1 {
            let a = ((t - 1.1) / 0.3).clamp(0.0, 1.0) * fade;
            let lh = page.height() * 0.028;
            for (x0, x1, y) in [(0.151, 0.840, 0.776), (0.151, 0.670, 0.851)] {
                let r = Rect::from_min_max(
                    Pos2::new(
                        page.left() + page.width() * x0,
                        page.top() + page.height() * y,
                    ),
                    Pos2::new(
                        page.left() + page.width() * x1,
                        page.top() + page.height() * y + lh,
                    ),
                );
                p.rect_filled(r, lh / 2.0, fade_col(TEXT_MUTED, a));
            }
        }

        ctx.request_repaint();
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        // Область логотипа можно тянуть — окно без системного заголовка.
        let drag_rect = Rect::from_min_size(
            ui.min_rect().min,
            Vec2::new(ui.available_width(), 64.0),
        );
        let sidebar_drag = ui.interact(
            drag_rect,
            egui::Id::new("sidebar_drag"),
            Sense::click_and_drag(),
        );
        if sidebar_drag.drag_started() {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }

        ui.horizontal(|ui| {
            ui.add_space(18.0);
            let texture = self.logo.get_or_insert_with(|| {
                ui.ctx().load_texture(
                    "app_logo",
                    egui::ColorImage::from_rgba_unmultiplied(
                        [crate::LOGO_W as usize, crate::LOGO_H as usize],
                        crate::LOGO_RGBA,
                    ),
                    egui::TextureOptions::LINEAR,
                )
            });
            // Логотип — вертикальный лист: высота фиксирована, ширина по пропорции.
            let logo_h = 36.0;
            let logo_w = logo_h * crate::LOGO_W as f32 / crate::LOGO_H as f32;
            let (rect, logo_resp) =
                ui.allocate_exact_size(Vec2::new(logo_w + 2.0, 44.0), Sense::hover());
            let hover = ui
                .ctx()
                .animate_bool_with_time(egui::Id::new("logo_hover"), logo_resp.hovered(), 0.2);
            let scale = 1.0 + 0.04 * hover;
            let logo_rect = Rect::from_center_size(
                rect.center(),
                Vec2::new(logo_w * scale, logo_h * scale),
            );
            ui.painter().image(
                texture.id(),
                logo_rect,
                Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                Color32::WHITE,
            );
            ui.add_space(11.0);
            ui.label(
                RichText::new("Просто Подпись")
                    .font(theme::medium(15.5))
                    .color(TEXT),
            );
        });

        ui.add_space(26.0);

        let navs = [
            Nav::Docs,
            Nav::Encrypt,
            Nav::Verify,
            Nav::Certs,
            Nav::Zip,
            Nav::Settings,
        ];
        let nav_left = ui.min_rect().left();
        let row_height = 40.0 + ui.spacing().item_spacing.y;
        let start_y = ui.cursor().min.y + 20.0;
        let active_index = navs.iter().position(|n| *n == self.active_nav).unwrap_or(0);
        let target_y = start_y + active_index as f32 * row_height;
        let indicator_y = ui.ctx().animate_value_with_time(
            egui::Id::new("nav_indicator"),
            target_y,
            0.24,
        );

        for (index, nav) in navs.into_iter().enumerate() {
            self.nav_item(ui, nav, index);
        }

        // Белый индикатор активного раздела плавно переезжает между пунктами.
        let p = ui.painter();
        p.rect_filled(
            Rect::from_center_size(
                Pos2::new(nav_left + 2.5, indicator_y),
                Vec2::new(3.0, 18.0),
            ),
            Rounding::same(2.0),
            Color32::WHITE,
        );
        p.rect_filled(
            Rect::from_center_size(
                Pos2::new(nav_left + 14.5, indicator_y),
                Vec2::new(8.0, 2.5),
            ),
            Rounding::same(1.5),
            Color32::WHITE,
        );

        ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(
                    RichText::new(format!(
                        "v{} · ГОСТ Р 34.10-2012",
                        env!("CARGO_PKG_VERSION")
                    ))
                    .font(theme::regular(10.5))
                    .color(TEXT_DIM),
                );
            });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(
                    RichText::new("КриптоПро CSP")
                        .font(theme::regular(11.5))
                        .color(TEXT_MUTED),
                );
                ui.add_space(4.0);
                let (r, _) = ui.allocate_exact_size(Vec2::splat(7.0), Sense::hover());
                ui.painter().circle_filled(r.center(), 3.5, GREEN);
            });
        });
    }

    fn nav_item(&mut self, ui: &mut Ui, nav: Nav, index: usize) {
        let active = self.active_nav == nav;
        let (rect, resp) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), 40.0), Sense::click());

        // Плавные переходы цвета текста, иконки и подсветки строки.
        let t = ui
            .ctx()
            .animate_bool_with_time(egui::Id::new(("nav_anim", index)), active, 0.2);
        let hover_t = ui
            .ctx()
            .animate_bool_with_time(egui::Id::new(("nav_hover", index)), resp.hovered() && !active, 0.15);

        let p = ui.painter();
        if hover_t > 0.01 {
            p.rect_filled(rect, Rounding::same(9.0), fade_col(BG_ACTIVE_ROW, hover_t));
        }

        let icon_rect = Rect::from_center_size(
            Pos2::new(rect.left() + 32.0, rect.center().y),
            Vec2::splat(17.0),
        );
        icons::paint(
            p,
            icon_rect,
            nav.icon(),
            lerp_color(TEXT_MUTED, ACCENT, t),
            1.6,
        );
        p.text(
            Pos2::new(rect.left() + 50.0, rect.center().y),
            Align2::LEFT_CENTER,
            nav.title(),
            if active {
                theme::medium(14.5)
            } else {
                theme::regular(14.0)
            },
            lerp_color(TEXT_MUTED, TEXT, t),
        );

        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if resp.clicked() {
            self.active_nav = nav;
        }
    }

    // -----------------------------------------------------------------------
    // Верхняя панель
    // -----------------------------------------------------------------------

    /// Полоса заголовка: перетаскивание окна и кнопки управления.
    fn title_bar(&mut self, ui: &mut Ui) {
        let strip = ui.max_rect();

        // Тонкая линия-разделитель под полосой.
        ui.painter().hline(
            0.0..=ui.ctx().screen_rect().width(),
            strip.bottom() - 0.5,
            Stroke::new(1.0, DIVIDER_SOFT),
        );

        let controls_w = CAPTION_BUTTON_W * 3.0;
        let drag_rect = Rect::from_min_max(
            strip.min,
            Pos2::new((strip.max.x - controls_w).max(strip.min.x), strip.max.y),
        );
        let drag = ui.interact(
            drag_rect,
            egui::Id::new("titlebar_drag"),
            Sense::click_and_drag(),
        );
        if drag.double_clicked() {
            let maximized = ui.ctx().input(|i| i.viewport().maximized.unwrap_or(false));
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
        } else if drag.drag_started() {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }

        let maximized = ui.ctx().input(|i| i.viewport().maximized.unwrap_or(false));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 0.0;

            if caption_button(ui, Icon::Close, true)
                .on_hover_text("Закрыть")
                .clicked()
            {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Close);
            }

            if caption_button(
                ui,
                if maximized {
                    Icon::Restore
                } else {
                    Icon::Maximize
                },
                false,
            )
            .on_hover_text(if maximized { "Восстановить" } else { "Развернуть" })
            .clicked()
            {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
            }

            if caption_button(ui, Icon::Minus, false)
                .on_hover_text("Свернуть")
                .clicked()
            {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }
        });
    }

    fn topbar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if menu_button(ui, self.sidebar_open)
                .on_hover_text("Свернуть или показать меню")
                .clicked()
            {
                self.sidebar_open = !self.sidebar_open;
            }
            ui.add_space(12.0);

            if self.active_nav != Nav::Docs {
                ui.label(
                    RichText::new(self.active_nav.title())
                        .font(theme::medium(16.0))
                        .color(TEXT_MUTED),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    self.token_profile(ui);
                });
                return;
            }

            let search_w = (ui.available_width() - 374.0 - 24.0).clamp(160.0, 480.0);
            ui.allocate_ui_with_layout(
                Vec2::new(search_w, 38.0),
                Layout::left_to_right(Align::Center),
                |ui| self.search_box(ui),
            );

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                self.token_profile(ui);
                ui.add_space(10.0);

                let r = icon_button(ui, Icon::Pen, 34.0).on_hover_text("Открыть панель подписания");
                if r.clicked() {
                    self.panel_open = true;
                    self.panel_collapsed = false;
                }
                let r = icon_button(ui, Icon::Download, 34.0).on_hover_text("Сохранить копию");
                if r.clicked() {
                    self.export_active();
                }
                let r = icon_button(ui, Icon::Trash, 34.0).on_hover_text("Удалить подпись");
                if r.clicked() {
                    self.delete_signature();
                }
                let r = icon_button(ui, Icon::BadgeCheck, 34.0).on_hover_text("Проверить подпись");
                if r.clicked() {
                    self.verify_active();
                }
            });
        });
    }

    fn search_box(&mut self, ui: &mut Ui) {
        egui::Frame::none()
            .fill(BG_SUNKEN)
            .rounding(Rounding::same(12.0))
            .inner_margin(Margin {
                left: 14.0,
                right: 12.0,
                top: 10.0,
                bottom: 10.0,
            })
            .show(ui, |ui| {
                ui.set_width(ui.available_width() - 26.0);
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                    icons::paint(ui.painter(), r, Icon::Search, TEXT_MUTED, 1.5);
                    ui.add_space(7.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .id(egui::Id::new("file_search"))
                            .frame(false)
                            .hint_text(
                                RichText::new("Поиск")
                                    .font(theme::regular(13.5))
                                    .color(TEXT_DIM),
                            )
                            .text_color(TEXT)
                            .desired_width(f32::INFINITY)
                            .margin(Margin::ZERO),
                    );
                });
            });
    }

    fn token_profile(&mut self, ui: &mut Ui) {
        ui.allocate_ui_with_layout(
            Vec2::new(204.0, 38.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::splat(34.0), Sense::hover());
                let p = ui.painter();
                p.rect_filled(r, Rounding::same(10.0), ACCENT_SOFT);
                icons::paint(p, r.shrink(9.0), Icon::Cert, ACCENT, 1.7);
                p.circle_filled(
                    Pos2::new(r.right() - 4.0, r.bottom() - 4.0),
                    5.0,
                    BG_WINDOW,
                );
                p.circle_filled(
                    Pos2::new(r.right() - 4.0, r.bottom() - 4.0),
                    3.2,
                    GREEN,
                );
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.add_space(1.0);
                    ui.label(
                        RichText::new("КриптоПро CSP")
                            .font(theme::medium(13.0))
                            .color(TEXT),
                    );
                    ui.label(
                        RichText::new("Токен / сертификат")
                            .font(theme::regular(11.0))
                            .color(TEXT_MUTED),
                    );
                });
            },
        );
    }

    // -----------------------------------------------------------------------
    // Центральная колонка: очередь документов
    // -----------------------------------------------------------------------

    /// Анимация идущего подписания поверх всего окна.
    fn signing_overlay(&mut self, ctx: &egui::Context) {
        let Some(state) = &self.signing else {
            return;
        };
        let done = state.done;
        let total = state.total.max(1);
        let started = state.started as f32;

        let area = ctx.screen_rect();
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Middle,
            egui::Id::new("signing_modal"),
        ));
        let p = &painter;
        p.rect_filled(area, 0.0, Color32::from_black_alpha(96));

        let card = Rect::from_center_size(area.center(), Vec2::new(372.0, 148.0));
        p.add(egui::Shape::Mesh(
            theme::floating_shadow().tessellate(card, Rounding::same(18.0)),
        ));
        p.rect_filled(card, Rounding::same(18.0), BG_PANEL);

        // Мини-лист с прорисовывающимся росчерком.
        let page = Rect::from_min_size(
            card.min + Vec2::new(26.0, 36.0),
            Vec2::new(48.0, 70.0),
        );
        p.rect_filled(page, Rounding::same(9.0), BG_WINDOW);
        p.rect_stroke(page, Rounding::same(9.0), Stroke::new(2.4, ACCENT));

        let now = ctx.input(|i| i.time) as f32;
        let phase = if started > 0.0 {
            (((now - started) / 1.6) % 1.0).clamp(0.0, 1.0)
        } else {
            0.0
        };
        if let Some(tex) = &self.sig_tex {
            let sig_rect = Rect::from_min_max(
                Pos2::new(page.left() + page.width() * 0.02, page.top() + page.height() * 0.28),
                Pos2::new(page.left() + page.width() * 1.30, page.top() + page.height() * 0.74),
            );
            let steps = 28;
            for i in 0..steps {
                let f0 = i as f32 / steps as f32;
                let f1 = (i + 1) as f32 / steps as f32;
                let a = ((phase * 1.25 - f0) / 0.18).clamp(0.0, 1.0);
                if a <= 0.01 {
                    continue;
                }
                let x0 = sig_rect.left() + sig_rect.width() * f0;
                let x1 = sig_rect.left() + sig_rect.width() * f1;
                p.image(
                    tex.id(),
                    Rect::from_min_max(
                        Pos2::new(x0, sig_rect.top()),
                        Pos2::new(x1, sig_rect.bottom()),
                    ),
                    Rect::from_min_max(Pos2::new(f0, 0.0), Pos2::new(f1, 1.0)),
                    Color32::from_white_alpha((a * 255.0) as u8),
                );
            }
        }

        let text_x = page.right() + 22.0;
        p.text(
            Pos2::new(text_x, card.top() + 44.0),
            Align2::LEFT_CENTER,
            "Подписание документа",
            theme::medium(16.0),
            TEXT,
        );
        p.text(
            Pos2::new(text_x, card.top() + 66.0),
            Align2::LEFT_CENTER,
            format!("{} из {}", done.min(total), total),
            theme::regular(12.5),
            TEXT_MUTED,
        );

        // Полоса прогресса.
        let bar = Rect::from_min_size(
            Pos2::new(text_x, card.bottom() - 48.0),
            Vec2::new(card.right() - text_x - 26.0, 8.0),
        );
        p.rect_filled(bar, Rounding::same(4.0), Color32::from_rgb(0x1E, 0x21, 0x2C));
        let progress = (done as f32 / total as f32).clamp(0.0, 1.0);
        if progress > 0.0 {
            p.rect_filled(
                Rect::from_min_size(bar.min, Vec2::new(bar.width() * progress, bar.height())),
                Rounding::same(4.0),
                ACCENT,
            );
        }

        ctx.request_repaint_after(Duration::from_millis(33));
    }

    fn docs_screen(&mut self, ui: &mut Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Документы")
                    .font(theme::medium(25.0))
                    .color(TEXT),
            );
            ui.add_space(4.0);
            count_badge(ui, self.files.len());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if round_add_button(ui, 42.0).clicked() {
                    self.add_files();
                }
            });
        });

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            sort_combo(ui, &mut self.sort);
            if !self.selected_files.is_empty() {
                ui.add_space(10.0);
                ui.label(
                    RichText::new(format!(
                        "выбрано {} · Ctrl+клик — несколько · Ctrl+A — все",
                        self.selected_files.len()
                    ))
                    .font(theme::regular(11.5))
                    .color(TEXT_DIM),
                );
            }
        });

        ui.add_space(10.0);

        let footer = 30.0;
        let list_h = (ui.available_height() - footer).max(120.0);
        egui::ScrollArea::vertical()
            .max_height(list_h)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.files.is_empty() {
                    self.empty_queue(ui);
                } else {
                    let indices = self.display_indices();
                    if indices.is_empty() {
                        ui.add_space(30.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                RichText::new("Ничего не найдено")
                                    .font(theme::regular(14.0))
                                    .color(TEXT_MUTED),
                            );
                        });
                    }
                    for idx in indices {
                        self.file_card(ui, idx);
                    }
                    ui.add_space(6.0);
                }
            });

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
            ui.painter().circle_filled(r.center(), 3.0, ACCENT);
            ui.add_space(2.0);
            ui.label(
                RichText::new(&self.message)
                    .font(theme::regular(12.0))
                    .color(TEXT_MUTED),
            );
            if let Some(dir) = self.last_signed_dir.clone() {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if folder_button(ui).clicked() {
                        open_in_explorer(&dir);
                    }
                });
            }
        });
    }

    fn display_indices(&self) -> Vec<usize> {
        let q = self.search.trim().to_lowercase();
        let mut v: Vec<usize> = self
            .files
            .iter()
            .enumerate()
            .filter(|(_, f)| q.is_empty() || f.name.to_lowercase().contains(&q))
            .map(|(i, _)| i)
            .collect();
        match self.sort {
            SortMode::Recent => {}
            SortMode::Name => v.sort_by(|a, b| {
                self.files[*a]
                    .name
                    .to_lowercase()
                    .cmp(&self.files[*b].name.to_lowercase())
            }),
            SortMode::Size => v.sort_by(|a, b| self.files[*b].size.cmp(&self.files[*a].size)),
        }
        v
    }

    fn empty_queue(&mut self, ui: &mut Ui) {
        ui.add_space(50.0);
        ui.vertical_centered(|ui| {
            let (r, _) = ui.allocate_exact_size(Vec2::splat(76.0), Sense::hover());
            let p = ui.painter();
            p.circle_filled(r.center(), 38.0, BG_CARD);
            icons::paint(
                p,
                Rect::from_center_size(r.center(), Vec2::splat(30.0)),
                Icon::File,
                TEXT_MUTED,
                1.6,
            );
            ui.add_space(14.0);
            ui.label(
                RichText::new("Пока нет документов")
                    .font(theme::medium(16.0))
                    .color(TEXT_SOFT),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Перетащите файлы сюда или нажмите «+»")
                    .font(theme::regular(13.0))
                    .color(TEXT_MUTED),
            );
        });
    }

    fn file_card(&mut self, ui: &mut Ui, idx: usize) {
        let width = ui.available_width();
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 86.0), Sense::click());
        if !ui.is_rect_visible(rect) {
            return;
        }

        let active = self.active_file == Some(idx);
        let hovered = resp.hovered();
        let selected = self.selected_files.contains(&idx);

        // Плавный подъём выбранной карточки: фон, смещение и тень.
        let lift = ui
            .ctx()
            .animate_bool_with_time(egui::Id::new(("card_lift", idx)), active, 0.2);
        let hover_t = ui
            .ctx()
            .animate_bool_with_time(egui::Id::new(("card_hover", idx)), hovered && !active, 0.15);
        let offset = -1.6 * lift;
        let card = Rect::from_min_max(
            rect.min + Vec2::new(0.0, 2.0 + offset),
            rect.max - Vec2::new(0.0, 2.0 - offset),
        );

        let p = ui.painter();
        let fill_t = lift.max(hover_t);
        if fill_t > 0.01 {
            let base = if lift > 0.01 { BG_CARD } else { BG_ROW_HOVER };
            p.rect_filled(card, Rounding::same(14.0), fade_col(base, fill_t));
        }
        if lift > 0.02 {
            let shadow = theme::card_shadow().tessellate(card, Rounding::same(14.0));
            p.add(egui::Shape::Mesh(shadow));
        }
        if selected && !active {
            p.rect_stroke(
                card.shrink(0.5),
                Rounding::same(14.0),
                Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(0x4B, 0x6B, 0xFB, 120)),
            );
        }

        let f = &self.files[idx];
        let icon_center = Pos2::new(card.left() + 42.0, card.center().y);
        p.circle_filled(icon_center, 21.0, f.kind.color());
        p.text(
            icon_center,
            Align2::CENTER_CENTER,
            f.kind.label(),
            FontId::new(9.5, theme::medium_family()),
            Color32::WHITE,
        );

        let text_x = card.left() + 76.0;
        let max_w = (card.width() - 76.0 - 18.0).max(40.0);

        let name_galley = truncated(
            ui,
            &f.name,
            theme::regular(15.0),
            if active { TEXT } else { TEXT_SOFT },
            max_w,
        );
        p.galley(Pos2::new(text_x, card.top() + 15.0), name_galley, TEXT);

        let meta = format!("{}  ·  {}", format_size(f.size), f.modified);
        let meta_galley = truncated(ui, &meta, theme::regular(12.0), TEXT_MUTED, max_w);
        p.galley(Pos2::new(text_x, card.top() + 37.0), meta_galley, TEXT_MUTED);

        let status = f.status;
        // Плавный перелив цвета статуса: очередь → подписан → зашифрован.
        let pending_t = ui.ctx().animate_bool_with_time(
            egui::Id::new(("st_pending", idx)),
            status == FileStatus::Pending,
            0.25,
        );
        let signed_t = ui.ctx().animate_bool_with_time(
            egui::Id::new(("st_signed", idx)),
            status == FileStatus::Signed,
            0.25,
        );
        let encrypted_t = ui.ctx().animate_bool_with_time(
            egui::Id::new(("st_encrypted", idx)),
            status == FileStatus::Encrypted,
            0.25,
        );
        let status_color = blend_status(AMBER, GREEN, ACCENT, pending_t, signed_t, encrypted_t);

        let chip_galley = ui.fonts(|fonts| {
            fonts.layout_no_wrap(
                status.label().to_string(),
                theme::regular(11.5),
                TEXT_SOFT,
            )
        });
        let chip_w = chip_galley.size().x + 30.0;
        let chip = Rect::from_min_size(
            Pos2::new(text_x, card.top() + 59.0),
            Vec2::new(chip_w, 20.0),
        );
        p.rect_filled(
            chip,
            Rounding::same(6.0),
            lerp_color(BG_CHIP, status_color, 0.18),
        );
        p.circle_filled(
            Pos2::new(chip.left() + 11.0, chip.center().y),
            3.0,
            status_color,
        );
        p.galley(
            Pos2::new(chip.left() + 19.0, chip.center().y - 8.0),
            chip_galley,
            lerp_color(TEXT_SOFT, status_color, 0.30),
        );

        // ФИО подписантов — справа от статуса.
        if !f.signatures.is_empty() {
            let signers = f
                .signatures
                .iter()
                .map(|s| s.subject.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let signers_x = chip.right() + 12.0;
            let signers_w = (card.right() - 16.0 - signers_x).max(40.0);
            if signers_w > 40.0 {
                let galley =
                    truncated(ui, &signers, theme::regular(11.5), TEXT_MUTED, signers_w);
                p.galley(
                    Pos2::new(signers_x, chip.center().y - 8.0),
                    galley,
                    TEXT_MUTED,
                );
            }
        }

        if hovered {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if resp.clicked() {
            let multi = ui.input(|i| i.modifiers.ctrl || i.modifiers.command || i.modifiers.shift);
            if multi {
                if let Some(pos) = self.selected_files.iter().position(|&x| x == idx) {
                    self.selected_files.remove(pos);
                } else {
                    self.selected_files.push(idx);
                }
            } else {
                self.selected_files = vec![idx];
            }
            self.active_file = Some(idx);
            self.request_hash(idx);
        }
    }

    // -----------------------------------------------------------------------
    // Инспектор документа
    // -----------------------------------------------------------------------

    fn inspector(&mut self, ui: &mut Ui) {
        // SidePanel в egui считает exact_width шириной контента и добавляет
        // внешние отступы наружу, поэтому фиксируем ширину инспектора явно.
        let height = ui.available_height();

        // При выборе другого документа содержимое мягко «подъезжает» на 4 px.
        let key = self.active_file.map(|v| v as f32 + 1.0).unwrap_or(0.0);
        let anim = ui
            .ctx()
            .animate_value_with_time(egui::Id::new("inspector_switch"), key, 0.24);
        let progress = if key > 0.0 {
            (anim - key + 1.0).clamp(0.0, 1.0)
        } else {
            1.0
        };
        let shift = (1.0 - progress) * 4.0;

        ui.allocate_ui_with_layout(
            Vec2::new(334.0, height),
            Layout::top_down(Align::Min),
            |ui| {
                ui.set_width(334.0);
                if shift > 0.05 {
                    ui.add_space(shift);
                }
                self.inspector_body(ui);

                // Мягкое проявление содержимого при смене документа.
                if progress < 0.999 {
                    ui.painter().rect_filled(
                        ui.max_rect(),
                        0.0,
                        fade_col(BG_WORKSPACE, 1.0 - progress),
                    );
                }
            },
        );
    }

    fn inspector_body(&mut self, ui: &mut Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Инспектор")
                    .font(theme::regular(12.0))
                    .color(TEXT_DIM),
            );
        });
        ui.add_space(4.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let Some(idx) = self.active_file else {
                    ui.add_space(40.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new("Выберите документ")
                                .font(theme::regular(13.5))
                                .color(TEXT_MUTED),
                        );
                    });
                    return;
                };
                let Some(file) = self.files.get(idx).cloned() else {
                    return;
                };

                self.document_card(ui, &file);

                ui.add_space(18.0);
                self.signers_block(ui, &file);

                ui.add_space(18.0);
                ui.label(
                    RichText::new("Связанные файлы")
                        .font(theme::medium(15.0))
                        .color(TEXT),
                );
                ui.add_space(10.0);
                related_files(ui, &file);

                ui.add_space(18.0);
                if !self.panel_open {
                    if accent_button(ui, "Подписать документ", Icon::Pen).clicked() {
                        self.panel_open = true;
                        self.panel_collapsed = false;
                    }
                }
            });
    }

    fn document_card(&self, ui: &mut Ui, file: &FileEntry) {
        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(Rounding::same(16.0))
            .shadow(theme::soft_shadow())
            .inner_margin(Margin::same(18.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
                    let p = ui.painter();
                    p.rect_filled(r, Rounding::same(10.0), file.kind.color());
                    icons::paint(p, r.shrink(10.0), Icon::File, Color32::WHITE, 1.8);
                    ui.add_space(4.0);
                    let text_w = (ui.available_width() - 8.0).max(80.0);
                    ui.allocate_ui_with_layout(
                        Vec2::new(text_w, 36.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&file.name)
                                        .font(theme::medium(15.0))
                                        .color(TEXT),
                                )
                                .truncate(true),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "{}  ·  {}",
                                    file.kind.label(),
                                    format_size(file.size)
                                ))
                                .font(theme::regular(11.5))
                                .color(TEXT_MUTED),
                            );
                        },
                    );
                });

                ui.add_space(14.0);
                ui.painter().hline(
                    ui.available_rect_before_wrap().x_range(),
                    ui.cursor().top(),
                    Stroke::new(1.0_f32, DIVIDER_SOFT),
                );
                ui.add_space(12.0);

                let (validation, color) = match file.status {
                    FileStatus::Signed => ("Выполнено", GREEN),
                    FileStatus::Encrypted => ("Зашифрован", ACCENT),
                    FileStatus::Pending => ("Не выполнялась", TEXT_MUTED),
                };
                meta_row(ui, "Валидация", validation, color, false);
                ui.add_space(2.0);
                meta_row(ui, "Алгоритм", "ГОСТ 34.10-2012", TEXT_SOFT, false);
                ui.add_space(2.0);
                let hash = file.hash.clone().unwrap_or_else(|| "—".to_string());
                meta_row(ui, "Hash сумма", &hash, TEXT_MUTED, true);
            });
    }

    fn signers_block(&mut self, ui: &mut Ui, file: &FileEntry) {
        ui.label(
            RichText::new("Подписанты / Сертификаты")
                .font(theme::medium(15.0))
                .color(TEXT),
        );
        ui.add_space(10.0);

        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(Rounding::same(16.0))
            .inner_margin(Margin {
                left: 16.0,
                right: 16.0,
                top: 14.0,
                bottom: 14.0,
            })
            .show(ui, |ui| {
                let mut signers: Vec<CertEntry> = Vec::new();
                for sig in &file.signatures {
                    if let Some(c) = self
                        .certificates
                        .iter()
                        .find(|c| c.subject == sig.subject)
                        .cloned()
                    {
                        signers.push(c);
                    } else {
                        signers.push(CertEntry {
                            subject: sig.subject.clone(),
                            thumbprint: String::new(),
                            issuer: "Сертификат подписи".to_string(),
                            valid_until: String::new(),
                            file_path: None,
                        });
                    }
                }
                if signers.is_empty() {
                    for idx in &self.selected_certs {
                        if let Some(c) = self.certificates.get(*idx) {
                            signers.push(c.clone());
                        }
                    }
                }

                if signers.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Нет подписантов")
                                .font(theme::regular(12.5))
                                .color(TEXT_MUTED),
                        );
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Выбрать сертификат")
                                        .font(theme::regular(12.0))
                                        .color(ACCENT),
                                )
                                .fill(Color32::TRANSPARENT)
                                .stroke(Stroke::NONE),
                            )
                            .clicked()
                        {
                            self.active_nav = Nav::Certs;
                        }
                    });
                } else {
                    ui.horizontal_wrapped(|ui| {
                        for c in &signers {
                            avatar(ui, &c.subject, &c.issuer, &c.valid_until);
                            ui.add_space(4.0);
                        }
                    });
                }
            });
    }

    // -----------------------------------------------------------------------
    // Плавающая панель подписания
    // -----------------------------------------------------------------------

    fn floating_panel(&mut self, ctx: &egui::Context) {
        // Панель плавно выезжает снизу; при закрытии уезжает обратно.
        let slide = ctx.animate_bool_with_time(
            egui::Id::new("sign_panel_slide"),
            self.panel_open,
            0.26,
        );
        if !self.panel_open && slide <= 0.001 {
            return;
        }

        let offset_y = (1.0 - slide) * 26.0;
        let anchor = Align2::RIGHT_BOTTOM;
        egui::Area::new(egui::Id::new("sign_panel"))
            .order(egui::Order::Foreground)
            .pivot(anchor)
            .fixed_pos(ctx.screen_rect().right_bottom() - Vec2::new(22.0, 22.0 - offset_y))
            .constrain_to(ctx.screen_rect())
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(BG_PANEL)
                    .rounding(Rounding::same(16.0))
                    .shadow(theme::floating_shadow())
                    .inner_margin(Margin::same(20.0))
                    .show(ui, |ui| {
                        ui.set_width(340.0);
                        if self.panel_collapsed {
                            self.sign_panel_collapsed(ui);
                        } else {
                            self.sign_panel_body(ui);
                        }
                    });
            });
    }

    fn sign_panel_collapsed(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
            icons::paint(ui.painter(), r, Icon::Pen, ACCENT, 1.7);
            ui.add_space(6.0);
            ui.label(
                RichText::new("Подписание документа")
                    .font(theme::medium(15.0))
                    .color(TEXT),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if icon_button(ui, Icon::Close, 28.0).clicked() {
                    self.panel_open = false;
                }
                if icon_button(ui, Icon::Plus, 28.0).clicked() {
                    self.panel_collapsed = false;
                }
            });
        });
    }

    fn sign_panel_body(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Подписание документа")
                    .font(theme::medium(19.0))
                    .color(TEXT),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if icon_button(ui, Icon::Close, 30.0).clicked() {
                    self.panel_open = false;
                }
                if icon_button(ui, Icon::Minus, 30.0).clicked() {
                    self.panel_collapsed = true;
                }
            });
        });

        ui.add_space(12.0);
        ui.label(
            RichText::new("Сертификат")
                .font(theme::regular(12.5))
                .color(TEXT_MUTED),
        );
        ui.add_space(4.0);
        self.cert_pills(ui);

        ui.add_space(14.0);
        toggle_row(ui, &mut self.detached, "Открепленная подпись").on_hover_text(
            "Включено — подпись отдельным файлом.\nВыключено — содержимое документа вкладывается в файл подписи (присоединенная подпись).",
        );
        ui.add_space(5.0);
        toggle_row(ui, &mut self.separate_files, "Каждая в отдельный файл").on_hover_text(
            "Включено — отдельный файл подписи на каждый сертификат.\nВыключено — одна общая подпись со всеми подписантами.",
        );
        ui.add_space(5.0);
        toggle_row(ui, &mut self.pack_zip, "Упаковать в ZIP")
            .on_hover_text("Дополнительно упаковать файлы подписей в ZIP-архив.");

        ui.add_space(10.0);
        ui.label(
            RichText::new(self.signing_mode_text())
                .font(theme::regular(11.5))
                .color(TEXT_DIM),
        );

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("Формат")
                        .font(theme::regular(12.0))
                        .color(TEXT_MUTED),
                );
                ui.add_space(2.0);
                format_combo(ui, &mut self.format, 110.0);
            });
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("Кодировка")
                        .font(theme::regular(12.0))
                        .color(TEXT_MUTED),
                );
                ui.add_space(2.0);
                encoding_combo(ui, &mut self.encoding, 116.0);
            });
            ui.with_layout(Layout::right_to_left(Align::Max), |ui| {
                if self.signing.is_some() {
                    sign_spinner(ui);
                } else if action_button(ui, Icon::Pen).clicked() {
                    self.sign_selected();
                }
            });
        });
    }

    /// Подпись под тумблерами: что именно получится в результате.
    fn signing_mode_text(&self) -> String {
        let certs = if self.certificates.is_empty() {
            0
        } else {
            self.selected_certs.len().max(1)
        };

        let attachment = if self.detached {
            "откреплённая подпись"
        } else {
            "присоединённая подпись (содержимое внутри)"
        };

        let package = if self.separate_files {
            if certs > 1 {
                format!("отдельный файл на каждый из {} серт.", certs)
            } else {
                "отдельный файл".to_string()
            }
        } else if certs > 1 {
            format!("один общий файл на {} серт.", certs)
        } else {
            "один файл".to_string()
        };

        format!("{} · {}", attachment, package)
    }

    fn cert_pills(&mut self, ui: &mut Ui) {
        let mut remove: Option<usize> = None;
        let selected = self.selected_certs.clone();

        ui.horizontal_wrapped(|ui| {
            for idx in &selected {
                let Some(cert) = self.certificates.get(*idx) else {
                    continue;
                };
                let name = cert.subject.clone();
                egui::Frame::none()
                    .fill(Color32::from_rgb(0x3B, 0x3F, 0x52))
                    .rounding(Rounding::same(9.0))
                    .inner_margin(Margin {
                        left: 12.0,
                        right: 6.0,
                        top: 5.0,
                        bottom: 5.0,
                    })
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(&name)
                                    .font(theme::regular(12.5))
                                    .color(TEXT),
                            );
                            if small_close(ui).clicked() {
                                remove = Some(*idx);
                            }
                        });
                    });
                ui.add_space(4.0);
            }

            if selected.is_empty() {
                ui.label(
                    RichText::new("Сертификат не выбран")
                        .font(theme::regular(12.5))
                        .color(TEXT_DIM),
                );
                ui.add_space(4.0);
            }

            if self.certificates.is_empty() {
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Загрузить сертификаты")
                                .font(theme::regular(12.0))
                                .color(ACCENT),
                        )
                        .fill(Color32::TRANSPARENT)
                        .stroke(Stroke::NONE),
                    )
                    .clicked()
                {
                    self.active_nav = Nav::Certs;
                }
            } else {
                ui.scope(|ui| {
                    let v = ui.visuals_mut();
                    v.widgets.inactive.bg_fill = Color32::from_rgb(0x3B, 0x3F, 0x52);
                    v.widgets.inactive.weak_bg_fill = Color32::from_rgb(0x3B, 0x3F, 0x52);
                    v.widgets.hovered.bg_fill = BG_CARD_HOVER;
                    v.widgets.hovered.weak_bg_fill = BG_CARD_HOVER;

                    ui.menu_button(
                        RichText::new("+").font(theme::medium(15.0)).color(TEXT_SOFT),
                        |ui| {
                            ui.set_min_width(240.0);
                            for i in 0..self.certificates.len() {
                                let subject = self.certificates[i].subject.clone();
                                let already = self.selected_certs.contains(&i);
                                if ui
                                    .selectable_label(
                                        already,
                                        RichText::new(subject).font(theme::regular(13.0)),
                                    )
                                    .clicked()
                                {
                                    if !already {
                                        self.selected_certs.push(i);
                                    }
                                    ui.close_menu();
                                }
                            }
                        },
                    );
                });
            }
        });

        if let Some(idx) = remove {
            self.selected_certs.retain(|&x| x != idx);
        }
    }
}

// ---------------------------------------------------------------------------
// Экраны разделов
// ---------------------------------------------------------------------------

impl CryptoLineApp {
    fn certs_screen(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Сертификаты",
            "Ключи КриптоПро CSP из системного хранилища Windows и импортированные файлы",
        );
        ui.add_space(16.0);

        ui.horizontal(|ui| {
            if accent_button(ui, "Системное хранилище", Icon::Download).clicked() {
                self.load_certs_from_store();
            }
            if secondary_button(ui, "Импортировать файл", Icon::Plus).clicked() {
                self.import_certificate_file();
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(format!(
                        "Выбрано: {} из {}",
                        self.selected_certs.len(),
                        self.certificates.len()
                    ))
                    .font(theme::regular(12.0))
                    .color(TEXT_MUTED),
                );
            });
        });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
            ui.painter().circle_filled(r.center(), 3.0, ACCENT);
            ui.add_space(2.0);
            ui.label(
                RichText::new(&self.message)
                    .font(theme::regular(12.0))
                    .color(TEXT_MUTED),
            );
        });

        ui.add_space(10.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.certificates.is_empty() {
                    empty_panel(
                        ui,
                        Icon::Cert,
                        "Сертификаты не загружены",
                        "Загрузите сертификаты из системного хранилища или укажите файл .der / .cer / .pem",
                    );
                }
                for i in 0..self.certificates.len() {
                    self.cert_card(ui, i);
                    ui.add_space(8.0);
                }
            });
    }

    fn cert_card(&mut self, ui: &mut Ui, i: usize) {
        let Some(cert) = self.certificates.get(i).cloned() else {
            return;
        };
        let selected = self.selected_certs.contains(&i);

        let resp = egui::Frame::none()
            .fill(if selected { BG_CARD_HOVER } else { BG_CARD })
            .rounding(Rounding::same(14.0))
            .inner_margin(Margin::same(16.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
                    let p = ui.painter();
                    p.circle_filled(r.center(), 21.0, avatar_color(&cert.subject));
                    p.text(
                        r.center(),
                        Align2::CENTER_CENTER,
                        initials(&cert.subject),
                        theme::medium(13.0),
                        Color32::WHITE,
                    );

                    ui.add_space(6.0);
                    let text_w = (ui.available_width() - 150.0).max(140.0);
                    ui.allocate_ui_with_layout(
                        Vec2::new(text_w, 56.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&cert.subject)
                                        .font(theme::medium(14.5))
                                        .color(TEXT),
                                )
                                .truncate(true),
                            );
                            let source = if cert.file_path.is_some() {
                                "Импортирован из файла"
                            } else {
                                "Системное хранилище · CurrentUser\\My"
                            };
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!("Выдан: {}", cert.issuer))
                                        .font(theme::regular(12.0))
                                        .color(TEXT_MUTED),
                                )
                                .truncate(true),
                            );
                            ui.label(
                                RichText::new(source)
                                    .font(theme::regular(11.0))
                                    .color(TEXT_DIM),
                            );
                        },
                    );

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        check_mark(ui, selected);
                        if !cert.valid_until.is_empty() {
                            ui.label(
                                RichText::new(format!("до {}", cert.valid_until))
                                    .font(theme::regular(11.5))
                                    .color(TEXT_MUTED),
                            );
                        }
                    });
                });
            })
            .response;

        let resp = resp.interact(Sense::click());
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if resp.clicked() {
            if selected {
                self.selected_certs.retain(|&x| x != i);
            } else {
                self.selected_certs.push(i);
            }
        }
    }

    fn verify_screen(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Проверка ЭП",
            "Массовая проверка: документы и подписи сопоставляются по имени, порог совпадения 80%",
        );
        ui.add_space(14.0);

        ui.horizontal(|ui| {
            if accent_button(ui, "Добавить документы", Icon::Folder).clicked() {
                if let Some(paths) = rfd::FileDialog::new()
                    .set_title("Документы для проверки")
                    .pick_files()
                {
                    for path in paths {
                        if !self.verify_docs.contains(&path) {
                            self.verify_docs.push(path);
                        }
                    }
                    self.rebuild_verify_items();
                }
            }
            if secondary_button(ui, "Добавить подписи", Icon::BadgeCheck).clicked() {
                if let Some(paths) = rfd::FileDialog::new()
                    .add_filter("Подписи", &["sig", "p7s", "sgn"])
                    .set_title("Файлы подписей")
                    .pick_files()
                {
                    for path in paths {
                        if !self.verify_sigs.contains(&path) {
                            self.verify_sigs.push(path);
                        }
                    }
                    self.rebuild_verify_items();
                }
            }
            if secondary_button(ui, "Очистить", Icon::Trash).clicked() {
                self.verify_docs.clear();
                self.verify_sigs.clear();
                self.verify_items.clear();
            }
        });

        ui.add_space(12.0);
        ui.columns(2, |cols| {
            self.verify_file_list(&mut cols[0], true);
            self.verify_file_list(&mut cols[1], false);
        });

        ui.add_space(10.0);
        let pairs = self
            .verify_items
            .iter()
            .filter(|item| item.doc.is_some() && item.sig.is_some())
            .count();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "Сопоставлено пар: {} · документов: {} · подписей: {}",
                    pairs,
                    self.verify_docs.len(),
                    self.verify_sigs.len()
                ))
                .font(theme::regular(12.0))
                .color(TEXT_MUTED),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if accent_button(ui, "Проверить все", Icon::BadgeCheck).clicked() {
                    self.verify_all();
                }
            });
        });

        ui.add_space(10.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.verify_items.is_empty() {
                    ui.add_space(26.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new(
                                "Перетащите документы и файлы .sig в окно — они разложатся по разделам",
                            )
                            .font(theme::regular(13.0))
                            .color(TEXT_MUTED),
                        );
                    });
                }
                for i in 0..self.verify_items.len() {
                    self.verify_result_row(ui, i);
                    ui.add_space(6.0);
                }
            });
    }

    fn verify_file_list(&mut self, ui: &mut Ui, documents: bool) {
        let (title, hint, list) = if documents {
            (
                "Документы",
                "PDF, DOCX, XML и другие файлы",
                self.verify_docs.clone(),
            )
        } else {
            ("Подписи", "Файлы .sig / .p7s", self.verify_sigs.clone())
        };

        let mut remove: Option<usize> = None;
        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(Rounding::same(14.0))
            .inner_margin(Margin::same(14.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(title).font(theme::medium(14.0)).color(TEXT));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(list.len().to_string())
                                .font(theme::regular(12.0))
                                .color(TEXT_MUTED),
                        );
                    });
                });
                ui.add_space(6.0);

                egui::ScrollArea::vertical()
                    .max_height(140.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if list.is_empty() {
                            ui.label(
                                RichText::new(hint)
                                    .font(theme::regular(11.5))
                                    .color(TEXT_DIM),
                            );
                        }
                        for (i, path) in list.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(file_display(path))
                                            .font(theme::regular(12.0))
                                            .color(TEXT_SOFT),
                                    )
                                    .truncate(true),
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if small_close(ui).clicked() {
                                        remove = Some(i);
                                    }
                                    if let Ok(meta) = std::fs::metadata(path) {
                                        ui.label(
                                            RichText::new(format_size(meta.len()))
                                                .font(theme::regular(11.0))
                                                .color(TEXT_DIM),
                                        );
                                    }
                                });
                            });
                        }
                    });
            });

        if let Some(index) = remove {
            if documents {
                if index < self.verify_docs.len() {
                    self.verify_docs.remove(index);
                }
            } else if index < self.verify_sigs.len() {
                self.verify_sigs.remove(index);
            }
            self.rebuild_verify_items();
        }
    }

    fn verify_result_row(&mut self, ui: &mut Ui, index: usize) {
        let Some(item) = self.verify_items.get(index).cloned() else {
            return;
        };

        let (icon, color) = match &item.result {
            Some((true, _)) => (Icon::BadgeCheck, GREEN),
            Some((false, _)) => (Icon::Close, RED),
            None => (Icon::File, TEXT_DIM),
        };

        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(Rounding::same(12.0))
            .inner_margin(Margin::same(12.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::hover());
                    icons::paint(ui.painter(), rect, icon, color, 1.8);
                    ui.add_space(6.0);

                    ui.vertical(|ui| {
                        let doc_name = item
                            .doc
                            .as_ref()
                            .map(|path| file_display(path))
                            .unwrap_or_else(|| "Нет документа".to_string());
                        ui.label(
                            RichText::new(doc_name)
                                .font(theme::medium(13.0))
                                .color(TEXT),
                        );

                        let sig_line = match (&item.sig, item.doc.is_some()) {
                            (Some(sig), true) => format!(
                                "{} · совпадение {:.0}%",
                                file_display(sig),
                                item.score * 100.0
                            ),
                            (Some(sig), false) => {
                                format!("{} · нет документа", file_display(sig))
                            }
                            (None, _) => "подпись не найдена".to_string(),
                        };
                        ui.label(
                            RichText::new(sig_line)
                                .font(theme::regular(11.5))
                                .color(TEXT_MUTED),
                        );

                        if let Some((ok, detail)) = &item.result {
                            let summary = if *ok {
                                "Подпись верна".to_string()
                            } else {
                                detail.lines().next().unwrap_or("Ошибка").to_string()
                            };
                            ui.add(
                                egui::Label::new(
                                    RichText::new(summary)
                                        .font(theme::regular(11.5))
                                        .color(if *ok { GREEN } else { RED }),
                                )
                                .truncate(true),
                            )
                            .on_hover_text(detail.clone());
                        }
                    });
                });
            });
    }

    /// Проверяет все сопоставленные пары.
    fn verify_all(&mut self) {
        let pairs = self
            .verify_items
            .iter()
            .filter(|item| item.doc.is_some() && item.sig.is_some())
            .count();
        if pairs == 0 {
            self.message = "Нет сопоставленных пар (порог совпадения 80%)".to_string();
            return;
        }

        let mut ok_count = 0usize;
        let mut fail_count = 0usize;
        let mut limit_skipped = 0usize;

        for index in 0..self.verify_items.len() {
            let (Some(doc), Some(sig)) = (
                self.verify_items[index].doc.clone(),
                self.verify_items[index].sig.clone(),
            ) else {
                continue;
            };

            if let Err(error) = verify_size_error(&doc, &sig) {
                self.verify_items[index].result = Some((false, error));
                limit_skipped += 1;
                continue;
            }

            let (ok, detail) = run_verify_cli(&self.cli_path(), &doc, &sig);
            let detail = detail.replace('✓', "•").replace('✗', "×");
            if ok {
                if let Some(new_path) = self.rename_after_verify(&doc, &sig, &detail) {
                    self.verify_items[index].sig = Some(new_path.clone());
                    if let Some(pos) = self.verify_sigs.iter().position(|p| p == &sig) {
                        self.verify_sigs[pos] = new_path;
                    }
                }
                ok_count += 1;
            } else {
                fail_count += 1;
            }
            self.verify_items[index].result = Some((ok, detail));
        }

        self.message = format!(
            "Проверка: верных {} · ошибок {} · пропущено по лимиту {}",
            ok_count, fail_count, limit_skipped
        );
    }

    /// Пересобирает пары по сходству имён (порог 80%).
    fn rebuild_verify_items(&mut self) {
        let docs = self.verify_docs.clone();
        let sigs = self.verify_sigs.clone();
        let mut items: Vec<VerifyItem> = Vec::new();
        let mut doc_matched = vec![false; docs.len()];

        for sig in &sigs {
            let candidates = verify_name_candidates(sig);
            let mut best: Option<(usize, f32)> = None;
            for (doc_index, doc) in docs.iter().enumerate() {
                let doc_key = verify_name_key(doc, false);
                let score = candidates
                    .iter()
                    .map(|key| name_similarity(key, &doc_key))
                    .fold(0.0f32, f32::max);
                if score >= 0.8 && best.map_or(true, |(_, best_score)| score > best_score) {
                    best = Some((doc_index, score));
                }
            }

            match best {
                Some((doc_index, score)) => {
                    doc_matched[doc_index] = true;
                    items.push(VerifyItem {
                        doc: Some(docs[doc_index].clone()),
                        sig: Some(sig.clone()),
                        score,
                        result: None,
                    });
                }
                None => items.push(VerifyItem {
                    doc: None,
                    sig: Some(sig.clone()),
                    score: 0.0,
                    result: None,
                }),
            }
        }

        for (doc_index, doc) in docs.iter().enumerate() {
            if !doc_matched[doc_index] {
                items.push(VerifyItem {
                    doc: Some(doc.clone()),
                    sig: None,
                    score: 0.0,
                    result: None,
                });
            }
        }

        items.sort_by(|a, b| {
            let name = |item: &VerifyItem| {
                item.doc
                    .as_ref()
                    .or(item.sig.as_ref())
                    .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_lowercase())
                    .unwrap_or_default()
            };
            (name(a), a.sig.is_none()).cmp(&(name(b), b.sig.is_none()))
        });

        self.verify_items = items;
    }

    fn zip_screen(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Архив ZIP",
            "Соберите подписи в один архив, чтобы отправить их вместе с документами",
        );
        ui.add_space(16.0);

        ui.horizontal(|ui| {
            if accent_button(ui, "Выбрать папку и упаковать", Icon::Archive).clicked() {
                if let Some(dir) = rfd::FileDialog::new()
                    .set_title("Куда сохранить архив")
                    .pick_folder()
                {
                    let indices = if self.selected_files.is_empty() {
                        (0..self.files.len()).collect()
                    } else {
                        self.selected_files.clone()
                    };
                    self.build_zip(dir, indices);
                }
            }
        });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
            ui.painter().circle_filled(r.center(), 3.0, ACCENT);
            ui.add_space(2.0);
            ui.label(
                RichText::new(&self.message)
                    .font(theme::regular(12.0))
                    .color(TEXT_MUTED),
            );
        });

        ui.add_space(10.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let indices = self.display_indices();
                if indices.is_empty() {
                    empty_panel(
                        ui,
                        Icon::Archive,
                        "Архив пока пуст",
                        "Подпишите документы — их файлы .sig появятся здесь",
                    );
                }
                for idx in indices {
                    let Some(file) = self.files.get(idx).cloned() else {
                        continue;
                    };
                    egui::Frame::none()
                        .fill(BG_CARD)
                        .rounding(Rounding::same(12.0))
                        .inner_margin(Margin::same(14.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(&file.name)
                                        .font(theme::regular(13.5))
                                        .color(TEXT_SOFT),
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "{} подп.",
                                            file.signatures.len()
                                        ))
                                        .font(theme::regular(11.5))
                                        .color(if file.signatures.is_empty() {
                                            TEXT_DIM
                                        } else {
                                            GREEN
                                        }),
                                    );
                                });
                            });
                        });
                    ui.add_space(6.0);
                }
            });
    }

    fn settings_screen(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Настройки",
            "Параметры окружения и подключение к КриптоПро CSP",
        );
        ui.add_space(20.0);

        let cli = self.cli_path();
        let cli_ok = cli.exists();

        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(Rounding::same(16.0))
            .inner_margin(Margin::same(20.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width().min(720.0));
                setting_row(
                    ui,
                    "CLI подписи",
                    &cli.display().to_string(),
                    cli_ok,
                );
                ui.add_space(10.0);
                setting_row(
                    ui,
                    "Временная папка",
                    &std::env::temp_dir().display().to_string(),
                    true,
                );
                ui.add_space(10.0);
                setting_row(
                    ui,
                    "Версия",
                    &format!("Просто Подпись {} · egui", env!("CARGO_PKG_VERSION")),
                    true,
                );
                ui.add_space(10.0);
                setting_row(ui, "Провайдер", "PROV_GOST_2012_256 · CALG_GR3411_2012_256", true);

                ui.add_space(18.0);
                ui.label(
                    RichText::new("Палитра")
                        .font(theme::regular(12.5))
                        .color(TEXT_MUTED),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    for c in [
                        BG_WINDOW,
                        BG_WORKSPACE,
                        BG_CARD,
                        ACCENT,
                        TEXT_MUTED,
                    ] {
                        let (r, _) =
                            ui.allocate_exact_size(Vec2::splat(26.0), Sense::hover());
                        ui.painter().circle_filled(r.center(), 13.0, c);
                        ui.add_space(4.0);
                    }
                });
            });

        ui.add_space(16.0);
        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(Rounding::same(16.0))
            .inner_margin(Margin::same(20.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width().min(720.0));
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Обновления")
                                .font(theme::medium(15.0))
                                .color(TEXT),
                        );
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(format!(
                                "Текущая версия: {}",
                                env!("CARGO_PKG_VERSION")
                            ))
                            .font(theme::regular(12.0))
                            .color(TEXT_MUTED),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if accent_button(ui, "Проверить обновления", Icon::Download)
                            .clicked()
                        {
                            self.check_updates();
                        }
                    });
                });

                ui.add_space(8.0);
                if let Some(error) = self.update_error.clone() {
                    ui.label(
                        RichText::new(error)
                            .font(theme::regular(12.0))
                            .color(RED),
                    );
                }
                if let Some(latest) = self.update_latest.clone() {
                    if version_is_newer(&latest, env!("CARGO_PKG_VERSION")) {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("Доступна версия {}", latest))
                                    .font(theme::medium(13.0))
                                    .color(AMBER),
                            );
                            if let Some(url) = self.update_url.clone() {
                                if secondary_button(ui, "Открыть страницу", Icon::Download)
                                    .clicked()
                                {
                                    open_external(&url);
                                }
                            }
                        });
                    } else {
                        ui.label(
                            RichText::new(format!(
                                "Установлена последняя версия ({})",
                                latest
                            ))
                            .font(theme::regular(12.5))
                            .color(GREEN),
                        );
                    }
                }
            });

        ui.add_space(16.0);
        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(Rounding::same(16.0))
            .inner_margin(Margin::same(20.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width().min(720.0));
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Инструкция")
                                .font(theme::medium(15.0))
                                .color(TEXT),
                        );
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new("PDF со скриншотами и подсказками")
                                .font(theme::regular(12.0))
                                .color(TEXT_MUTED),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if secondary_button(ui, "Открыть инструкцию", Icon::File).clicked()
                        {
                            let path = self.manual_path();
                            if path.exists() {
                                open_external(&path.display().to_string());
                            } else {
                                self.message =
                                    "Инструкция не найдена рядом с программой".to_string();
                            }
                        }
                    });
                });
            });
    }

    fn manual_path(&self) -> PathBuf {
        self.cli_path()
            .parent()
            .map(|dir| dir.join("Просто подпись — инструкция.pdf"))
            .unwrap_or_else(|| PathBuf::from("Просто подпись — инструкция.pdf"))
    }

    fn check_updates(&mut self) {
        self.update_error = None;
        self.update_latest = None;
        self.update_url = None;

        match fetch_update_manifest() {
            Some(json) => {
                let latest = json_string(&json, "version").unwrap_or_default();
                if latest.is_empty() {
                    self.update_error =
                        Some("Некорректный ответ сервера обновлений".to_string());
                    return;
                }
                let url = json_string(&json, "url").unwrap_or_default();
                self.update_latest = Some(latest);
                self.update_url = if url.is_empty() { None } else { Some(url) };
            }
            None => {
                self.update_error = Some(
                    "Не удалось проверить обновления. Проверьте подключение к интернету."
                        .to_string(),
                );
            }
        }
    }

    fn encrypt_screen(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Шифрование",
            "Документы шифруются на сертификаты получателей · ГОСТ Р 34.12-2015 (Кузнечик)",
        );
        ui.add_space(14.0);

        ui.horizontal(|ui| {
            if accent_button(ui, "Зашифровать", Icon::Lock).clicked() {
                self.encrypt_selected();
            }
            ui.add_space(8.0);
            if secondary_button(ui, "Добавить документы", Icon::Plus).clicked() {
                self.add_files();
            }
        });

        ui.add_space(16.0);

        if self.files.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(
                    RichText::new("Нет документов")
                        .font(theme::medium(17.0))
                        .color(TEXT),
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "Добавьте файлы кнопкой «Добавить документы» или перетащите их в окно.",
                    )
                    .font(theme::regular(12.5))
                    .color(TEXT_MUTED),
                );
            });
            return;
        }

        let docs: Vec<(usize, String, String)> = self
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| (i, f.name.clone(), f.modified.clone()))
            .collect();
        let certs: Vec<(usize, String, String)> = self
            .certificates
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.subject.clone(), c.issuer.clone()))
            .collect();

        let mut toggle_doc: Option<usize> = None;
        let mut toggle_cert: Option<usize> = None;

        ui.columns(2, |cols| {
            let left = &mut cols[0];
            left.label(
                RichText::new(format!("Документы · {}", docs.len()))
                    .font(theme::medium(13.0))
                    .color(TEXT_MUTED),
            );
            left.add_space(8.0);
            egui::ScrollArea::vertical()
                .id_source("encrypt_docs")
                .max_height(430.0)
                .show(left, |ui| {
                    for (idx, name, date) in &docs {
                        let selected = self.selected_files.contains(idx);
                        if list_row(ui, selected, name, date).clicked() {
                            toggle_doc = Some(*idx);
                        }
                        ui.add_space(6.0);
                    }
                });

            let right = &mut cols[1];
            right.label(
                RichText::new(format!("Получатели · {}", certs.len()))
                    .font(theme::medium(13.0))
                    .color(TEXT_MUTED),
            );
            right.add_space(8.0);
            if certs.is_empty() {
                right.label(
                    RichText::new("Загрузите сертификаты в разделе «Сертификаты»")
                        .font(theme::regular(12.5))
                        .color(TEXT_DIM),
                );
            }
            egui::ScrollArea::vertical()
                .id_source("encrypt_certs")
                .max_height(430.0)
                .show(right, |ui| {
                    for (idx, subject, issuer) in &certs {
                        let selected = self.selected_certs.contains(idx);
                        if list_row(ui, selected, subject, issuer).clicked() {
                            toggle_cert = Some(*idx);
                        }
                        ui.add_space(6.0);
                    }
                });
        });

        if let Some(idx) = toggle_doc {
            if let Some(pos) = self.selected_files.iter().position(|i| *i == idx) {
                self.selected_files.remove(pos);
            } else {
                self.selected_files.push(idx);
            }
            self.active_file = Some(idx);
        }
        if let Some(idx) = toggle_cert {
            if let Some(pos) = self.selected_certs.iter().position(|i| *i == idx) {
                self.selected_certs.remove(pos);
            } else {
                self.selected_certs.push(idx);
            }
        }
    }

    /// Шифрует выбранные документы на выбранные сертификаты получателей.
    fn encrypt_selected(&mut self) {
        let mut docs = self.selected_files.clone();
        if docs.is_empty() {
            if let Some(active) = self.active_file {
                docs.push(active);
            }
        }
        if docs.is_empty() {
            self.message = "Выберите документы для шифрования".to_string();
            return;
        }
        if self.selected_certs.is_empty() {
            self.message = "Выберите хотя бы одного получателя".to_string();
            return;
        }

        let mut cert_paths: Vec<PathBuf> = Vec::new();
        for idx in self.selected_certs.clone() {
            if let Some((path, _)) = self.resolve_cert(idx) {
                cert_paths.push(path);
            }
        }
        if cert_paths.is_empty() {
            self.message = "Не удалось подготовить сертификаты получателей".to_string();
            return;
        }

        let cli = self.cli_path();
        if !cli.exists() {
            self.message = format!("CLI не найдена: {}", cli.display());
            return;
        }

        let mut done = 0usize;
        let mut errors: Vec<String> = Vec::new();
        let mut cipher = String::new();

        for idx in docs {
            let Some(file) = self.files.get(idx) else {
                continue;
            };
            let mut out = file.path.clone().into_os_string();
            out.push(".enc");
            let out = PathBuf::from(out);

            let mut cmd = std::process::Command::new(&cli);
            cmd.arg("encrypt").arg("--file").arg(&file.path);
            for cert in &cert_paths {
                cmd.arg("--cert").arg(cert);
            }
            cmd.arg("--output").arg(&out);

            match cmd.output() {
                Ok(result) if result.status.success() => {
                    let stdout = String::from_utf8_lossy(&result.stdout);
                    if let Some(line) = stdout.lines().find(|l| l.trim().starts_with("алгоритм:")) {
                        cipher = line.split(':').nth(1).unwrap_or("").trim().to_string();
                    }
                    done += 1;
                }
                Ok(result) => {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    let text = stderr
                        .lines()
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("ошибка шифрования")
                        .trim()
                        .to_string();
                    errors.push(format!("{}: {}", file.name, text));
                }
                Err(e) => errors.push(format!("{}: {}", file.name, e)),
            }
        }

        self.message = if done > 0 {
            let mut text = format!("Зашифровано файлов: {}", done);
            if !cipher.is_empty() {
                text.push_str(&format!(" · {}", cipher));
            }
            if !errors.is_empty() {
                text.push_str(&format!(" · ошибок: {}", errors.len()));
            }
            text
        } else {
            format!(
                "Шифрование не выполнено: {}",
                errors.first().cloned().unwrap_or_default()
            )
        };

        if !errors.is_empty() {
            self.active_nav = Nav::Encrypt;
        }
    }
}

// ---------------------------------------------------------------------------
// Действия
// ---------------------------------------------------------------------------

impl CryptoLineApp {
    fn cli_path(&self) -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join("Podpis-cli.exe")))
            .unwrap_or_else(|| PathBuf::from("Podpis-cli.exe"))
    }

    /// Ctrl+A — выбрать все файлы в текущей выборке.
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        // egui-winit не отдаёт Event::Key для букв при нелатинской раскладке,
        // поэтому дополнительно опрашиваем физическое состояние клавиш.
        let event_a = ctx.input(|i| {
            i.events.iter().any(|event| match event {
                egui::Event::Key {
                    key,
                    physical_key,
                    pressed: true,
                    modifiers,
                    ..
                } => {
                    let is_a =
                        *key == egui::Key::A || *physical_key == Some(egui::Key::A);
                    is_a && modifiers.ctrl && !modifiers.alt && !modifiers.shift
                }
                _ => false,
            })
        });

        let down = event_a || crate::win::ctrl_a_down();
        let just_pressed = down && !self.ctrl_a_was_down;
        self.ctrl_a_was_down = down;

        if !just_pressed || self.active_nav != Nav::Docs {
            return;
        }
        // Не мешаем выделению текста в поле поиска.
        let search_id = egui::Id::new("file_search");
        if ctx.memory(|m| m.focused()) == Some(search_id) {
            return;
        }

        let indices = self.display_indices();
        if indices.is_empty() {
            return;
        }

        self.selected_files = indices;
        if self.active_file.is_none() {
            self.active_file = self.selected_files.first().copied();
            if let Some(idx) = self.active_file {
                self.request_hash(idx);
            }
        }
        self.message = format!("Выбрано файлов: {}", self.selected_files.len());
    }

    fn add_files(&mut self) {
        if let Some(paths) = rfd::FileDialog::new()
            .add_filter(
                "Документы",
                &[
                    "pdf", "doc", "docx", "xml", "txt", "rtf", "odt", "xls", "xlsx", "enc",
                ],
            )
            .add_filter("Все файлы", &["*"])
            .set_title("Выбрать файлы для подписи")
            .pick_files()
        {
            let mut added = 0;
            for path in paths {
                if self.push_file(path) {
                    added += 1;
                }
            }
            if added > 0 {
                self.message = format!("Добавлено файлов: {}", added);
            }
        }
    }

    fn push_file(&mut self, path: PathBuf) -> bool {
        if self.files.iter().any(|f| f.path == path) {
            return false;
        }
        if let Some(mut entry) = FileEntry::from_path(path) {
            // Подписи, которые уже лежат рядом с документом, подхватываем сразу:
            // иначе кнопка «Проверить подпись» не находит файл .sig.
            entry.signatures = find_signatures_for(&entry.path);
            if !entry.signatures.is_empty() {
                entry.status = FileStatus::Signed;
            }
            self.files.push(entry);
            let idx = self.files.len() - 1;
            if self.active_file.is_none() {
                self.active_file = Some(idx);
                self.selected_files = vec![idx];
                self.request_hash(idx);
            }
            true
        } else {
            false
        }
    }

    fn handle_dropped(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .filter(|path| path.is_file())
                .collect()
        });
        if dropped.is_empty() {
            return;
        }

        let has_signature = dropped.iter().any(|path| is_signature_path(path));
        let on_verify = self.active_nav == Nav::Verify;

        // Если в наборе есть подписи — весь набор идёт на проверку:
        // документы в один раздел, подписи в другой.
        if has_signature || on_verify {
            let mut added = 0;
            for path in dropped {
                if is_signature_path(&path) {
                    if !self.verify_sigs.contains(&path) {
                        self.verify_sigs.push(path);
                        added += 1;
                    }
                } else if !self.verify_docs.contains(&path) {
                    self.verify_docs.push(path);
                    added += 1;
                }
            }
            if added > 0 {
                self.rebuild_verify_items();
                self.active_nav = Nav::Verify;
                self.message = format!("Добавлено для проверки: {}", added);
            }
            return;
        }

        let mut added = 0;
        for path in dropped {
            if self.push_file(path) {
                added += 1;
            }
        }
        if added > 0 {
            self.message = format!("Добавлено файлов: {}", added);
        }
    }

    fn drop_overlay(&self, ctx: &egui::Context) {
        let dragging = ctx.input(|i| !i.raw.hovered_files.is_empty());
        if !dragging {
            return;
        }
        let screen = ctx.screen_rect();
        let p = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("drop_overlay"),
        ));
        p.rect_filled(
            screen,
            Rounding::ZERO,
            Color32::from_rgba_unmultiplied(0x1B, 0x1D, 0x26, 220),
        );
        let r = screen.shrink2(Vec2::new(46.0, 36.0));
        p.rect_stroke(r, Rounding::same(20.0), Stroke::new(2.0_f32, ACCENT));
        p.circle_filled(screen.center() - Vec2::new(0.0, 34.0), 34.0, ACCENT_SOFT);
        icons::paint(
            &p,
            Rect::from_center_size(
                screen.center() - Vec2::new(0.0, 34.0),
                Vec2::splat(28.0),
            ),
            Icon::Download,
            ACCENT,
            2.0,
        );
        let (title, hint) = if self.active_nav == Nav::Verify {
            (
                "Отпустите файлы для проверки",
                "Документы и подписи .sig разложатся по разделам",
            )
        } else {
            (
                "Отпустите файлы, чтобы добавить",
                "PDF, DOCX, XML, TXT и другие документы",
            )
        };
        p.text(
            screen.center() + Vec2::new(0.0, 22.0),
            Align2::CENTER_CENTER,
            title,
            theme::medium(20.0),
            TEXT,
        );
        p.text(
            screen.center() + Vec2::new(0.0, 48.0),
            Align2::CENTER_CENTER,
            hint,
            theme::regular(13.0),
            TEXT_MUTED,
        );
    }

    /// Ресайз окна без системной рамки: следим за курсором у краёв напрямую.
    /// Area здесь не используется — иначе она перехватывает клики по кнопкам.
    fn resize_borders(&mut self, ctx: &egui::Context) {
        use egui::viewport::ResizeDirection as R;

        let s = ctx.screen_rect();
        let (pointer, pressed, down) = ctx.input(|i| {
            (
                i.pointer.hover_pos(),
                i.pointer.primary_pressed(),
                i.pointer.primary_down(),
            )
        });
        let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));

        if let Some(p) = pointer {
            let band = 6.0;
            let corner = 12.0;

            let dir = if p.y <= s.top() + band {
                if p.x <= s.left() + corner {
                    Some(R::NorthWest)
                } else if p.x >= s.right() - corner {
                    Some(R::NorthEast)
                } else {
                    Some(R::North)
                }
            } else if p.y >= s.bottom() - band {
                if p.x <= s.left() + corner {
                    Some(R::SouthWest)
                } else if p.x >= s.right() - corner {
                    Some(R::SouthEast)
                } else {
                    Some(R::South)
                }
            } else if p.x <= s.left() + band {
                Some(R::West)
            } else if p.x >= s.right() - band {
                Some(R::East)
            } else {
                None
            };

            match dir {
                Some(R::NorthWest) | Some(R::SouthEast) => {
                    ctx.set_cursor_icon(egui::CursorIcon::ResizeNwSe)
                }
                Some(R::NorthEast) | Some(R::SouthWest) => {
                    ctx.set_cursor_icon(egui::CursorIcon::ResizeNeSw)
                }
                Some(R::North) | Some(R::South) => {
                    ctx.set_cursor_icon(egui::CursorIcon::ResizeVertical)
                }
                Some(R::East) | Some(R::West) => {
                    ctx.set_cursor_icon(egui::CursorIcon::ResizeHorizontal)
                }
                None => {}
            }

            if pressed && self.resize_drag.is_none() && !maximized {
                if let Some(dir) = dir {
                    if let (Some(rect), Some(cursor)) =
                        (crate::win::window_rect(), crate::win::cursor_pos())
                    {
                        self.resize_drag = Some(ResizeDrag {
                            dir,
                            start_rect: Some(rect),
                            start_cursor: Some(cursor),
                        });
                    }
                }
            }
        }

        if let Some(drag) = self.resize_drag {
            if down {
                if let (Some(rect), Some(start), Some(now)) =
                    (drag.start_rect, drag.start_cursor, crate::win::cursor_pos())
                {
                    resize_native(ctx, drag.dir, rect, start, now);
                }
            } else {
                self.resize_drag = None;
            }
        }
    }

    fn request_hash(&mut self, idx: usize) {
        if self.hash_pending == Some(idx) {
            return;
        }
        let Some(file) = self.files.get(idx) else {
            return;
        };
        if file.hash.is_some() {
            return;
        }
        let path = file.path.clone();
        let cli = self.cli_path();
        let (tx, rx) = mpsc::channel();
        self.hash_rx = Some(rx);
        self.hash_pending = Some(idx);
        std::thread::spawn(move || {
            let mut value = String::new();
            if let Ok(out) = std::process::Command::new(cli)
                .arg("hash")
                .arg("--file")
                .arg(&path)
                .output()
            {
                if out.status.success() {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    if let Some(pos) = stdout.rfind("): ") {
                        value = stdout[pos + 3..].trim().to_string();
                    }
                }
            }
            let _ = tx.send((idx, value));
        });
    }

    fn poll_hash(&mut self) {
        let Some(rx) = &self.hash_rx else {
            return;
        };
        match rx.try_recv() {
            Ok((idx, value)) => {
                if let Some(f) = self.files.get_mut(idx) {
                    if !value.is_empty() {
                        f.hash = Some(value);
                    }
                }
                self.hash_pending = None;
                self.hash_rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.hash_pending = None;
                self.hash_rx = None;
            }
        }
    }

    fn load_certs_from_store(&mut self) {
        // PowerShell пишет результат в UTF-8 файл: консольный вывод в cp866
        // испортил бы кириллицу в ФИО.
        let out_file = std::env::temp_dir().join("cryptoline_certs.txt");
        let script = format!(
            r#"$certs = Get-ChildItem Cert:\CurrentUser\My; $lines = foreach($cert in $certs) {{ "CERT_START|" + $cert.Subject + "|" + $cert.Thumbprint + "|" + $cert.Issuer + "|" + $cert.NotAfter.ToString("dd.MM.yyyy") + "|CERT_END" }}; [IO.File]::WriteAllLines("{}", $lines, [Text.UTF8Encoding]::new($false))"#,
            out_file.display()
        );

        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let content = std::fs::read_to_string(&out_file).unwrap_or_default();
                let _ = std::fs::remove_file(&out_file);

                let mut count = 0;
                for line in content.lines() {
                    if !line.contains("CERT_START|") || !line.contains("|CERT_END") {
                        continue;
                    }
                    let processed = line
                        .replace("CERT_START|", "")
                        .replace("|CERT_END", "");
                    let parts: Vec<&str> = processed.split('|').collect();
                    if parts.len() < 3 {
                        continue;
                    }
                    let subject = self.format_person(&self.extract_cn_from_dn(parts[0]));
                    let thumbprint = parts[1].trim().to_string();
                    let issuer = self.extract_cn_from_dn(parts[2]);
                    let valid_until = parts
                        .get(3)
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                    if thumbprint.is_empty() {
                        continue;
                    }
                    if self
                        .certificates
                        .iter()
                        .any(|c| !c.thumbprint.is_empty() && c.thumbprint == thumbprint)
                    {
                        continue;
                    }
                    self.certificates.push(CertEntry {
                        subject,
                        thumbprint,
                        issuer,
                        valid_until,
                        file_path: None,
                    });
                    count += 1;
                }
                self.message = if count > 0 {
                    format!("Загружено сертификатов из системного хранилища: {}", count)
                } else {
                    "В хранилище CurrentUser\\My сертификаты не найдены".to_string()
                };
            }
            Err(e) => self.message = format!("Ошибка загрузки сертификатов: {}", e),
            Ok(_) => {
                self.message = "Не удалось прочитать хранилище сертификатов".to_string()
            }
        }
    }

    fn import_certificate_file(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Сертификаты", &["der", "cer", "pem", "crt"])
            .set_title("Импортировать сертификат")
            .pick_file()
        else {
            self.message = "Импорт отменён".to_string();
            return;
        };

        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                self.message = format!("Ошибка чтения файла: {}", e);
                return;
            }
        };

        let cert_file = std::env::temp_dir().join(format!(
            "cryptoline_cert_{}.der",
            self.certificates.len() + 1
        ));
        if let Err(e) = std::fs::write(&cert_file, &data) {
            self.message = format!("Ошибка сохранения сертификата: {}", e);
            return;
        }

        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let fallback = filename
            .trim_end_matches(".der")
            .trim_end_matches(".cer")
            .trim_end_matches(".pem")
            .trim_end_matches(".crt")
            .to_string();
        // Имя владельца берём из самого сертификата через CLI.
        let subject = match self.certificate_subject(&cert_file) {
            Some(cn) => self.format_person(&cn),
            None => self.format_person(&fallback),
        };

        self.certificates.push(CertEntry {
            subject,
            issuer: "Импортированный файл".to_string(),
            thumbprint: filename.clone(),
            valid_until: String::new(),
            file_path: Some(cert_file),
        });

        self.message = format!("Сертификат импортирован: {}", filename);
        self.active_nav = Nav::Certs;
    }

    /// Достаёт CN из DN вида `CN=..., O=..., C=...`.
    ///
    /// Windows (CryptoAPI, .NET) отдаёт значения в кавычках, а кавычки внутри
    /// значения удваивает: `CN="ООО ""ТЕНЗОР"""`. Поэтому снимаем обрамление
    /// и превращаем `""` обратно в `"`.
    fn extract_cn_from_dn(&self, dn: &str) -> String {
        for part in split_dn(dn) {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix("CN=") {
                return unquote_dn_value(rest);
            }
        }
        unquote_dn_value(dn)
    }

    /// Форматирует ФИО («ИВАН ПЕТРОВ» → «Иван Петров»), но не трогает
    /// названия организаций.
    fn format_person(&self, name: &str) -> String {
        let lower = name.to_lowercase();
        let is_org = name.contains('"')
            || lower.starts_with("ооо")
            || lower.starts_with("ао ")
            || lower.starts_with("пао")
            || lower.starts_with("зао")
            || lower.starts_with("ип ")
            || lower.starts_with("мку")
            || lower.starts_with("гуп");
        if is_org {
            return name.to_string();
        }
        self.format_name(name)
    }

    fn certificate_subject(&self, path: &Path) -> Option<String> {
        let out = std::process::Command::new(self.cli_path())
            .arg("cert")
            .arg("--cert")
            .arg(path)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout.lines().find(|l| l.starts_with("Субъект:"))?;
        let dn = line.trim_start_matches("Субъект:").trim();
        let cn = self.extract_cn_from_dn(dn);
        if cn.is_empty() {
            None
        } else {
            Some(cn)
        }
    }

    /// Разделы ФИО пишутся с заглавной буквы: «ЧЕРНЕЙ ИВАН» → «Черней Иван».
    fn format_name(&self, name: &str) -> String {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return String::new();
        }

        let mut out = String::with_capacity(trimmed.len());
        let mut capitalize = true;
        for ch in trimmed.chars() {
            if ch.is_alphabetic() {
                if capitalize {
                    out.extend(ch.to_uppercase());
                    capitalize = false;
                } else {
                    out.extend(ch.to_lowercase());
                }
            } else {
                out.push(ch);
                if ch == ' ' || ch == '-' || ch == '.' {
                    capitalize = true;
                }
            }
        }
        out
    }

    fn resolve_cert(&self, idx: usize) -> Option<(PathBuf, String)> {
        let cert = self.certificates.get(idx)?;
        if let Some(path) = &cert.file_path {
            return Some((path.clone(), cert.subject.clone()));
        }

        let temp_cert = std::env::temp_dir().join(format!(
            "cryptoline_cert_{}.der",
            cert.thumbprint.chars().take(16).collect::<String>()
        ));

        // Экспорт открытого сертификата из хранилища в DER через .NET:
        // предсказуемее, чем разбор вывода certutil.
        let script = format!(
            "$c = Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {{ $_.Thumbprint -eq '{}' }}; if ($c) {{ [IO.File]::WriteAllBytes('{}', $c.Export('Cert')) }}",
            cert.thumbprint,
            temp_cert.display()
        );
        let ok = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !ok || !temp_cert.exists() {
            let _ = std::fs::remove_file(&temp_cert);
            return None;
        }

        Some((temp_cert, cert.subject.clone()))
    }

    /// Проверяет размеры и при необходимости показывает предупреждение.
    fn sign_selected(&mut self) {
        let mut indices = self.selected_files.clone();
        if indices.is_empty() {
            if let Some(active) = self.active_file {
                indices.push(active);
            }
        }

        let large: Vec<String> = indices
            .iter()
            .filter_map(|idx| self.files.get(*idx))
            .filter(|file| file.size > LARGE_FILE_BYTES)
            .map(|file| format!("{} — {}", file.name, format_size(file.size)))
            .collect();

        if !large.is_empty() {
            self.large_sign_files = Some(large);
            return;
        }

        self.sign_selected_now();
    }

    fn sign_selected_now(&mut self) {
        if self.signing.is_some() {
            self.message = "Подписание уже выполняется".to_string();
            return;
        }
        let mut file_indices = self.selected_files.clone();
        if file_indices.is_empty() {
            if let Some(a) = self.active_file {
                file_indices.push(a);
            }
        }
        if file_indices.is_empty() {
            self.message = "Выберите документ для подписи".to_string();
            return;
        }

        if self.certificates.is_empty() && self.selected_certs.is_empty() {
            self.message = "Сертификаты не загружены — откройте раздел «Сертификаты»".to_string();
            self.active_nav = Nav::Certs;
            return;
        }
        if self.selected_certs.is_empty() {
            self.selected_certs.push(0);
        }

        let cli = self.cli_path();
        if !cli.exists() {
            self.message = format!("CLI не найдена: {}", cli.display());
            return;
        }

        let cert_indices = self.selected_certs.clone();
        let mut errors: Vec<String> = Vec::new();

        // Сертификаты готовим один раз на весь пакет документов.
        let mut prepared: Vec<PreparedCert> = Vec::new();
        for cert_idx in &cert_indices {
            match self.resolve_cert(*cert_idx) {
                Some((path, subject)) => {
                    let imported = self
                        .certificates
                        .get(*cert_idx)
                        .map(|c| c.file_path.is_some())
                        .unwrap_or(false);
                    prepared.push(PreparedCert {
                        path,
                        subject,
                        imported,
                    });
                }
                None => errors.push("не удалось подготовить сертификат".to_string()),
            }
        }
        if prepared.is_empty() {
            self.message = "Не удалось подготовить ни один сертификат".to_string();
            return;
        }

        let separate = self.separate_files;
        let detached = self.detached;
        let format = self.format;
        let encoding = self.encoding;

        // Документы к подписанию: (индекс в списке, путь).
        let jobs: Vec<(usize, PathBuf)> = file_indices
            .iter()
            .filter_map(|idx| self.files.get(*idx).map(|f| (*idx, f.path.clone())))
            .collect();
        if jobs.is_empty() {
            self.message = "Нет документов для подписания".to_string();
            return;
        }

        let temp_certs: Vec<PathBuf> = prepared
            .iter()
            .filter(|c| !c.imported)
            .map(|c| c.path.clone())
            .collect();

        // Подпись идёт в фоновом потоке, чтобы интерфейс продолжал анимироваться.
        let (tx, rx) = mpsc::channel::<SignOutcome>();
        let prepared_thread = prepared.clone();
        let cli_thread = cli.clone();
        std::thread::spawn(move || {
            for (idx, path) in jobs {
                let mut created: Vec<(String, PathBuf)> = Vec::new();
                let mut errors: Vec<String> = Vec::new();

                if separate {
                    for cert in &prepared_thread {
                        match run_sign_cli(
                            &cli_thread,
                            &path,
                            &[cert.path.clone()],
                            detached,
                            format,
                            encoding,
                        ) {
                            Ok(sig) => created.push((cert.subject.clone(), sig)),
                            Err(e) => errors.push(e),
                        }
                    }
                } else {
                    let cert_paths: Vec<PathBuf> =
                        prepared_thread.iter().map(|c| c.path.clone()).collect();
                    match run_sign_cli(
                        &cli_thread,
                        &path,
                        &cert_paths,
                        detached,
                        format,
                        encoding,
                    ) {
                        Ok(sig) => {
                            for cert in &prepared_thread {
                                created.push((cert.subject.clone(), sig.clone()));
                            }
                        }
                        Err(e) => errors.push(e),
                    }
                }

                let _ = tx.send(SignOutcome {
                    idx,
                    created,
                    errors,
                });
            }
        });

        self.sign_rx = Some(rx);
        self.signing = Some(SignState {
            total: file_indices.len(),
            done: 0,
            started: 0.0,
            dirs: Vec::new(),
            errors: errors.len(),
            temp_certs,
        });
        self.message = format!("Подписание документов: 0 из {}", file_indices.len());
    }

    /// Забирает результаты фонового подписания и завершает операцию.
    fn poll_signing(&mut self, ctx: &egui::Context) {
        if self.sign_rx.is_none() {
            return;
        }
        let mut finished = false;
        let mut outcomes: Vec<SignOutcome> = Vec::new();
        if let Some(rx) = &self.sign_rx {
            loop {
                match rx.try_recv() {
                    Ok(outcome) => outcomes.push(outcome),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        finished = true;
                        break;
                    }
                }
            }
        }
        for outcome in outcomes {
            self.apply_sign_outcome(outcome);
        }

        if finished {
            self.sign_rx = None;
            self.finish_signing();
        } else {
            if let Some(state) = &mut self.signing {
                if state.started == 0.0 {
                    state.started = ctx.input(|i| i.time);
                }
            }
            ctx.request_repaint_after(Duration::from_millis(40));
        }
    }

    fn apply_sign_outcome(&mut self, outcome: SignOutcome) {
        let SignOutcome {
            idx,
            created,
            errors,
        } = outcome;

        if let Some(state) = &mut self.signing {
            state.done += 1;
            state.errors += errors.len();
        }

        if created.is_empty() {
            return;
        }

        let signed_at = chrono::Local::now()
            .format("%d.%m.%Y %H:%M")
            .to_string();
        if let Some(file) = self.files.get_mut(idx) {
            for (subject, path) in &created {
                file.signatures.push(SignatureInfo {
                    subject: subject.clone(),
                    path: Some(path.clone()),
                    signed_at: signed_at.clone(),
                });
            }
            file.status = FileStatus::Signed;

            if let Some(dir) = file.path.parent() {
                if let Some(state) = &mut self.signing {
                    if !state.dirs.iter().any(|d| d == dir) {
                        state.dirs.push(dir.to_path_buf());
                    }
                }
            }

            if self.pack_zip {
                let mut unique: Vec<(String, PathBuf)> = Vec::new();
                for (subject, path) in &created {
                    if !unique.iter().any(|(_, p)| p == path) {
                        unique.push((subject.clone(), path.clone()));
                    }
                }
                let zip_path = file.zip_path();
                let _ = write_zip(&zip_path, &unique);
            }
        }
    }

    fn finish_signing(&mut self) {
        let Some(state) = self.signing.take() else {
            return;
        };

        for cert in &state.temp_certs {
            let _ = std::fs::remove_file(cert);
        }

        let mut report_errors = 0;
        for dir in &state.dirs {
            if self.write_reports(dir).is_err() {
                report_errors += 1;
            }
        }
        if let Some(dir) = state.dirs.first() {
            self.last_signed_dir = Some(dir.clone());
        }

        let signed_sigs: usize = self
            .files
            .iter()
            .map(|f| f.signatures.len())
            .sum::<usize>();
        let signed_files = self
            .files
            .iter()
            .filter(|f| f.status == FileStatus::Signed)
            .count();

        let mut text = format!(
            "Подписано файлов: {} · подписей: {} · отчёты: {}",
            signed_files,
            signed_sigs,
            state.dirs.len()
        );
        if state.errors > 0 {
            text.push_str(&format!(" · ошибок: {}", state.errors));
        }
        if report_errors > 0 {
            text.push_str(&format!(" · ошибок отчётов: {}", report_errors));
        }
        self.message = text;
    }

    /// Строки отчёта по всем документам из указанной папки.
    fn report_rows(&self, folder: &Path) -> Vec<ReportRow> {
        let mut rows: Vec<ReportRow> = Vec::new();

        for file in &self.files {
            if file.path.parent() != Some(folder) {
                continue;
            }

            let size = format_size(file.size);
            let status = file.status.label().to_string();

            if file.signatures.is_empty() {
                rows.push(ReportRow {
                    file: file.name.clone(),
                    size,
                    status,
                    signer: "—".to_string(),
                    signature_file: "—".to_string(),
                    signature_hash: "—".to_string(),
                    signed_at: "—".to_string(),
                });
                continue;
            }

            for sig in &file.signatures {
                let signature_file = sig
                    .path
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "—".to_string());
                let signature_hash = sig
                    .path
                    .as_ref()
                    .map(|p| sha256_hex(p))
                    .unwrap_or_else(|| "—".to_string());

                rows.push(ReportRow {
                    file: file.name.clone(),
                    size: size.clone(),
                    status: status.clone(),
                    signer: sig.subject.clone(),
                    signature_file,
                    signature_hash,
                    signed_at: if sig.signed_at.is_empty() {
                        "—".to_string()
                    } else {
                        sig.signed_at.clone()
                    },
                });
            }
        }

        rows.sort_by(|a, b| {
            (a.file.to_lowercase(), a.signer.to_lowercase())
                .cmp(&(b.file.to_lowercase(), b.signer.to_lowercase()))
        });
        rows
    }

    /// Пишет TXT и XLSX отчёты в папку с документами.
    fn write_reports(&mut self, folder: &Path) -> Result<(), String> {
        let rows = self.report_rows(folder);
        if rows.is_empty() {
            return Ok(());
        }

        let txt = folder.join("Отчёт о подписях.txt");
        let xlsx = folder.join("Отчёт о подписях.xlsx");

        crate::report::write_txt(&txt, folder, &rows)
            .map_err(|e| format!("{}: {}", txt.display(), e))?;
        crate::report::write_xlsx(&xlsx, &rows)
            .map_err(|e| format!("{}: {}", xlsx.display(), e))?;
        Ok(())
    }

    fn delete_signature(&mut self) {
        let Some(idx) = self.active_file else {
            self.message = "Выберите документ".to_string();
            return;
        };
        let Some(file) = self.files.get(idx) else {
            return;
        };
        if file.signatures.is_empty() {
            self.message = "У файла нет подписей".to_string();
            return;
        }
        self.confirm_delete = true;
    }

    fn confirm_delete_dialog(&mut self, ctx: &egui::Context) {
        if !self.confirm_delete {
            return;
        }
        let mut open = true;
        egui::Window::new("delete_confirm")
            .title_bar(false)
            .resizable(false)
            .collapsible(false)
            .frame(egui::Frame::none())
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .open(&mut open)
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(BG_PANEL)
                    .rounding(Rounding::same(16.0))
                    .inner_margin(Margin::same(22.0))
                    .show(ui, |ui| {
                        ui.set_width(340.0);
                        ui.label(
                            RichText::new("Удалить подписи?")
                                .font(theme::medium(18.0))
                                .color(TEXT),
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(
                                "Файлы подписей .sig / .p7s будут удалены с диска без возможности восстановления.",
                            )
                            .font(theme::regular(12.5))
                            .color(TEXT_MUTED),
                        );
                        ui.add_space(16.0);
                        ui.horizontal(|ui| {
                            if danger_button(ui, "Удалить", 120.0).clicked() {
                                self.delete_signature_now();
                                self.confirm_delete = false;
                            }
                            if secondary_button(ui, "Отмена", Icon::Close).clicked() {
                                self.confirm_delete = false;
                            }
                        });
                    });
            });
        if !open {
            self.confirm_delete = false;
        }
    }

    /// Предупреждение о больших файлах перед подписанием.
    fn large_sign_dialog(&mut self, ctx: &egui::Context) {
        let Some(files) = self.large_sign_files.clone() else {
            return;
        };
        let mut open = true;
        egui::Window::new("large_sign_warning")
            .title_bar(false)
            .resizable(false)
            .collapsible(false)
            .frame(egui::Frame::none())
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .open(&mut open)
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(BG_PANEL)
                    .rounding(Rounding::same(16.0))
                    .inner_margin(Margin::same(22.0))
                    .show(ui, |ui| {
                        ui.set_width(430.0);
                        ui.label(
                            RichText::new("Большой файл")
                                .font(theme::medium(18.0))
                                .color(TEXT),
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(
                                "Размер файла превышает 50 МБ. Подписание может занять заметное время.",
                            )
                            .font(theme::regular(12.5))
                            .color(TEXT_MUTED),
                        );
                        ui.add_space(4.0);
                        if !self.detached {
                            ui.label(
                                RichText::new(
                                    "В режиме присоединённой подписи содержимое документа будет вложено в файл подписи — он станет больше исходного.",
                                )
                                .font(theme::regular(12.0))
                                .color(AMBER),
                            );
                        }
                        ui.add_space(10.0);
                        for file in files.iter().take(6) {
                            ui.label(
                                RichText::new(format!("• {}", file))
                                    .font(theme::regular(12.0))
                                    .color(TEXT_SOFT),
                            );
                        }
                        ui.add_space(16.0);
                        ui.horizontal(|ui| {
                            if accent_button(ui, "Подписать", Icon::Pen).clicked() {
                                self.large_sign_files = None;
                                self.sign_selected_now();
                            }
                            if secondary_button(ui, "Отмена", Icon::Close).clicked() {
                                self.large_sign_files = None;
                            }
                        });
                    });
            });
        if !open {
            self.large_sign_files = None;
        }
    }

    fn delete_signature_now(&mut self) {
        let Some(idx) = self.active_file else {
            return;
        };
        let Some(file) = self.files.get(idx).cloned() else {
            return;
        };
        let mut removed = 0;
        for sig in &file.signatures {
            if let Some(p) = &sig.path {
                if std::fs::remove_file(p).is_ok() {
                    removed += 1;
                }
            }
        }
        if let Some(f) = self.files.get_mut(idx) {
            f.signatures.clear();
            f.status = FileStatus::Pending;
        }
        // Обновляем отчёт в папке документа.
        if let Some(dir) = file.path.parent() {
            let dir = dir.to_path_buf();
            let _ = self.write_reports(&dir);
        }
        self.message = format!("Удалено подписей: {}", removed);
    }

    fn export_active(&mut self) {
        let Some(idx) = self.active_file else {
            self.message = "Выберите документ".to_string();
            return;
        };
        let Some(file) = self.files.get(idx).cloned() else {
            return;
        };
        let Some(target) = rfd::FileDialog::new()
            .set_file_name(&file.name)
            .set_title("Сохранить копию документа")
            .save_file()
        else {
            return;
        };
        match std::fs::copy(&file.path, &target) {
            Ok(_) => self.message = format!("Копия сохранена: {}", target.display()),
            Err(e) => self.message = format!("Ошибка сохранения: {}", e),
        }
    }

    fn verify_active(&mut self) {
        let Some(idx) = self.active_file else {
            self.message = "Выберите документ".to_string();
            return;
        };
        let Some(file) = self.files.get(idx).cloned() else {
            return;
        };
        let Some(sig) = file.existing_signature().cloned() else {
            self.message = "У документа нет файла подписи".to_string();
            return;
        };
        self.verify_pair(file.path.clone(), sig);
    }

    fn verify_pair(&mut self, file: PathBuf, sig: PathBuf) {
        if let Err(error) = verify_size_error(&file, &sig) {
            self.message = error;
            return;
        }

        let (ok, detail) = run_verify_cli(&self.cli_path(), &file, &sig);
        if ok {
            let renamed = self.rename_after_verify(&file, &sig, &detail);
            // Если подпись переименована — обновляем путь и в карточке документа,
            // иначе повторная проверка ищет старый файл.
            if let (Some(new_path), Some(idx)) = (
                renamed.clone(),
                self.files.iter().position(|f| f.path == file),
            ) {
                if let Some(entry) = self.files.get_mut(idx) {
                    for s in &mut entry.signatures {
                        if s.path.as_deref() == Some(sig.as_path()) {
                            s.path = Some(new_path.clone());
                        }
                    }
                }
            }
            if let Some(parent) = file.parent() {
                let parent = parent.to_path_buf();
                let _ = self.write_reports(&parent);
            }
            self.message = match renamed {
                Some(path) => format!(
                    "Подпись верна · файл подписи: {}",
                    file_display(&path)
                ),
                None => format!("Подпись верна · {}", file_display(&file)),
            };
        } else {
            self.message = format!("Подпись недействительна · {}", detail);
        }
    }

    /// После успешной проверки переименовывает подпись в
    /// `<имя документа>_<Фамилия_ИО>.<ext>`.
    fn rename_after_verify(
        &mut self,
        doc: &Path,
        sig: &Path,
        detail: &str,
    ) -> Option<PathBuf> {
        let owner = owner_from_verify_detail(detail)?;
        let stem = doc.file_stem().and_then(|s| s.to_str())?;
        if stem.is_empty() {
            return None;
        }
        let ext = sig.extension().and_then(|e| e.to_str()).unwrap_or("sig");
        let dir = sig.parent()?;

        let mut target = dir.join(format!("{}_{}.{}", stem, owner, ext));
        if target == sig {
            return None;
        }
        if target.exists() {
            let mut n = 2;
            loop {
                let candidate =
                    dir.join(format!("{}_{}_{}.{}", stem, owner, n, ext));
                if !candidate.exists() {
                    target = candidate;
                    break;
                }
                n += 1;
                if n > 999 {
                    return None;
                }
            }
        }

        if std::fs::rename(sig, &target).is_err() {
            return None;
        }

        for file in &mut self.files {
            for signature in &mut file.signatures {
                if signature.path.as_deref() == Some(sig) {
                    signature.path = Some(target.clone());
                }
            }
        }

        Some(target)
    }

    fn build_zip(&mut self, dir: PathBuf, indices: Vec<usize>) {
        let mut entries: Vec<(String, PathBuf)> = Vec::new();
        for idx in indices {
            let Some(f) = self.files.get(idx) else {
                continue;
            };
            for sig in &f.signatures {
                if let Some(p) = &sig.path {
                    if p.exists() {
                        let name = p
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        entries.push((name, p.clone()));
                    }
                }
            }
        }
        if entries.is_empty() {
            self.message = "Нет подписей для архива".to_string();
            return;
        }

        let zip_path = dir.join("cryptoline_signatures.zip");
        match write_zip(&zip_path, &entries) {
            Ok(()) => self.message = format!("Архив создан: {}", zip_path.display()),
            Err(e) => self.message = format!("Ошибка создания архива: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// Разбор DN
// ---------------------------------------------------------------------------/// Делит DN по запятым, не трогая запятые внутри кавычек и после `\`.
fn split_dn(dn: &str) -> Vec<&str> {
    let bytes = dn.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                parts.push(&dn[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&dn[start..]);
    parts
}

/// Снимает обрамляющие кавычки и раскрывает удвоенные (`""` → `"`).
fn unquote_dn_value(raw: &str) -> String {
    let value = raw.trim();
    let inner = if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        &value[1..value.len() - 1]
    } else {
        value
    };
    inner.replace("\"\"", "\"").trim().to_string()
}

/// Точки контура скруглённого прямоугольника (по часовой стрелке).
fn rounded_rect_path(rect: Rect, r: f32) -> Vec<Pos2> {
    use std::f32::consts::{FRAC_PI_2, PI};
    let mut pts = Vec::new();
    let r = r.min(rect.width() / 2.0).min(rect.height() / 2.0).max(0.0);
    let corners = [
        (Pos2::new(rect.right() - r, rect.top() + r), -FRAC_PI_2),
        (Pos2::new(rect.right() - r, rect.bottom() - r), 0.0),
        (Pos2::new(rect.left() + r, rect.bottom() - r), FRAC_PI_2),
        (Pos2::new(rect.left() + r, rect.top() + r), PI),
    ];
    for (c, start) in corners {
        for i in 0..=8 {
            let a = start + FRAC_PI_2 * (i as f32 / 8.0);
            pts.push(Pos2::new(c.x + r * a.cos(), c.y + r * a.sin()));
        }
    }
    if let Some(first) = pts.first().copied() {
        pts.push(first);
    }
    pts
}

/// Цвет с масштабированной прозрачностью.
fn fade_col(c: Color32, f: f32) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), (c.a() as f32 * f.clamp(0.0, 1.0)) as u8)
}

/// Линейная интерполяция цвета (t = 0..1).
fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    Color32::from_rgba_unmultiplied(
        mix(a.r(), b.r()),
        mix(a.g(), b.g()),
        mix(a.b(), b.b()),
        mix(a.a(), b.a()),
    )
}

/// Смешивает три цвета по весам — для плавной смены статуса.
fn blend_status(a: Color32, b: Color32, c: Color32, wa: f32, wb: f32, wc: f32) -> Color32 {
    let total = (wa + wb + wc).max(0.001);
    let mix = |x: u8, y: u8, z: u8| {
        ((x as f32 * wa + y as f32 * wb + z as f32 * wc) / total) as u8
    };
    Color32::from_rgb(
        mix(a.r(), b.r(), c.r()),
        mix(a.g(), b.g(), c.g()),
        mix(a.b(), b.b(), c.b()),
    )
}

// ---------------------------------------------------------------------------
// Мелкие виджеты
// ---------------------------------------------------------------------------

fn truncated(
    ui: &Ui,
    text: &str,
    font: FontId,
    color: Color32,
    max_width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::single_section(
        text.to_owned(),
        egui::TextFormat {
            font_id: font,
            color,
            ..Default::default()
        },
    );
    job.wrap.max_width = max_width;
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    job.wrap.overflow_character = Some('…');
    ui.fonts(|f| f.layout_job(job))
}

/// Строка списка с отметкой выбора — для экрана шифрования.
fn list_row(ui: &mut Ui, selected: bool, title: &str, subtitle: &str) -> Response {
    let (rect, resp) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), 52.0),
        Sense::click(),
    );
    let p = ui.painter();
    p.rect_filled(
        rect,
        Rounding::same(10.0),
        if resp.hovered() { BG_CARD_HOVER } else { BG_CARD },
    );
    p.text(
        Pos2::new(rect.left() + 14.0, rect.center().y - 8.0),
        Align2::LEFT_CENTER,
        title,
        theme::medium(13.0),
        TEXT,
    );
    p.text(
        Pos2::new(rect.left() + 14.0, rect.center().y + 9.0),
        Align2::LEFT_CENTER,
        subtitle,
        theme::regular(11.5),
        TEXT_MUTED,
    );
    let c = Pos2::new(rect.right() - 20.0, rect.center().y);
    p.circle_filled(c, 9.0, if selected { ACCENT } else { BG_SUNKEN });
    p.circle_stroke(
        c,
        9.0,
        Stroke::new(1.2, if selected { ACCENT } else { DIVIDER }),
    );
    if selected {
        p.add(egui::Shape::line(
            vec![
                Pos2::new(c.x - 4.0, c.y + 0.5),
                Pos2::new(c.x - 1.0, c.y + 3.5),
                Pos2::new(c.x + 4.5, c.y - 3.0),
            ],
            Stroke::new(1.8, Color32::WHITE),
        ));
    }
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn icon_button(ui: &mut Ui, icon: Icon, size: f32) -> Response {    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
    let p = ui.painter();
    if resp.hovered() {
        p.rect_filled(rect, Rounding::same(9.0), BG_CARD_HOVER);
    }
    icons::paint(
        p,
        Rect::from_center_size(rect.center(), Vec2::splat(size * 0.52)),
        icon,
        if resp.hovered() { TEXT } else { TEXT_MUTED },
        1.7,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn round_add_button(ui: &mut Ui, diameter: f32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(diameter), Sense::click());
    let p = ui.painter();
    let hover = ui
        .ctx()
        .animate_bool_with_time(ui.id().with("add_hover"), resp.hovered(), 0.12);
    let d = diameter * (1.0 + 0.05 * hover);
    paint_round_shadow(p, rect.center(), d / 2.0);
    p.circle_filled(
        rect.center(),
        d / 2.0,
        lerp_color(ACCENT, ACCENT_HOVER, hover),
    );
    icons::paint(
        p,
        Rect::from_center_size(rect.center(), Vec2::splat(d * 0.44)),
        Icon::Plus,
        Color32::WHITE,
        2.0,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Кнопка подписания в состоянии «идёт подписание» — вращающийся индикатор.
fn sign_spinner(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(58.0), Sense::hover());
    let p = ui.painter();
    let c = rect.center();
    paint_round_shadow(p, c, 29.0);
    p.circle_filled(c, 29.0, ACCENT);
    let t = ui.input(|i| i.time) as f32 * 5.0;
    for i in 0..8 {
        let a = t + i as f32 * 0.55;
        let alpha = 30 + i as u32 * 26;
        let r = 21.0;
        p.circle_filled(
            Pos2::new(c.x + r * a.cos(), c.y + r * a.sin()),
            2.5,
            Color32::from_rgba_unmultiplied(255, 255, 255, alpha.min(255) as u8),
        );
    }
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(33));
}

fn action_button(ui: &mut Ui, icon: Icon) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(58.0), Sense::click());
    let p = ui.painter();

    // Наведение — мягкое увеличение, нажатие — тактильное сжатие.
    let hover = ui
        .ctx()
        .animate_bool_with_time(ui.id().with("sign_hover"), resp.hovered(), 0.12);
    let pressed = resp.is_pointer_button_down_on();
    let scale = if pressed { 0.95 } else { 1.0 + 0.05 * hover };
    let radius = 29.0 * scale;

    paint_round_shadow(p, rect.center(), radius);
    p.circle_filled(
        rect.center(),
        radius,
        lerp_color(ACCENT, ACCENT_HOVER, hover),
    );
    icons::paint(
        p,
        Rect::from_center_size(rect.center(), Vec2::splat(24.0 * scale)),
        icon,
        Color32::WHITE,
        2.0,
    );

    // Мягкая пульсация готовности к подписанию.
    let time = ui.input(|i| i.time) as f32;
    let pulse = (time * 2.2).sin() * 0.5 + 0.5;
    p.circle_stroke(
        rect.center(),
        radius + 2.0 + pulse * 5.0,
        Stroke::new(
            1.4,
            Color32::from_rgba_unmultiplied(0x4B, 0x6B, 0xFB, (46.0 * (1.0 - pulse)) as u8),
        ),
    );
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(50));

    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Аккуратная круглая тень: тёмная снизу + едва заметное свечение акцента.
/// Раньше использовался размытый прямоугольник — вокруг круглой кнопки
/// появлялось квадратное пятно.
fn paint_round_shadow(p: &egui::Painter, center: Pos2, radius: f32) {
    for i in 0..4 {
        let alpha = 34 - i * 9;
        let r = radius + 1.0 + i as f32 * 1.6;
        p.circle_filled(
            center + Vec2::new(0.0, 3.0 + i as f32 * 1.4),
            r,
            Color32::from_black_alpha(alpha as u8),
        );
    }
    for i in 0..3 {
        let alpha = 12 - i * 4;
        let r = radius + 2.0 + i as f32 * 2.2;
        p.circle_filled(
            center + Vec2::new(0.0, 2.0),
            r,
            Color32::from_rgba_unmultiplied(0x4B, 0x6B, 0xFB, alpha as u8),
        );
    }
}

/// Нативный ресайз через Win32: одна атомарная операция, без «прыжков»
/// между InnerSize и OuterPosition.
fn resize_native(
    ctx: &egui::Context,
    dir: egui::viewport::ResizeDirection,
    start_rect: (i32, i32, i32, i32),
    start_cursor: (i32, i32),
    cursor: (i32, i32),
) {
    use egui::viewport::ResizeDirection as R;

    let (sx, sy, sw, sh) = start_rect;
    let dx = cursor.0 - start_cursor.0;
    let dy = cursor.1 - start_cursor.1;

    let mut x = sx;
    let mut y = sy;
    let mut w = sw;
    let mut h = sh;

    match dir {
        R::East => w += dx,
        R::West => {
            w -= dx;
            x += dx;
        }
        R::South => h += dy,
        R::North => {
            h -= dy;
            y += dy;
        }
        R::NorthEast => {
            w += dx;
            h -= dy;
            y += dy;
        }
        R::NorthWest => {
            w -= dx;
            x += dx;
            h -= dy;
            y += dy;
        }
        R::SouthEast => {
            w += dx;
            h += dy;
        }
        R::SouthWest => {
            w -= dx;
            x += dx;
            h += dy;
        }
    }

    let ppp = ctx.pixels_per_point();
    let min_w = (1120.0 * ppp) as i32;
    let min_h = (700.0 * ppp) as i32;

    if w < min_w {
        if matches!(
            dir,
            R::West | R::NorthWest | R::SouthWest
        ) {
            x = sx + sw - min_w;
        }
        w = min_w;
    }
    if h < min_h {
        if matches!(
            dir,
            R::North | R::NorthEast | R::NorthWest
        ) {
            y = sy + sh - min_h;
        }
        h = min_h;
    }

    crate::win::set_window_rect(x, y, w, h);
}

fn folder_button(ui: &mut Ui) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(138.0, 28.0), Sense::click());
    let p = ui.painter();
    if resp.hovered() {
        p.rect_filled(rect, Rounding::same(8.0), BG_CARD_HOVER);
    }
    icons::paint(
        p,
        Rect::from_center_size(
            Pos2::new(rect.left() + 15.0, rect.center().y),
            Vec2::splat(14.0),
        ),
        Icon::Folder,
        if resp.hovered() { TEXT } else { ACCENT },
        1.5,
    );
    p.text(
        Pos2::new(rect.left() + 27.0, rect.center().y),
        Align2::LEFT_CENTER,
        "Открыть папку",
        theme::regular(12.0),
        if resp.hovered() { TEXT } else { ACCENT },
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Кнопка на полосе заголовка — как в мессенджерах: без скругления,
/// прямоугольная зона 46×34, у «закрыть» красная подсветка.
fn caption_button(ui: &mut Ui, icon: Icon, danger: bool) -> Response {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(CAPTION_BUTTON_W, CAPTION_BUTTON_H), Sense::click());
    let p = ui.painter();
    if resp.hovered() {
        p.rect_filled(
            rect,
            Rounding::ZERO,
            if danger {
                Color32::from_rgb(0xE0, 0x45, 0x45)
            } else {
                BG_CARD_HOVER
            },
        );
    }
    icons::paint(
        p,
        Rect::from_center_size(rect.center(), Vec2::splat(10.0)),
        icon,
        if resp.hovered() { TEXT } else { TEXT_SOFT },
        1.2,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Кнопка меню: сворачивает и разворачивает боковую панель.
fn menu_button(ui: &mut Ui, active: bool) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(34.0), Sense::click());
    let p = ui.painter();
    if resp.hovered() {
        p.rect_filled(rect, Rounding::same(9.0), BG_CARD_HOVER);
    }
    icons::paint(
        p,
        Rect::from_center_size(rect.center(), Vec2::splat(17.0)),
        Icon::Menu,
        if resp.hovered() || active { TEXT } else { TEXT_MUTED },
        1.7,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}fn danger_button(ui: &mut Ui, label: &str, width: f32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 38.0), Sense::click());
    let p = ui.painter();
    p.rect_filled(
        rect,
        Rounding::same(10.0),
        if resp.hovered() {
            Color32::from_rgb(0xF0, 0x6B, 0x6B)
        } else {
            RED
        },
    );
    p.text(
        rect.center(),
        Align2::CENTER_CENTER,
        label,
        theme::regular(13.5),
        Color32::WHITE,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn accent_button(ui: &mut Ui, label: &str, icon: Icon) -> Response {
    let text_w = ui.fonts(|f| {
        f.layout_no_wrap(label.to_string(), theme::regular(13.5), Color32::WHITE)
            .size()
            .x
    });
    let width = (text_w + 60.0).clamp(150.0, 320.0);
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 40.0), Sense::click());
    let p = ui.painter();
    let fill = if resp.hovered() { ACCENT_HOVER } else { ACCENT };
    p.rect_filled(rect, Rounding::same(10.0), fill);
    icons::paint(
        p,
        Rect::from_center_size(
            Pos2::new(rect.left() + 24.0, rect.center().y),
            Vec2::splat(16.0),
        ),
        icon,
        Color32::WHITE,
        1.7,
    );
    p.text(
        Pos2::new(rect.left() + 40.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        theme::regular(13.5),
        Color32::WHITE,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn secondary_button(ui: &mut Ui, label: &str, icon: Icon) -> Response {
    let width = ui
        .fonts(|f| {
            f.layout_no_wrap(label.to_string(), theme::regular(13.5), TEXT_SOFT)
                .size()
                .x
        })
        + 58.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 40.0), Sense::click());
    let p = ui.painter();
    p.rect_filled(
        rect,
        Rounding::same(10.0),
        if resp.hovered() { BG_CARD_HOVER } else { BG_SUNKEN },
    );
    icons::paint(
        p,
        Rect::from_center_size(
            Pos2::new(rect.left() + 22.0, rect.center().y),
            Vec2::splat(16.0),
        ),
        icon,
        if resp.hovered() { TEXT } else { TEXT_MUTED },
        1.7,
    );
    p.text(
        Pos2::new(rect.left() + 38.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        theme::regular(13.5),
        TEXT_SOFT,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn count_badge(ui: &mut Ui, n: usize) {
    let text = n.to_string();
    let width = if n > 99 { 30.0 } else { 23.0 };
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 23.0), Sense::hover());
    let p = ui.painter();
    p.circle_filled(rect.center(), 11.5, ACCENT);
    p.text(
        rect.center(),
        Align2::CENTER_CENTER,
        text,
        theme::medium(11.5),
        Color32::WHITE,
    );
}

fn sort_combo(ui: &mut Ui, sort: &mut SortMode) {
    let id = egui::Id::new("sort_mode_popup");
    let resp = dropdown_button(ui, sort.label(), 118.0, false);
    if resp.clicked() {
        ui.memory_mut(|m| m.open_popup(id));
    }
    egui::popup_below_widget(ui, id, &resp, |ui| {
        ui.set_min_width(112.0);
        for s in [SortMode::Recent, SortMode::Name, SortMode::Size] {
            if ui
                .selectable_label(
                    *sort == s,
                    RichText::new(s.label()).font(theme::regular(13.0)),
                )
                .clicked()
            {
                *sort = s;
                ui.memory_mut(|m| m.close_popup());
            }
        }
    });
}

/// Кнопка-селектор с нарисованным шевроном и всплывающим списком.
fn dropdown_button(ui: &mut Ui, label: &str, width: f32, filled: bool) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 34.0), Sense::click());
    let p = ui.painter();
    let bg = if filled {
        if resp.hovered() {
            BG_CARD_HOVER
        } else {
            Color32::from_rgb(0x3B, 0x3F, 0x52)
        }
    } else if resp.hovered() {
        BG_CARD_HOVER
    } else {
        Color32::TRANSPARENT
    };
    p.rect_filled(rect, Rounding::same(9.0), bg);
    p.text(
        Pos2::new(rect.left() + 11.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        theme::regular(13.0),
        if filled { TEXT } else { TEXT_MUTED },
    );
    icons::paint(
        p,
        Rect::from_center_size(
            Pos2::new(rect.right() - 13.0, rect.center().y),
            Vec2::splat(11.0),
        ),
        Icon::ChevronDown,
        TEXT_MUTED,
        1.5,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn format_combo(ui: &mut Ui, format: &mut SigFormat, width: f32) {
    let id = egui::Id::new("sig_format_popup");
    let resp = dropdown_button(ui, format.label(), width, true);
    if resp.clicked() {
        ui.memory_mut(|m| m.open_popup(id));
    }
    egui::popup_below_widget(ui, id, &resp, |ui| {
        ui.set_min_width(width - 12.0);
        for f in [SigFormat::Sig, SigFormat::P7s] {
            if ui
                .selectable_label(
                    *format == f,
                    RichText::new(f.label()).font(theme::regular(13.0)),
                )
                .clicked()
            {
                *format = f;
                ui.memory_mut(|m| m.close_popup());
            }
        }
    });
}

fn encoding_combo(ui: &mut Ui, encoding: &mut SigEncoding, width: f32) {
    let id = egui::Id::new("sig_encoding_popup");
    let resp = dropdown_button(ui, encoding.label(), width, true);
    if resp.clicked() {
        ui.memory_mut(|m| m.open_popup(id));
    }
    egui::popup_below_widget(ui, id, &resp, |ui| {
        ui.set_min_width(width - 12.0);
        for e in [SigEncoding::Base64, SigEncoding::Der] {
            if ui
                .selectable_label(
                    *encoding == e,
                    RichText::new(e.label()).font(theme::regular(13.0)),
                )
                .clicked()
            {
                *encoding = e;
                ui.memory_mut(|m| m.close_popup());
            }
        }
    });
}

fn toggle_row(ui: &mut Ui, value: &mut bool, label: &str) -> Response {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 30.0), Sense::click());
    let p = ui.painter();
    let track = Rect::from_min_size(
        Pos2::new(rect.left(), rect.center().y - 10.0),
        Vec2::new(36.0, 20.0),
    );
    // Плавное скольжение бегунка и перелив цвета трека.
    let t = ui
        .ctx()
        .animate_bool_with_time(egui::Id::new(("toggle", label)), *value, 0.2);
    p.rect_filled(
        track,
        Rounding::same(10.0),
        lerp_color(Color32::from_rgb(0x4A, 0x4E, 0x5F), ACCENT, t),
    );
    let knob_x = track.left() + 10.0 + (track.width() - 20.0) * t;
    p.circle_filled(Pos2::new(knob_x, track.center().y), 7.0, Color32::WHITE);
    p.text(
        Pos2::new(track.right() + 12.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        theme::regular(13.5),
        lerp_color(TEXT_SOFT, TEXT, if resp.hovered() { 1.0 } else { t * 0.4 }),
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    if resp.clicked() {
        *value = !*value;
    }
    resp
}

fn small_close(ui: &mut Ui) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::click());
    let p = ui.painter();
    if resp.hovered() {
        p.circle_filled(rect.center(), 8.0, Color32::from_rgb(0x4A, 0x4E, 0x62));
    }
    icons::paint(
        p,
        Rect::from_center_size(rect.center(), Vec2::splat(9.0)),
        Icon::Close,
        if resp.hovered() { TEXT } else { TEXT_MUTED },
        1.4,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn check_mark(ui: &mut Ui, checked: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
    let p = ui.painter();
    if checked {
        p.circle_filled(rect.center(), 11.0, ACCENT);
        icons::paint(
            p,
            Rect::from_center_size(rect.center(), Vec2::splat(12.0)),
            Icon::Check,
            Color32::WHITE,
            1.8,
        );
    } else {
        p.circle_stroke(
            rect.center(),
            10.0,
            Stroke::new(1.4_f32, Color32::from_rgb(0x55, 0x59, 0x6C)),
        );
    }
}

fn avatar(ui: &mut Ui, name: &str, sub: &str, valid: &str) {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(44.0), Sense::hover());
    let p = ui.painter();
    p.circle_filled(rect.center(), 22.0, avatar_color(name));
    p.text(
        rect.center(),
        Align2::CENTER_CENTER,
        initials(name),
        theme::medium(13.5),
        Color32::WHITE,
    );
    let badge = Pos2::new(rect.right() - 5.0, rect.bottom() - 5.0);
    p.circle_filled(badge, 8.0, BG_CARD);
    p.circle_filled(badge, 6.0, GREEN);
    icons::paint(
        p,
        Rect::from_center_size(badge, Vec2::splat(8.0)),
        Icon::Check,
        Color32::WHITE,
        1.2,
    );

    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }

    // Белая подсказка плавно проявляется: opacity 0→1, scale 0.96→1.
    let tip = ui.ctx().animate_bool_with_time(
        egui::Id::new(("signer_hover", name, sub)),
        resp.hovered(),
        0.16,
    );
    if tip > 0.01 {
        let id = egui::Id::new(("signer_tip", name, sub));
        egui::Area::new(id)
            .order(egui::Order::Tooltip)
            .pivot(egui::Align2::LEFT_CENTER)
            .fixed_pos(Pos2::new(rect.right() + 10.0, rect.center().y))
            .interactable(false)
            .show(ui.ctx(), |ui| {
                egui::Frame::none()
                    .fill(fade_col(Color32::WHITE, tip))
                    .rounding(Rounding::same(10.0))
                    .shadow(theme::soft_shadow())
                    .inner_margin(Margin {
                        left: 14.0,
                        right: 14.0,
                        top: 10.0,
                        bottom: 10.0,
                    })
                    .show(ui, |ui| {
                        ui.set_max_width(260.0 * (0.96 + 0.04 * tip));
                        ui.label(
                            RichText::new(name)
                                .font(theme::medium(14.0))
                                .color(fade_col(Color32::from_rgb(0x1F, 0x22, 0x2E), tip)),
                        );
                        ui.label(
                            RichText::new(format!("Сертификат · {}", sub))
                                .font(theme::regular(12.0))
                                .color(fade_col(Color32::from_rgb(0x6B, 0x6F, 0x82), tip)),
                        );
                        if !valid.is_empty() {
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(format!("Действителен до: {}", valid))
                                    .font(theme::regular(12.0))
                                    .color(fade_col(Color32::from_rgb(0x3B, 0x3F, 0x50), tip)),
                            );
                        }
                    });
            });
    }
}

fn related_files(ui: &mut Ui, file: &FileEntry) {
    ui.horizontal(|ui| {
        file_badge(ui, file.kind.label(), file.kind.color());
        if let Some(sig) = file.existing_signature() {
            let ext = sig
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("sig")
                .to_uppercase();
            file_badge(ui, &format!(".{}", ext), ACCENT);
        }
        if file.zip_path().exists() {
            file_badge(ui, ".ZIP", ZIP_YELLOW);
        }
    });
}

fn file_badge(ui: &mut Ui, label: &str, color: Color32) {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
    let lift = ui.ctx().animate_bool_with_time(
        egui::Id::new(("badge_hover", label)),
        resp.hovered(),
        0.16,
    );
    let p = ui.painter();
    let rect = rect.translate(Vec2::new(0.0, -2.0 * lift));
    if lift > 0.02 {
        p.add(egui::Shape::Mesh(
            theme::soft_shadow().tessellate(rect, Rounding::same(11.0)),
        ));
    }
    p.rect_filled(rect, Rounding::same(11.0), color);
    p.text(
        rect.center(),
        Align2::CENTER_CENTER,
        label,
        FontId::new(10.0, theme::medium_family()),
        Color32::WHITE,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
}

fn meta_row(ui: &mut Ui, label: &str, value: &str, value_color: Color32, mono: bool) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [100.0, 18.0],
            egui::Label::new(
                RichText::new(label)
                    .font(theme::regular(12.5))
                    .color(TEXT_MUTED),
            ),
        );
        let value_w = (ui.available_width() - 6.0).max(60.0);
        let text = if mono {
            RichText::new(value).font(theme::mono(11.5))
        } else {
            RichText::new(value).font(theme::regular(13.0))
        };
        ui.allocate_ui_with_layout(
            Vec2::new(value_w, 18.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.add(egui::Label::new(text.color(value_color)).truncate(true));
            },
        )
        .response
        .on_hover_text(value);
    });
}

fn page_header(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.add_space(6.0);
    ui.label(
        RichText::new(title)
            .font(theme::medium(25.0))
            .color(TEXT),
    );
    ui.add_space(4.0);
    ui.label(
        RichText::new(subtitle)
            .font(theme::regular(13.0))
            .color(TEXT_MUTED),
    );
}

fn empty_panel(ui: &mut Ui, icon: Icon, title: &str, hint: &str) {
    ui.add_space(50.0);
    ui.vertical_centered(|ui| {
        let (r, _) = ui.allocate_exact_size(Vec2::splat(76.0), Sense::hover());
        let p = ui.painter();
        p.circle_filled(r.center(), 38.0, BG_CARD);
        icons::paint(
            p,
            Rect::from_center_size(r.center(), Vec2::splat(30.0)),
            icon,
            TEXT_MUTED,
            1.6,
        );
        ui.add_space(14.0);
        ui.label(
            RichText::new(title)
                .font(theme::medium(16.0))
                .color(TEXT_SOFT),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new(hint)
                .font(theme::regular(13.0))
                .color(TEXT_MUTED),
        );
    });
}

fn setting_row(ui: &mut Ui, label: &str, value: &str, ok: bool) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [140.0, 18.0],
            egui::Label::new(
                RichText::new(label)
                    .font(theme::regular(12.5))
                    .color(TEXT_MUTED),
            ),
        );
        ui.label(
            RichText::new(value)
                .font(theme::mono(11.5))
                .color(TEXT_SOFT),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(if ok { "OK" } else { "нет" })
                    .font(theme::medium(11.5))
                    .color(if ok { GREEN } else { RED }),
            );
        });
    });
}

// ---------------------------------------------------------------------------
// Утилиты
// ---------------------------------------------------------------------------

/// SHA-256 файла подписи в hex; «—», если файл недоступен.
fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    match std::fs::read(path) {
        Ok(data) => Sha256::digest(&data)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect(),
        Err(_) => "—".to_string(),
    }
}

/// Открывает папку в системном файловом менеджере.
fn open_in_explorer(path: &Path) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer").arg(path).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.1} ГБ", b / GB).replace('.', ",")
    } else if b >= MB {
        format!("{:.1} МБ", b / MB).replace('.', ",")
    } else if b >= KB {
        format!("{:.0} КБ", b / KB)
    } else {
        format!("{} Б", bytes)
    }
}

fn initials(name: &str) -> String {
    let mut out = String::new();
    for word in name.split_whitespace().take(2) {
        if let Some(c) = word.chars().find(|c| c.is_alphabetic()) {
            out.extend(c.to_uppercase());
        }
    }
    if out.is_empty() {
        "?".to_string()
    } else {
        out
    }
}

fn avatar_color(name: &str) -> Color32 {
    let sum: u32 = name.bytes().map(|b| b as u32).sum();
    const PALETTE: [Color32; 4] = [ACCENT, PURPLE, TEAL, Color32::from_rgb(0x4F, 0x8E, 0xF7)];
    PALETTE[(sum as usize) % PALETTE.len()]
}

fn file_display(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

const UPDATE_MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/cherneyivan-cloud/prosto-podpis-updates/main/latest.json";

/// Загружает манифест обновлений (curl, при отсутствии — PowerShell).
fn fetch_update_manifest() -> Option<String> {
    // ?t= — чтобы CDN GitHub не отдавал закэшированный манифест.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let url = format!("{}?t={}", UPDATE_MANIFEST_URL, stamp);
    if let Ok(output) = std::process::Command::new("curl.exe")
        .args(["-s", "-L", "--max-time", "10", &url])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }

    let temp = std::env::temp_dir().join("prosto_podpis_update.json");
    let script = format!(
        "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri '{}' -TimeoutSec 10 -OutFile '{}'",
        url,
        temp.display()
    );
    let ok = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if ok {
        let text = std::fs::read_to_string(&temp).ok();
        let _ = std::fs::remove_file(&temp);
        return text
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
    }
    None
}

fn json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn version_is_newer(latest: &str, current: &str) -> bool {
    let parse = |value: &str| -> Vec<u32> {
        value
            .trim_start_matches('v')
            .split('.')
            .map(|part| part.parse::<u32>().unwrap_or(0))
            .collect()
    };
    let latest = parse(latest);
    let current = parse(current);
    for index in 0..latest.len().max(current.len()) {
        let left = *latest.get(index).unwrap_or(&0);
        let right = *current.get(index).unwrap_or(&0);
        if left != right {
            return left > right;
        }
    }
    false
}

fn open_external(url: &str) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer").arg(url).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

/// Файл подписи по расширению.
fn is_signature_path(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .as_deref(),
        Some("sig") | Some("p7s") | Some("sgn")
    )
}

/// Ищет файлы подписи, которые уже лежат рядом с документом.
///
/// Подходят `<имя>.pdf.sig`, `<имя>.sig` и `<имя>_Фамилия_ИО.sig` —
/// последний вариант появляется после переименования при проверке.
fn find_signatures_for(doc: &Path) -> Vec<SignatureInfo> {
    let mut out = Vec::new();
    let (Some(dir), Some(stem), Some(full)) = (
        doc.parent(),
        doc.file_stem().and_then(|s| s.to_str()),
        doc.file_name().and_then(|s| s.to_str()),
    ) else {
        return out;
    };

    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() || !is_signature_path(&path) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let is_pair = name == format!("{}.sig", full)
            || name == format!("{}.p7s", full)
            || name == format!("{}.sgn", full)
            || name == format!("{}.sig", stem)
            || name == format!("{}.p7s", stem)
            || name == format!("{}.sgn", stem)
            || name.starts_with(&format!("{}_", stem));
        if !is_pair {
            continue;
        }

        let base = name
            .trim_end_matches(".sig")
            .trim_end_matches(".p7s")
            .trim_end_matches(".sgn");
        let subject = base
            .strip_prefix(&format!("{}_", stem))
            .map(|s| s.replace('_', " "))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Подпись".to_string());

        let signed_at = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .map(|t| {
                let dt: chrono::DateTime<chrono::Local> = t.into();
                dt.format("%d.%m.%Y · %H:%M").to_string()
            })
            .unwrap_or_else(|_| "—".to_string());

        out.push(SignatureInfo {
            subject,
            path: Some(path),
            signed_at,
        });
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Ключ имени для сопоставления: без расширений, только буквы и цифры.
fn verify_name_key(path: &Path, is_signature: bool) -> String {
    alnum(&strip_name(path, is_signature))
}

/// Варианты ключа подписи: полный и без хвоста `_Фамилия_ИО`,
/// который программа дописывает после успешной проверки.
fn verify_name_candidates(path: &Path) -> Vec<String> {
    let base = strip_name(path, true);
    let mut out = vec![alnum(&base)];
    let mut current = base;
    for _ in 0..2 {
        match current.rfind('_') {
            Some(pos) => {
                current.truncate(pos);
                out.push(alnum(&current));
            }
            None => break,
        }
    }
    out
}

fn alnum(value: &str) -> String {
    value.chars().filter(|ch| ch.is_alphanumeric()).collect()
}

/// Имя без расширения подписи и расширения документа.
fn strip_name(path: &Path, is_signature: bool) -> String {
    let mut name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    if is_signature {
        for ext in [".sig", ".p7s", ".sgn"] {
            if name.ends_with(ext) {
                name.truncate(name.len() - ext.len());
                break;
            }
        }
    }
    for ext in [
        ".pdf", ".docx", ".doc", ".xml", ".txt", ".rtf", ".odt", ".xlsx", ".xls", ".zip",
    ] {
        if name.ends_with(ext) {
            name.truncate(name.len() - ext.len());
            break;
        }
    }
    name
}

/// Сходство строк 0..1 по Левенштейну.
fn name_similarity(a: &str, b: &str) -> f32 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let max_len = a_chars.len().max(b_chars.len());
    if max_len == 0 {
        return 1.0;
    }
    let distance = levenshtein(&a_chars, &b_chars);
    1.0 - distance as f32 / max_len as f32
}

fn levenshtein(a: &[char], b: &[char]) -> usize {
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];

    for (i, a_char) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, b_char) in b.iter().enumerate() {
            let cost = if a_char == b_char { 0 } else { 1 };
            current[j + 1] = (previous[j + 1] + 1)
                .min(current[j] + 1)
                .min(previous[j] + cost);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[b.len()]
}

/// Строгий лимит проверки: документ и файл подписи не больше 80 МБ.
fn verify_size_error(doc: &Path, sig: &Path) -> Result<(), String> {
    for (path, label) in [(doc, "Документ"), (sig, "Файл подписи")] {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > VERIFY_MAX_BYTES {
                return Err(format!(
                    "{} больше 80 МБ — строгая проверка не выполняется: {}",
                    label,
                    file_display(path)
                ));
            }
        }
    }
    Ok(())
}

/// Владелец подписи из вывода verify: «Фамилия_ИО».
fn owner_from_verify_detail(detail: &str) -> Option<String> {
    let line = detail
        .lines()
        .find(|line| line.contains("SURNAME=") || line.contains("CN="))?;

    let surname = field_value(line, "SURNAME=");
    let given = field_value(line, "GIVENNAME=");
    let cn = field_value(line, "CN=").unwrap_or_default();

    let (surname, given) = match (surname, given) {
        (Some(surname), Some(given)) => (surname, given),
        (Some(surname), None) => {
            let words: Vec<&str> = cn.split_whitespace().collect();
            let given = if words.len() > 1 {
                words[1..].join(" ")
            } else {
                String::new()
            };
            (surname, given)
        }
        (None, Some(given)) => {
            let surname = cn.split_whitespace().next()?.to_string();
            (surname, given)
        }
        (None, None) => {
            if cn.is_empty() {
                return None;
            }
            let words: Vec<&str> = cn.split_whitespace().collect();
            let surname = words.first()?.to_string();
            let given = if words.len() > 1 {
                words[1..].join(" ")
            } else {
                String::new()
            };
            (surname, given)
        }
    };

    let surname = owner_title(&surname);
    if surname.is_empty() {
        return None;
    }

    let initials: String = given
        .split_whitespace()
        .filter_map(|word| word.chars().find(|ch| ch.is_alphabetic()))
        .take(2)
        .map(|ch| ch.to_uppercase().to_string())
        .collect();

    if initials.is_empty() {
        Some(surname)
    } else {
        Some(format!("{}_{}", surname, initials))
    }
}

fn field_value(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let end = rest.find(',').unwrap_or(rest.len());
    let value = rest[..end].trim().trim_matches('"').to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn owner_title(value: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;
    for ch in value.trim().chars() {
        if ch.is_alphabetic() {
            if capitalize {
                out.extend(ch.to_uppercase());
                capitalize = false;
            } else {
                out.extend(ch.to_lowercase());
            }
        } else {
            out.push(ch);
            if ch == '-' || ch == ' ' {
                capitalize = true;
            }
        }
    }
    out.trim_matches('"').trim().to_string()
}

fn run_verify_cli(cli: &Path, file: &Path, sig: &Path) -> (bool, String) {
    let run = |sig_path: &Path| match std::process::Command::new(cli)
        .arg("verify")
        .arg("--file")
        .arg(file)
        .arg("--signature")
        .arg(sig_path)
        .output()
    {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let detail = if stdout.is_empty() { stderr } else { stdout };
            (out.status.success(), detail)
        }
        Err(e) => (false, e.to_string()),
    };

    let first = run(sig);
    if first.0 {
        return first;
    }

    // Если подпись сохранена как DER, а не Base64 — CLI ждёт Base64.
    if let Ok(bytes) = std::fs::read(sig) {
        if bytes.first() == Some(&0x30) {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
            let tmp = std::env::temp_dir().join("cryptoline_verify_tmp.sig");
            if std::fs::write(&tmp, encoded).is_ok() {
                let result = run(&tmp);
                let _ = std::fs::remove_file(&tmp);
                return result;
            }
        }
    }

    first
}

fn run_sign_cli(
    cli: &Path,
    file: &Path,
    certs: &[PathBuf],
    detached: bool,
    format: SigFormat,
    encoding: SigEncoding,
) -> Result<PathBuf, String> {
    let mut cmd = std::process::Command::new(cli);
    cmd.arg("sign").arg("--file").arg(file);
    for cert in certs {
        cmd.arg("--cert").arg(cert);
    }
    if !detached {
        cmd.arg("--attached");
    }

    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(stderr
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("ошибка подписи")
            .trim()
            .to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut sig_path = stdout
        .lines()
        .find_map(|line| {
            line.split("Подпись сохранена:")
                .nth(1)
                .map(|s| PathBuf::from(s.trim()))
        })
        .unwrap_or_else(|| file.with_extension("sig"));

    if format == SigFormat::P7s {
        let new_path = sig_path.with_extension(format.extension());
        if std::fs::rename(&sig_path, &new_path).is_ok() {
            sig_path = new_path;
        }
    }

    if encoding == SigEncoding::Der {
        convert_to_der(&sig_path).map_err(|e| format!("DER: {}", e))?;
    }

    Ok(sig_path)
}

fn convert_to_der(path: &Path) -> std::io::Result<()> {
    use base64::Engine;
    let text = std::fs::read_to_string(path)?;
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(path, bytes)
}

fn write_zip(path: &Path, entries: &[(String, PathBuf)]) -> Result<(), String> {
    use std::io::Write;

    let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(file);

    let mut used: Vec<String> = Vec::new();
    for (name, src) in entries {
        let mut unique = name.clone();
        let mut n = 1;
        while used.contains(&unique) {
            let stem = Path::new(name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("signature");
            let ext = Path::new(name)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("sig");
            unique = format!("{}_{}.{}", stem, n, ext);
            n += 1;
        }
        used.push(unique.clone());

        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let data = std::fs::read(src).map_err(|e| e.to_string())?;
        zip.start_file(unique, options).map_err(|e| e.to_string())?;
        zip.write_all(&data).map_err(|e| e.to_string())?;
    }

    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}
