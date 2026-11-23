//! Интерфейс КриптоЛайн: тёмная матовая тема, три колонки и плавающая
//! панель подписания.
//!
//! Логика подписи вынесена в CLI (`cryptoline-cli.exe`), который лежит рядом
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
    detached: bool,
    separate_files: bool,
    pack_zip: bool,
    format: SigFormat,
    encoding: SigEncoding,

    hash_pending: Option<usize>,
    hash_rx: Option<mpsc::Receiver<(usize, String)>>,

    verify_file: Option<PathBuf>,
    verify_sig: Option<PathBuf>,
    verify_result: Option<(bool, String)>,

    confirm_delete: bool,
    titlebar_applied: bool,
    logo: Option<egui::TextureHandle>,
    resize_drag: Option<ResizeDrag>,
    ctrl_a_was_down: bool,
    last_signed_dir: Option<PathBuf>,
    large_sign_files: Option<Vec<String>>,
}

/// Сертификат, подготовленный к вызову CLI (путь к DER + владелец).
struct PreparedCert {
    path: PathBuf,
    subject: String,
    imported: bool,
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
            detached: true,
            separate_files: false,
            pack_zip: false,
            format: SigFormat::Sig,
            encoding: SigEncoding::Base64,
            hash_pending: None,
            hash_rx: None,
            verify_file: None,
            verify_sig: None,
            verify_result: None,
            confirm_delete: false,
            titlebar_applied: false,
            logo: None,
            resize_drag: None,
            ctrl_a_was_down: false,
            last_signed_dir: None,
            large_sign_files: None,
        }
    }
}

impl CryptoLineApp {
    /// Открыть приложение сразу с набором документов (аргументы командной строки).
    pub fn with_paths(paths: Vec<PathBuf>) -> Self {
        let mut app = Self::default();
        for path in paths {
            if path.is_file() {
                app.push_file(path);
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
        self.handle_dropped(ctx);

        if self.hash_pending.is_some() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        // Сайдбар — на всю высоту окна.
        egui::SidePanel::left("sidebar")
            .exact_width(212.0)
            .resizable(false)
            .frame(
                egui::Frame::none()
                    .fill(BG_WINDOW)
                    .inner_margin(Margin {
                        left: 0.0,
                        right: 14.0,
                        top: 18.0,
                        bottom: 14.0,
                    }),
            )
            .show(ctx, |ui| self.sidebar(ui));

        egui::TopBottomPanel::top("topbar")
            .exact_height(72.0)
            .frame(
                egui::Frame::none()
                    .fill(BG_WINDOW)
                    .inner_margin(Margin {
                        left: 24.0,
                        right: 20.0,
                        top: 14.0,
                        bottom: 12.0,
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
                    "app_icon",
                    egui::ColorImage::from_rgba_unmultiplied(
                        [crate::ICON_SIZE as usize, crate::ICON_SIZE as usize],
                        crate::ICON_RGBA,
                    ),
                    egui::TextureOptions::LINEAR,
                )
            });
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
            ui.painter().image(
                texture.id(),
                rect,
                Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                Color32::WHITE,
            );
            ui.add_space(8.0);
            ui.add_space(4.0);
            ui.label(
                RichText::new("Просто подпись")
                    .font(theme::medium(15.5))
                    .color(TEXT),
            );
        });

        ui.add_space(30.0);

        for nav in [
            Nav::Docs,
            Nav::Encrypt,
            Nav::Verify,
            Nav::Certs,
            Nav::Zip,
            Nav::Settings,
        ] {
            self.nav_item(ui, nav);
        }

        ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(
                    RichText::new("v1.0 · ГОСТ Р 34.10-2012")
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

    fn nav_item(&mut self, ui: &mut Ui, nav: Nav) {
        let active = self.active_nav == nav;
        let (rect, resp) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), 40.0), Sense::click());

        let p = ui.painter();
        if active {
            p.rect_filled(
                Rect::from_min_size(
                    Pos2::new(rect.left() + 1.0, rect.center().y - 9.0),
                    Vec2::new(3.0, 18.0),
                ),
                Rounding::same(2.0),
                Color32::WHITE,
            );
        } else if resp.hovered() {
            p.rect_filled(rect, Rounding::same(9.0), BG_ACTIVE_ROW);
        }

        let icon_rect = Rect::from_center_size(
            Pos2::new(rect.left() + 32.0, rect.center().y),
            Vec2::splat(17.0),
        );
        icons::paint(
            p,
            icon_rect,
            nav.icon(),
            if active { ACCENT } else { TEXT_MUTED },
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
            if active { TEXT } else { TEXT_MUTED },
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

    fn topbar(&mut self, ui: &mut Ui) {
        self.topbar_drag(ui);

        if self.active_nav != Nav::Docs {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(self.active_nav.title())
                        .font(theme::medium(16.0))
                        .color(TEXT_MUTED),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    self.window_controls(ui);
                    ui.add_space(6.0);
                    self.token_profile(ui);
                });
            });
            return;
        }

        ui.horizontal(|ui| {
            let search_w = (ui.available_width() - 374.0 - 24.0).max(160.0);
            ui.allocate_ui_with_layout(
                Vec2::new(search_w, 46.0),
                Layout::left_to_right(Align::Center),
                |ui| self.search_box(ui),
            );

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                self.window_controls(ui);
                ui.add_space(10.0);
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

    /// Перетаскивание окна без системного заголовка.
    fn topbar_drag(&mut self, ui: &mut Ui) {
        let drag = ui.interact(
            ui.max_rect(),
            egui::Id::new("topbar_drag"),
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
    }

    fn window_controls(&mut self, ui: &mut Ui) {
        let close = window_button(ui, Icon::Close, true);
        if close.clicked() {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Close);
        }

        let maximized = ui.ctx().input(|i| i.viewport().maximized.unwrap_or(false));
        let max = window_button(
            ui,
            if maximized {
                Icon::Restore
            } else {
                Icon::Maximize
            },
            false,
        )
        .on_hover_text(if maximized { "Восстановить" } else { "Развернуть" });
        if max.clicked() {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
        }

        if window_button(ui, Icon::Minus, false)
            .on_hover_text("Свернуть")
            .clicked()
        {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
    }

    fn search_box(&mut self, ui: &mut Ui) {
        egui::Frame::none()
            .fill(BG_SUNKEN)
            .rounding(Rounding::same(12.0))
            .inner_margin(Margin {
                left: 14.0,
                right: 12.0,
                top: 9.0,
                bottom: 9.0,
            })
            .show(ui, |ui| {
                ui.set_width(ui.available_width().min(356.0) - 26.0);
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                    icons::paint(ui.painter(), r, Icon::Search, TEXT_MUTED, 1.5);
                    ui.add_space(7.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .id(egui::Id::new("file_search"))
                            .frame(false)
                            .hint_text(
                                RichText::new("Поиск по документам...")
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
            Vec2::new(204.0, 46.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::splat(38.0), Sense::hover());
                let p = ui.painter();
                p.rect_filled(r, Rounding::same(10.0), ACCENT_SOFT);
                icons::paint(p, r.shrink(10.0), Icon::Cert, ACCENT, 1.7);
                p.circle_filled(
                    Pos2::new(r.right() - 4.0, r.bottom() - 4.0),
                    5.5,
                    BG_WINDOW,
                );
                p.circle_filled(
                    Pos2::new(r.right() - 4.0, r.bottom() - 4.0),
                    3.5,
                    GREEN,
                );
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.add_space(4.0);
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
        let card = Rect::from_min_max(
            rect.min + Vec2::new(0.0, 2.0),
            rect.max - Vec2::new(0.0, 2.0),
        );

        let p = ui.painter();
        if active {
            p.add(egui::Shape::Mesh(
                theme::card_shadow().tessellate(card, Rounding::same(14.0)),
            ));
            p.rect_filled(card, Rounding::same(14.0), BG_CARD);
        } else if hovered {
            p.rect_filled(card, Rounding::same(14.0), BG_ROW_HOVER);
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
        p.rect_filled(chip, Rounding::same(6.0), BG_CHIP);
        p.circle_filled(
            Pos2::new(chip.left() + 11.0, chip.center().y),
            3.0,
            status.dot(),
        );
        p.galley(
            Pos2::new(chip.left() + 19.0, chip.center().y - 8.0),
            chip_galley,
            TEXT_SOFT,
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
        ui.allocate_ui_with_layout(
            Vec2::new(334.0, height),
            Layout::top_down(Align::Min),
            |ui| {
                ui.set_width(334.0);
                self.inspector_body(ui);
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
        if !self.panel_open {
            return;
        }

        let anchor = Align2::RIGHT_BOTTOM;
        egui::Area::new(egui::Id::new("sign_panel"))
            .order(egui::Order::Foreground)
            .pivot(anchor)
            .fixed_pos(ctx.screen_rect().right_bottom() - Vec2::new(22.0, 22.0))
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
                if action_button(ui, Icon::Pen).clicked() {
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
            "Ключи КриптоПро CSP из хранилища Windows и импортированные файлы",
        );
        ui.add_space(16.0);

        ui.horizontal(|ui| {
            if accent_button(ui, "Загрузить из Windows Store", Icon::Download).clicked() {
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
                        "Загрузите хранилище Windows или укажите файл сертификата .der / .cer / .pem",
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
                                "Хранилище Windows · CurrentUser\\My"
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
            "Проверьте отсоединённую подпись .sig: messageDigest и подпись сертификата",
        );
        ui.add_space(20.0);

        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(Rounding::same(16.0))
            .inner_margin(Margin::same(20.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width().min(720.0));
                ui.label(
                    RichText::new("Документ")
                        .font(theme::regular(12.5))
                        .color(TEXT_MUTED),
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, "Выбрать документ", Icon::File).clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .set_title("Документ для проверки")
                            .pick_file()
                        {
                            self.verify_file = Some(p);
                            self.verify_result = None;
                        }
                    }
                    if let Some(p) = &self.verify_file {
                        ui.label(
                            RichText::new(file_display(p))
                                .font(theme::regular(13.0))
                                .color(TEXT_SOFT),
                        );
                    }
                });

                ui.add_space(12.0);
                ui.label(
                    RichText::new("Файл подписи")
                        .font(theme::regular(12.5))
                        .color(TEXT_MUTED),
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, "Выбрать .sig", Icon::BadgeCheck).clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("Подпись", &["sig", "p7s"])
                            .set_title("Файл подписи")
                            .pick_file()
                        {
                            self.verify_sig = Some(p);
                            self.verify_result = None;
                        }
                    }
                    if let Some(p) = &self.verify_sig {
                        ui.label(
                            RichText::new(file_display(p))
                                .font(theme::regular(13.0))
                                .color(TEXT_SOFT),
                        );
                    }
                });

                ui.add_space(18.0);
                if accent_button(ui, "Проверить подпись", Icon::BadgeCheck).clicked() {
                    self.run_verify();
                }
            });

        if let Some((ok, detail)) = self.verify_result.clone() {
            ui.add_space(16.0);
            egui::Frame::none()
                .fill(BG_CARD)
                .rounding(Rounding::same(14.0))
                .inner_margin(Margin::same(18.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
                        icons::paint(
                            ui.painter(),
                            r,
                            if ok { Icon::BadgeCheck } else { Icon::Close },
                            if ok { GREEN } else { RED },
                            1.8,
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(if ok {
                                "Подпись верна"
                            } else {
                                "Подпись недействительна"
                            })
                            .font(theme::medium(15.0))
                            .color(if ok { GREEN } else { RED }),
                        );
                    });
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(detail)
                            .font(theme::mono(11.5))
                            .color(TEXT_MUTED),
                    );
                });
        }
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
                setting_row(ui, "Версия", "Просто подпись 1.0 · egui", true);
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
    }

    fn encrypt_screen(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Шифрование",
            "Шифрование документов для получателей по ГОСТ Р 34.12",
        );
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            let (r, _) = ui.allocate_exact_size(Vec2::splat(92.0), Sense::hover());
            let p = ui.painter();
            p.circle_filled(r.center(), 46.0, ACCENT_SOFT);
            icons::paint(
                p,
                Rect::from_center_size(r.center(), Vec2::splat(38.0)),
                Icon::Lock,
                ACCENT,
                2.0,
            );
            ui.add_space(16.0);
            ui.label(
                RichText::new("Модуль шифрования готовится")
                    .font(theme::medium(19.0))
                    .color(TEXT),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Будет доступно шифрование документов на сертификаты получателей\n\
                     через КриптоПро CSP. Подпись и проверка уже работают.",
                )
                .font(theme::regular(13.0))
                .color(TEXT_MUTED),
            );
            ui.add_space(18.0);
            if accent_button(ui, "Перейти к документам", Icon::Docs).clicked() {
                self.active_nav = Nav::Docs;
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Действия
// ---------------------------------------------------------------------------

impl CryptoLineApp {
    fn cli_path(&self) -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join("cryptoline-cli.exe")))
            .unwrap_or_else(|| PathBuf::from("cryptoline-cli.exe"))
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
        if let Some(entry) = FileEntry::from_path(path) {
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
                .collect()
        });
        if dropped.is_empty() {
            return;
        }
        let mut added = 0;
        for p in dropped {
            if self.push_file(p) {
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
        p.text(
            screen.center() + Vec2::new(0.0, 22.0),
            Align2::CENTER_CENTER,
            "Отпустите файлы, чтобы добавить",
            theme::medium(20.0),
            TEXT,
        );
        p.text(
            screen.center() + Vec2::new(0.0, 48.0),
            Align2::CENTER_CENTER,
            "PDF, DOCX, XML, TXT и другие документы",
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
                    format!("Загружено сертификатов из Windows Store: {}", count)
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

    fn extract_cn_from_dn(&self, dn: &str) -> String {
        for part in dn.split(',') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix("CN=") {
                return rest.trim().trim_matches('"').to_string();
            }
        }
        dn.to_string()
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
        let mut signed_files = 0usize;
        let mut signed_sigs = 0usize;
        let mut errors: Vec<String> = Vec::new();
        let mut signed_dirs: Vec<PathBuf> = Vec::new();

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

        for file_idx in file_indices {
            let Some(file) = self.files.get(file_idx).cloned() else {
                continue;
            };
            let mut created: Vec<(String, PathBuf)> = Vec::new();

            if separate {
                // По файлу подписи на каждый сертификат.
                for cert in &prepared {
                    match run_sign_cli(
                        &cli,
                        &file.path,
                        &[cert.path.clone()],
                        detached,
                        format,
                        encoding,
                    ) {
                        Ok(path) => created.push((cert.subject.clone(), path)),
                        Err(e) => errors.push(e),
                    }
                }
            } else {
                // Одна общая подпись со всеми подписантами.
                let cert_paths: Vec<PathBuf> =
                    prepared.iter().map(|c| c.path.clone()).collect();
                match run_sign_cli(
                    &cli,
                    &file.path,
                    &cert_paths,
                    detached,
                    format,
                    encoding,
                ) {
                    Ok(path) => {
                        for cert in &prepared {
                            created.push((cert.subject.clone(), path.clone()));
                        }
                    }
                    Err(e) => errors.push(e),
                }
            }

            if !created.is_empty() {
                let signed_at = chrono::Local::now()
                    .format("%d.%m.%Y %H:%M")
                    .to_string();
                if let Some(f) = self.files.get_mut(file_idx) {
                    for (subject, path) in &created {
                        f.signatures.push(SignatureInfo {
                            subject: subject.clone(),
                            path: Some(path.clone()),
                            signed_at: signed_at.clone(),
                        });
                    }
                    f.status = FileStatus::Signed;
                }
                signed_files += 1;
                signed_sigs += created.len();

                if let Some(dir) = file.path.parent() {
                    if !signed_dirs.iter().any(|d| d == dir) {
                        signed_dirs.push(dir.to_path_buf());
                    }
                }

                if self.pack_zip {
                    // При общей подписи путь один и тот же — не дублируем в ZIP.
                    let mut unique: Vec<(String, PathBuf)> = Vec::new();
                    for (subject, path) in &created {
                        if !unique.iter().any(|(_, p)| p == path) {
                            unique.push((subject.clone(), path.clone()));
                        }
                    }
                    let zip_path = file.zip_path();
                    match write_zip(&zip_path, &unique) {
                        Ok(()) => {
                            self.message = format!("Подписи упакованы: {}", zip_path.display())
                        }
                        Err(e) => errors.push(format!("ZIP: {}", e)),
                    }
                }
            }
        }

        // Временные DER-файлы сертификатов из хранилища больше не нужны.
        for cert in &prepared {
            if !cert.imported {
                let _ = std::fs::remove_file(&cert.path);
            }
        }

        // Отчёт о подписях — в каждую папку, где появились подписи.
        let mut report_errors = 0;
        for dir in &signed_dirs {
            if let Err(e) = self.write_reports(dir) {
                report_errors += 1;
                errors.push(format!("Отчёт: {}", e));
            }
        }
        if let Some(dir) = signed_dirs.first() {
            self.last_signed_dir = Some(dir.clone());
        }

        if errors.is_empty() {
            self.message = format!(
                "Подписано файлов: {} · подписей: {} · отчёты: {}",
                signed_files,
                signed_sigs,
                signed_dirs.len()
            );
        } else {            let suffix = if report_errors > 0 {
                format!(", ошибок отчётов: {}", report_errors)
            } else {
                String::new()
            };
            self.message = format!(
                "Подписано файлов: {}, подписей: {} · ошибок: {} ({}){}",
                signed_files,
                signed_sigs,
                errors.len(),
                errors.first().cloned().unwrap_or_default(),
                suffix
            );
        }
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

    fn run_verify(&mut self) {
        let (Some(file), Some(sig)) = (self.verify_file.clone(), self.verify_sig.clone()) else {
            self.verify_result = Some((false, "Выберите документ и файл подписи".to_string()));
            return;
        };
        if let Err(error) = verify_size_error(&file, &sig) {
            self.verify_result = Some((false, error));
            return;
        }

        let (ok, detail) = run_verify_cli(&self.cli_path(), &file, &sig);
        if ok {
            let renamed = self.rename_after_verify(&file, &sig, &detail);
            if let Some(path) = &renamed {
                self.verify_sig = Some(path.clone());
            }
            let detail = detail.replace('✓', "•").replace('✗', "×");
            let extra = renamed
                .as_ref()
                .map(|path| {
                    format!(
                        "\nФайл подписи переименован: {}",
                        file_display(path)
                    )
                })
                .unwrap_or_default();
            self.verify_result = Some((true, format!("{}{}", detail, extra)));
        } else {
            let detail = detail.replace('✓', "•").replace('✗', "×");
            self.verify_result = Some((false, detail));
        }
    }

    fn verify_pair(&mut self, file: PathBuf, sig: PathBuf) {
        if let Err(error) = verify_size_error(&file, &sig) {
            self.message = error;
            return;
        }

        let (ok, detail) = run_verify_cli(&self.cli_path(), &file, &sig);
        if ok {
            let renamed = self.rename_after_verify(&file, &sig, &detail);
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

fn icon_button(ui: &mut Ui, icon: Icon, size: f32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
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
    paint_round_shadow(p, rect.center(), diameter / 2.0);
    p.circle_filled(
        rect.center(),
        diameter / 2.0,
        if resp.hovered() { ACCENT_HOVER } else { ACCENT },
    );
    icons::paint(
        p,
        Rect::from_center_size(rect.center(), Vec2::splat(diameter * 0.44)),
        Icon::Plus,
        Color32::WHITE,
        2.0,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn action_button(ui: &mut Ui, icon: Icon) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(58.0), Sense::click());
    let p = ui.painter();
    paint_round_shadow(p, rect.center(), 29.0);
    p.circle_filled(
        rect.center(),
        29.0,
        if resp.hovered() { ACCENT_HOVER } else { ACCENT },
    );
    icons::paint(
        p,
        Rect::from_center_size(rect.center(), Vec2::splat(24.0)),
        icon,
        Color32::WHITE,
        2.0,
    );
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

fn window_button(ui: &mut Ui, icon: Icon, danger: bool) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::click());
    let p = ui.painter();
    if resp.hovered() {
        p.rect_filled(
            rect,
            Rounding::same(7.0),
            if danger {
                Color32::from_rgb(0xD9, 0x4A, 0x4A)
            } else {
                BG_CARD_HOVER
            },
        );
    }
    icons::paint(
        p,
        Rect::from_center_size(rect.center(), Vec2::splat(12.0)),
        icon,
        if resp.hovered() { TEXT } else { TEXT_MUTED },
        1.3,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn danger_button(ui: &mut Ui, label: &str, width: f32) -> Response {
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
    p.rect_filled(
        track,
        Rounding::same(10.0),
        if *value {
            ACCENT
        } else {
            Color32::from_rgb(0x4A, 0x4E, 0x5F)
        },
    );
    let knob_x = if *value {
        track.right() - 10.0
    } else {
        track.left() + 10.0
    };
    p.circle_filled(Pos2::new(knob_x, track.center().y), 7.0, Color32::WHITE);
    p.text(
        Pos2::new(track.right() + 12.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        theme::regular(13.5),
        if resp.hovered() { TEXT } else { TEXT_SOFT },
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
        if let Some(pointer) = ui.ctx().pointer_hover_pos() {
            let id = egui::Id::new(("signer_tip", name.to_string(), sub.to_string()));
            egui::Area::new(id)
                .order(egui::Order::Tooltip)
                .fixed_pos(pointer + Vec2::new(16.0, 18.0))
                .show(ui.ctx(), |ui| {
                    egui::Frame::none()
                        .fill(Color32::WHITE)
                        .rounding(Rounding::same(10.0))
                        .shadow(theme::soft_shadow())
                        .inner_margin(Margin {
                            left: 14.0,
                            right: 14.0,
                            top: 10.0,
                            bottom: 10.0,
                        })
                        .show(ui, |ui| {
                            ui.set_max_width(260.0);
                            ui.label(
                                RichText::new(name)
                                    .font(theme::medium(14.0))
                                    .color(Color32::from_rgb(0x1F, 0x22, 0x2E)),
                            );
                            ui.label(
                                RichText::new(format!("Сертификат · {}", sub))
                                    .font(theme::regular(12.0))
                                    .color(Color32::from_rgb(0x6B, 0x6F, 0x82)),
                            );
                            if !valid.is_empty() {
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new(format!("Действителен до: {}", valid))
                                        .font(theme::regular(12.0))
                                        .color(Color32::from_rgb(0x3B, 0x3F, 0x50)),
                                );
                            }
                        });
                });
        }
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
    let p = ui.painter();
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
