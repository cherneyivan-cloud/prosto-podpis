//! Векторные иконки, нарисованные примитивами egui.
//!
//! Это даёт четкие иконки без зависимости от иконочных шрифтов и без
//! размытия: линии рисуются в целевом прямоугольнике, масштабируются
//! вместе с ним.

use eframe::egui::{self, Color32, Pos2, Rect, Rounding, Shape, Stroke, Vec2};

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Icon {
    Shield,
    Docs,
    Lock,
    BadgeCheck,
    Cert,
    Archive,
    Settings,
    Search,
    Plus,
    Pen,
    Trash,
    Download,
    Check,
    Close,
    Minus,
    ChevronDown,
    File,
    Folder,
    Maximize,
    Restore,
    Menu,
}

pub fn paint(painter: &egui::Painter, rect: Rect, icon: Icon, color: Color32, width: f32) {
    let s = rect.width().min(rect.height());
    let r = Rect::from_center_size(rect.center(), Vec2::splat(s));
    let x = |t: f32| r.left() + t * s;
    let y = |t: f32| r.top() + t * s;
    let p = |t: f32, u: f32| Pos2::new(x(t), y(u));
    let stroke = Stroke::new(width, color);
    let rounding = Rounding::same(s * 0.08);

    match icon {
        Icon::Shield => {
            // Щит с замочной скважиной — логотип приложения.
            let pts = vec![
                p(0.50, 0.06),
                p(0.86, 0.21),
                p(0.86, 0.53),
                p(0.50, 0.94),
                p(0.14, 0.53),
                p(0.14, 0.21),
            ];
            painter.add(Shape::closed_line(pts, stroke));
            painter.circle_stroke(p(0.50, 0.42), s * 0.10, stroke);
            painter.line_segment([p(0.50, 0.49), p(0.50, 0.65)], stroke);
        }
        Icon::Docs => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.18, 0.12), p(0.70, 0.90)),
                rounding,
                stroke,
            );
            painter.rect_stroke(
                Rect::from_min_max(p(0.32, 0.26), p(0.84, 0.96)),
                rounding,
                stroke,
            );
        }
        Icon::Lock => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.20, 0.45), p(0.80, 0.88)),
                Rounding::same(s * 0.10),
                stroke,
            );
            let arc: Vec<Pos2> = (0..=14)
                .map(|i| {
                    let a = std::f32::consts::PI + i as f32 / 14.0 * std::f32::consts::PI;
                    p(0.50 + 0.21 * a.cos(), 0.45 + 0.21 * a.sin())
                })
                .collect();
            painter.add(Shape::line(arc, stroke));
            painter.circle_filled(p(0.50, 0.65), s * 0.05, color);
        }
        Icon::BadgeCheck => {
            painter.circle_stroke(p(0.50, 0.50), s * 0.40, stroke);
            painter.add(Shape::line(
                vec![p(0.31, 0.50), p(0.45, 0.65), p(0.70, 0.36)],
                stroke,
            ));
        }
        Icon::Cert => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.14, 0.12), p(0.86, 0.68)),
                rounding,
                stroke,
            );
            painter.line_segment([p(0.28, 0.29), p(0.62, 0.29)], stroke);
            painter.line_segment([p(0.28, 0.42), p(0.72, 0.42)], stroke);
            painter.circle_stroke(p(0.66, 0.60), s * 0.10, stroke);
            painter.line_segment([p(0.60, 0.68), p(0.56, 0.88)], stroke);
            painter.line_segment([p(0.72, 0.68), p(0.76, 0.88)], stroke);
        }
        Icon::Archive => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.06, 0.16), p(0.94, 0.36)),
                rounding,
                stroke,
            );
            painter.rect_stroke(
                Rect::from_min_max(p(0.13, 0.36), p(0.87, 0.90)),
                rounding,
                stroke,
            );
            painter.rect_stroke(
                Rect::from_min_max(p(0.40, 0.22), p(0.60, 0.30)),
                Rounding::same(s * 0.03),
                stroke,
            );
        }
        Icon::Settings => {
            painter.circle_stroke(p(0.50, 0.50), s * 0.17, stroke);
            for i in 0..8 {
                let a = i as f32 * std::f32::consts::TAU / 8.0;
                painter.line_segment(
                    [
                        p(0.50 + 0.28 * a.cos(), 0.50 + 0.28 * a.sin()),
                        p(0.50 + 0.40 * a.cos(), 0.50 + 0.40 * a.sin()),
                    ],
                    stroke,
                );
            }
        }
        Icon::Search => {
            painter.circle_stroke(p(0.42, 0.42), s * 0.28, stroke);
            painter.line_segment([p(0.64, 0.64), p(0.88, 0.88)], stroke);
        }
        Icon::Plus => {
            painter.line_segment([p(0.50, 0.20), p(0.50, 0.80)], stroke);
            painter.line_segment([p(0.20, 0.50), p(0.80, 0.50)], stroke);
        }
        Icon::Pen => {
            // Перо: корпус, кончик и разделительная линия.
            painter.add(Shape::closed_line(
                vec![p(0.30, 0.70), p(0.64, 0.18), p(0.82, 0.34), p(0.38, 0.80)],
                stroke,
            ));
            painter.line_segment([p(0.38, 0.80), p(0.18, 0.88)], stroke);
            painter.line_segment([p(0.42, 0.62), p(0.72, 0.28)], stroke);
        }
        Icon::Trash => {
            painter.line_segment([p(0.14, 0.26), p(0.86, 0.26)], stroke);
            painter.line_segment([p(0.38, 0.16), p(0.62, 0.16)], stroke);
            painter.add(Shape::line(
                vec![p(0.24, 0.30), p(0.30, 0.88), p(0.70, 0.88), p(0.76, 0.30)],
                stroke,
            ));
            painter.line_segment([p(0.43, 0.40), p(0.45, 0.78)], stroke);
            painter.line_segment([p(0.57, 0.40), p(0.55, 0.78)], stroke);
        }
        Icon::Download => {
            painter.line_segment([p(0.50, 0.14), p(0.50, 0.62)], stroke);
            painter.add(Shape::line(
                vec![p(0.30, 0.44), p(0.50, 0.66), p(0.70, 0.44)],
                stroke,
            ));
            painter.add(Shape::line(
                vec![p(0.16, 0.70), p(0.16, 0.88), p(0.84, 0.88), p(0.84, 0.70)],
                stroke,
            ));
        }
        Icon::Check => {
            painter.add(Shape::line(
                vec![p(0.18, 0.52), p(0.42, 0.74), p(0.84, 0.26)],
                stroke,
            ));
        }
        Icon::Close => {
            painter.line_segment([p(0.22, 0.22), p(0.78, 0.78)], stroke);
            painter.line_segment([p(0.78, 0.22), p(0.22, 0.78)], stroke);
        }
        Icon::Minus => {
            painter.line_segment([p(0.22, 0.50), p(0.78, 0.50)], stroke);
        }
        Icon::ChevronDown => {
            painter.add(Shape::line(
                vec![p(0.26, 0.40), p(0.50, 0.62), p(0.74, 0.40)],
                stroke,
            ));
        }
        Icon::File => {
            painter.add(Shape::closed_line(
                vec![
                    p(0.24, 0.08),
                    p(0.60, 0.08),
                    p(0.80, 0.28),
                    p(0.80, 0.92),
                    p(0.24, 0.92),
                ],
                stroke,
            ));
            painter.add(Shape::line(
                vec![p(0.60, 0.08), p(0.60, 0.28), p(0.80, 0.28)],
                stroke,
            ));
            painter.line_segment([p(0.36, 0.50), p(0.68, 0.50)], stroke);
            painter.line_segment([p(0.36, 0.64), p(0.68, 0.64)], stroke);
            painter.line_segment([p(0.36, 0.78), p(0.56, 0.78)], stroke);
        }
        Icon::Folder => {
            painter.add(Shape::closed_line(
                vec![
                    p(0.14, 0.30),
                    p(0.40, 0.30),
                    p(0.48, 0.22),
                    p(0.86, 0.22),
                    p(0.86, 0.80),
                    p(0.14, 0.80),
                ],
                stroke,
            ));
            painter.line_segment([p(0.14, 0.40), p(0.86, 0.40)], stroke);
        }
        Icon::Maximize => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.20, 0.20), p(0.80, 0.80)),
                Rounding::same(s * 0.04),
                stroke,
            );
        }
        Icon::Restore => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.28, 0.14), p(0.86, 0.72)),
                Rounding::same(s * 0.04),
                stroke,
            );
            painter.add(Shape::line(
                vec![p(0.14, 0.32), p(0.14, 0.86), p(0.68, 0.86)],
                stroke,
            ));
        }
        Icon::Menu => {
            for t in [0.30, 0.50, 0.70] {
                painter.line_segment([p(0.16, t), p(0.84, t)], stroke);
            }
        }
    }
}
