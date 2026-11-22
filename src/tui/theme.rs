//! Farben der TUI: „Doering Night“.
//!
//! Dunkle Bühne, Violett als Stimme, der Verlauf Indigo → Violett → Pink nur
//! in der Wortmarke. Statusfarben sind von der Marke getrennt: Grün = ok,
//! Amber = wartet/auffällig, Rot = gestoppt. Die gefüllte Amber-Fläche gibt
//! es genau einmal: für das, was auf einen Menschen wartet.
//!
//! Nicht jedes Terminal kann 24-Bit-Farben. [`Depth`] wählt die beste Stufe,
//! die das Terminal ankündigt; `NO_COLOR` schaltet Farben ganz ab.

use ratatui::style::{Color, Modifier, Style};

use super::model::Tone;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// 24 Bit: die Palette exakt.
    True,
    /// 256 Farben: nächster Würfel- oder Grauwert.
    Ansi256,
    /// 16 Farben: die Farben des Terminal-Themes.
    Ansi16,
    /// Keine Farben, nur fett/invertiert.
    Mono,
}

impl Depth {
    /// Liest `NO_COLOR`, `COLORTERM` und `TERM`.
    pub fn detect() -> Self {
        let var = |k: &str| std::env::var(k).unwrap_or_default();
        Self::from_env(&var("NO_COLOR"), &var("COLORTERM"), &var("TERM"))
    }

    pub fn from_env(no_color: &str, colorterm: &str, term: &str) -> Self {
        if !no_color.is_empty() || term == "dumb" {
            Depth::Mono
        } else if colorterm.contains("truecolor") || colorterm.contains("24bit") {
            Depth::True
        } else if term.contains("256color") {
            Depth::Ansi256
        } else {
            Depth::Ansi16
        }
    }
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub depth: Depth,
    pub bg: Color,
    pub raised: Color,
    pub sel: Color,
    pub line: Color,
    pub ink: Color,
    pub muted: Color,
    pub dim: Color,
    pub accent: Color,
    pub ok: Color,
    pub warn: Color,
    pub bad: Color,
    /// Verlauf der Wortmarke, ein Wert pro Buchstabe von „HEDGE“.
    pub mark: [Color; 5],
}

/// Die Palette als RGB – Quelle für alle Farbtiefen.
mod rgb {
    pub const BG: u32 = 0x08070d;
    pub const RAISED: u32 = 0x0e0c16;
    pub const SEL: u32 = 0x1a1726;
    pub const LINE: u32 = 0x2c2842;
    pub const INK: u32 = 0xf4f3f8;
    pub const MUTED: u32 = 0xa6a3ba;
    pub const DIM: u32 = 0x6b6883;
    pub const ACCENT: u32 = 0xa78bfa;
    pub const OK: u32 = 0x6ee7a0;
    pub const WARN: u32 = 0xfbbf24;
    pub const BAD: u32 = 0xf87171;
    pub const MARK: [u32; 5] = [0x7072f5, 0x8b6ff6, 0xa66cf7, 0xca5dca, 0xee4d9c];
}

impl Theme {
    pub fn new(depth: Depth) -> Self {
        let c = |v: u32| convert(v, depth);
        match depth {
            Depth::True | Depth::Ansi256 => Self {
                depth,
                bg: c(rgb::BG),
                raised: c(rgb::RAISED),
                sel: c(rgb::SEL),
                line: c(rgb::LINE),
                ink: c(rgb::INK),
                muted: c(rgb::MUTED),
                dim: c(rgb::DIM),
                accent: c(rgb::ACCENT),
                ok: c(rgb::OK),
                warn: c(rgb::WARN),
                bad: c(rgb::BAD),
                mark: rgb::MARK.map(c),
            },
            // Mit 16 Farben gehört der Hintergrund dem Terminal.
            Depth::Ansi16 => Self {
                depth,
                bg: Color::Reset,
                raised: Color::Reset,
                sel: Color::DarkGray,
                line: Color::DarkGray,
                ink: Color::Reset,
                muted: Color::Gray,
                dim: Color::DarkGray,
                accent: Color::LightMagenta,
                ok: Color::LightGreen,
                warn: Color::Yellow,
                bad: Color::LightRed,
                mark: [
                    Color::LightBlue,
                    Color::LightBlue,
                    Color::LightMagenta,
                    Color::LightMagenta,
                    Color::Magenta,
                ],
            },
            Depth::Mono => Self {
                depth,
                bg: Color::Reset,
                raised: Color::Reset,
                sel: Color::Reset,
                line: Color::Reset,
                ink: Color::Reset,
                muted: Color::Reset,
                dim: Color::Reset,
                accent: Color::Reset,
                ok: Color::Reset,
                warn: Color::Reset,
                bad: Color::Reset,
                mark: [Color::Reset; 5],
            },
        }
    }

    /// Grundstil jeder Fläche: Text in `ink` auf der Bühne.
    pub fn base(&self) -> Style {
        Style::new().fg(self.ink).bg(self.bg)
    }

    pub fn fg(&self, color: Color) -> Style {
        Style::new().fg(color)
    }

    pub fn tone(&self, tone: Tone) -> Style {
        let style = self.fg(match tone {
            Tone::Ink => self.ink,
            Tone::Muted => self.muted,
            Tone::Dim => self.dim,
            Tone::Accent => self.accent,
            Tone::Ok => self.ok,
            Tone::Warn => self.warn,
            Tone::Bad => self.bad,
        });
        // Ohne Farben trägt die Schriftstärke den Unterschied.
        if self.depth == Depth::Mono && tone == Tone::Dim {
            style.add_modifier(Modifier::DIM)
        } else {
            style
        }
    }

    pub fn bold(&self, tone: Tone) -> Style {
        self.tone(tone).add_modifier(Modifier::BOLD)
    }

    /// Gefüllte Fläche in einer Statusfarbe, z. B. `HOLD`.
    pub fn chip(&self, color: Color) -> Style {
        match self.depth {
            Depth::Mono => Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD),
            Depth::Ansi16 => Style::new()
                .fg(Color::Black)
                .bg(color)
                .add_modifier(Modifier::BOLD),
            _ => Style::new()
                .fg(self.bg)
                .bg(color)
                .add_modifier(Modifier::BOLD),
        }
    }

    /// Die ausgewählte Zeile einer Liste.
    pub fn selected(&self) -> Style {
        match self.depth {
            Depth::Mono => Style::new().add_modifier(Modifier::REVERSED),
            Depth::Ansi16 => Style::new().bg(self.sel).fg(Color::White),
            _ => Style::new().bg(self.sel),
        }
    }
}

fn convert(v: u32, depth: Depth) -> Color {
    let (r, g, b) = ((v >> 16) as u8, (v >> 8) as u8, v as u8);
    match depth {
        Depth::True => Color::Rgb(r, g, b),
        _ => Color::Indexed(nearest_256(r, g, b)),
    }
}

/// Nächster Wert der xterm-256-Palette: 6×6×6-Würfel oder Graustufe, je
/// nachdem, was näher liegt.
fn nearest_256(r: u8, g: u8, b: u8) -> u8 {
    const STEPS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let step = |v: u8| -> usize {
        STEPS
            .iter()
            .enumerate()
            .min_by_key(|(_, s)| (i32::from(**s) - i32::from(v)).abs())
            .map(|(i, _)| i)
            .unwrap_or(0)
    };
    let dist = |a: (u8, u8, u8)| -> i32 {
        let d = |x: u8, y: u8| (i32::from(x) - i32::from(y)).pow(2);
        d(a.0, r) + d(a.1, g) + d(a.2, b)
    };
    let (ri, gi, bi) = (step(r), step(g), step(b));
    let cube = (STEPS[ri], STEPS[gi], STEPS[bi]);
    let avg = (u16::from(r) + u16::from(g) + u16::from(b)) / 3;
    let gray_i = ((avg.saturating_sub(8) + 5) / 10).min(23) as u8;
    let gray_v = 8 + 10 * gray_i;
    if dist((gray_v, gray_v, gray_v)) < dist(cube) {
        232 + gray_i
    } else {
        (16 + 36 * ri + 6 * gi + bi) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_follows_the_environment() {
        assert_eq!(
            Depth::from_env("1", "truecolor", "xterm-256color"),
            Depth::Mono
        );
        assert_eq!(Depth::from_env("", "", "dumb"), Depth::Mono);
        assert_eq!(
            Depth::from_env("", "truecolor", "xterm-256color"),
            Depth::True
        );
        assert_eq!(Depth::from_env("", "24bit", "xterm"), Depth::True);
        assert_eq!(Depth::from_env("", "", "xterm-256color"), Depth::Ansi256);
        assert_eq!(Depth::from_env("", "", "xterm"), Depth::Ansi16);
    }

    #[test]
    fn truecolor_uses_the_palette_exactly() {
        let t = Theme::new(Depth::True);
        assert_eq!(t.bg, Color::Rgb(0x08, 0x07, 0x0d));
        assert_eq!(t.accent, Color::Rgb(0xa7, 0x8b, 0xfa));
        assert_eq!(t.mark[4], Color::Rgb(0xee, 0x4d, 0x9c));
    }

    #[test]
    fn palette_maps_to_sensible_256_colors() {
        assert_eq!(nearest_256(0, 0, 0), 16);
        assert_eq!(nearest_256(255, 255, 255), 231);
        // Fast schwarz mit Blaustich → dunkelste Graustufe, nicht Blau.
        assert_eq!(nearest_256(0x08, 0x07, 0x0d), 232);
        // Violett bleibt violett (Würfel 175,135,255).
        assert_eq!(nearest_256(0xa7, 0x8b, 0xfa), 141);
        // Status bleibt unterscheidbar.
        let t = Theme::new(Depth::Ansi256);
        assert_ne!(t.ok, t.warn);
        assert_ne!(t.warn, t.bad);
        assert_ne!(t.accent, t.bad);
    }

    #[test]
    fn without_colors_a_chip_is_still_visible() {
        let t = Theme::new(Depth::Mono);
        assert!(t.chip(t.warn).add_modifier.contains(Modifier::REVERSED));
        assert_eq!(t.base().fg, Some(Color::Reset));
    }
}
