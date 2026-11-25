//! A one-line footer on the host terminal saying the agent is jailed.
//!
//! The agent's PTY is one row shorter than the host terminal and the host's
//! scroll region ends above the last row, so the agent draws and scrolls as
//! if that row did not exist. The relay passes the agent's output through
//! [`Footer::filter`], which keeps it that way: sequences that would reset
//! the scroll region or move onto the last row are rewritten, and the footer
//! is painted again after anything that erases it.
//!
//! This is a parser for the shape of escape sequences only, not a terminal
//! emulator: the cursor position is never tracked, so painting saves and
//! restores it with DECSC/DECRC.

/// Below this many rows the footer is dropped and the agent gets them all.
const MIN_ROWS: u16 = 5;
/// Longer CSI sequences are passed through unexamined.
const MAX_CSI: usize = 64;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Ground,
    /// After ESC, which is held back until the next byte.
    Esc,
    /// Intermediates of a non-CSI escape sequence, up to its final byte.
    EscIntermediate,
    /// Parameters of a CSI sequence, collected in `csi`.
    Csi,
    /// The rest of a CSI sequence too long to examine.
    CsiLong,
    /// OSC, DCS, APC, PM or SOS string, up to BEL or ST.
    Str,
    /// After ESC inside a string, which is held back.
    StrEsc,
}

pub struct Footer {
    label: String,
    rows: u16,
    cols: u16,
    /// The scroll region the agent asked for, if not its whole screen.
    region: Option<(u16, u16)>,
    state: State,
    csi: Vec<u8>,
    /// The footer may have been erased: paint it at the next chance.
    stale: bool,
    /// The host scroll region may have been reset too.
    region_stale: bool,
    /// Output passed through since the footer was last painted.
    dirty: bool,
}

impl Footer {
    pub fn new(label: String, rows: u16, cols: u16) -> Footer {
        Footer {
            label,
            rows,
            cols,
            region: None,
            state: State::Ground,
            csi: Vec::new(),
            stale: false,
            region_stale: false,
            dirty: false,
        }
    }

    fn active(&self) -> bool {
        self.rows >= MIN_ROWS
    }

    /// Rows the agent may use: all but the last while the footer is shown.
    pub fn agent_rows(&self) -> u16 {
        if self.active() {
            self.rows - 1
        } else {
            self.rows
        }
    }

    /// Reserve the last row and paint the footer for the first time.
    pub fn open(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.active() {
            // Scroll once if the cursor is on the last row, so the footer
            // does not cover the line the user launched from.
            out.extend_from_slice(b"\r\n\x1b[A");
            self.paint(&mut out, true);
        }
        out
    }

    /// The host terminal changed size. Call before resizing the agent's PTY.
    pub fn resize(&mut self, rows: u16, cols: u16) -> Vec<u8> {
        let mut out = Vec::new();
        let was_active = self.active();
        let old_rows = self.rows;
        self.rows = rows;
        self.cols = cols;
        self.region = None;
        if was_active && old_rows < rows {
            // The old footer row is now inside the agent's screen.
            out.extend_from_slice(
                format!("\x1b7\x1b[{old_rows};1H\x1b[2K\x1b8").as_bytes(),
            );
        }
        if self.active() {
            self.paint(&mut out, true);
        } else if was_active {
            out.extend_from_slice(b"\x1b7\x1b[r\x1b8");
        }
        out
    }

    /// Give the last row back to the host terminal.
    pub fn close(&mut self) -> Vec<u8> {
        if !self.active() {
            return Vec::new();
        }
        format!("\x1b7\x1b[r\x1b[{};1H\x1b[2K\x1b8", self.rows).into_bytes()
    }

    /// Paint the footer if output has passed since it was last painted and
    /// the agent is not in the middle of an escape sequence. For when the
    /// output goes quiet, to repair anything [`Footer::filter`] missed.
    pub fn refresh(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.active() && self.dirty && self.state == State::Ground {
            let with_region = self.region_stale;
            self.paint(&mut out, with_region);
        }
        out
    }

    /// Copy the agent's output to `out`, adjusted to keep the footer.
    pub fn filter(&mut self, input: &[u8], out: &mut Vec<u8>) {
        if !self.active() {
            out.extend_from_slice(input);
            return;
        }
        self.dirty = true;
        for &byte in input {
            self.step(byte, out);
        }
        if self.stale && self.state == State::Ground {
            let with_region = self.region_stale;
            self.paint(out, with_region);
        }
    }

    fn step(&mut self, byte: u8, out: &mut Vec<u8>) {
        match self.state {
            State::Ground => {
                if byte == ESC {
                    self.state = State::Esc;
                } else {
                    out.push(byte);
                }
            }
            State::Esc => match byte {
                b'[' => {
                    self.csi.clear();
                    self.state = State::Csi;
                }
                b']' | b'P' | b'_' | b'^' | b'X' => {
                    out.extend_from_slice(&[ESC, byte]);
                    self.state = State::Str;
                }
                ESC => out.push(ESC),
                0x20..=0x2f => {
                    out.extend_from_slice(&[ESC, byte]);
                    self.state = State::EscIntermediate;
                }
                _ => {
                    out.extend_from_slice(&[ESC, byte]);
                    self.state = State::Ground;
                    if byte == b'c' {
                        // RIS: a full reset.
                        self.region = None;
                        self.stale = true;
                        self.region_stale = true;
                    }
                }
            },
            State::EscIntermediate => {
                if byte == ESC {
                    self.state = State::Esc;
                } else {
                    out.push(byte);
                    if !(0x20..=0x2f).contains(&byte) {
                        self.state = State::Ground;
                    }
                }
            }
            State::Csi => match byte {
                0x40..=0x7e => {
                    self.state = State::Ground;
                    let params = std::mem::take(&mut self.csi);
                    self.csi_final(&params, byte, out);
                    self.csi = params;
                }
                ESC => {
                    // The terminal abandons the sequence; so do we.
                    out.extend_from_slice(b"\x1b[");
                    out.extend_from_slice(&self.csi);
                    self.state = State::Esc;
                }
                _ => {
                    self.csi.push(byte);
                    if self.csi.len() > MAX_CSI {
                        out.extend_from_slice(b"\x1b[");
                        out.extend_from_slice(&self.csi);
                        self.state = State::CsiLong;
                    }
                }
            },
            State::CsiLong => {
                if byte == ESC {
                    self.state = State::Esc;
                } else {
                    out.push(byte);
                    if (0x40..=0x7e).contains(&byte) {
                        self.state = State::Ground;
                    }
                }
            }
            State::Str => match byte {
                ESC => self.state = State::StrEsc,
                BEL => {
                    out.push(byte);
                    self.state = State::Ground;
                }
                _ => out.push(byte),
            },
            State::StrEsc => {
                if byte == b'\\' {
                    out.extend_from_slice(b"\x1b\\");
                    self.state = State::Ground;
                } else {
                    // Not a string terminator: a new escape sequence.
                    self.state = State::Esc;
                    self.step(byte, out);
                }
            }
        }
    }

    /// A complete CSI sequence: `ESC [ params final`.
    fn csi_final(&mut self, params: &[u8], last: u8, out: &mut Vec<u8>) {
        let limit = self.agent_rows();
        let numbers = numbers(params);
        match (last, &numbers) {
            // DECSTBM. Without arguments it means the whole screen, which
            // to the agent ends above the footer.
            (b'r', Some(args)) if args.len() <= 2 => {
                let top = args.first().copied().filter(|n| *n > 0).unwrap_or(1);
                let bottom = args
                    .get(1)
                    .copied()
                    .filter(|n| *n > 0)
                    .unwrap_or(limit)
                    .min(limit);
                let (top, bottom) = if top < bottom {
                    (top, bottom)
                } else {
                    (1, limit)
                };
                self.region =
                    ((top, bottom) != (1, limit)).then_some((top, bottom));
                out.extend_from_slice(
                    format!("\x1b[{top};{bottom}r").as_bytes(),
                );
            }
            // CUP, HVP and VPA with a row below the agent's screen.
            (b'H' | b'f' | b'd', Some(args))
                if args.first().is_some_and(|row| *row > limit) =>
            {
                out.extend_from_slice(format!("\x1b[{limit}").as_bytes());
                for arg in &args[1..] {
                    out.extend_from_slice(format!(";{arg}").as_bytes());
                }
                out.push(last);
            }
            _ => {
                out.extend_from_slice(b"\x1b[");
                out.extend_from_slice(params);
                out.push(last);
                match last {
                    // ED: erasing the display takes the footer with it.
                    // 3 only clears the scrollback.
                    b'J' if params != b"3" => self.stale = true,
                    // Switching to or from the alternate screen.
                    b'h' | b'l'
                        if params.strip_prefix(b"?").is_some_and(|modes| {
                            modes.split(|b| *b == b';').any(|mode| {
                                matches!(mode, b"47" | b"1047" | b"1049")
                            })
                        }) =>
                    {
                        self.stale = true;
                        self.region_stale = true;
                    }
                    // DECSTR: a soft reset.
                    b'p' if params == b"!" => {
                        self.region = None;
                        self.stale = true;
                        self.region_stale = true;
                    }
                    _ => {}
                }
            }
        }
    }

    fn paint(&mut self, out: &mut Vec<u8>, with_region: bool) {
        out.extend_from_slice(b"\x1b7");
        if with_region {
            // Setting the region homes the cursor; DECRC puts it back.
            let (top, bottom) = self.region.unwrap_or((1, self.agent_rows()));
            out.extend_from_slice(format!("\x1b[{top};{bottom}r").as_bytes());
        }
        let width = usize::from(self.cols);
        let text: String = self.label.chars().take(width).collect();
        out.extend_from_slice(
            format!("\x1b[{};1H\x1b[0;7m{text:<width$}\x1b[0m\x1b8", self.rows)
                .as_bytes(),
        );
        self.stale = false;
        self.region_stale = false;
        self.dirty = false;
    }
}

/// Plain `;`-separated numeric parameters, with empty ones as 0. `None` for
/// private or intermediate bytes, which belong to other sequences.
fn numbers(params: &[u8]) -> Option<Vec<u16>> {
    if params.is_empty() {
        return Some(Vec::new());
    }
    params
        .split(|b| *b == b';')
        .map(|part| {
            if part.is_empty() {
                return Some(0);
            }
            std::str::from_utf8(part).ok()?.parse().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAINT: &str = "\x1b7\x1b[24;1H\x1b[0;7mjail      \x1b[0m\x1b8";
    const PAINT_REGION: &str =
        "\x1b7\x1b[1;23r\x1b[24;1H\x1b[0;7mjail      \x1b[0m\x1b8";

    fn footer() -> Footer {
        Footer::new("jail".into(), 24, 10)
    }

    fn filter(footer: &mut Footer, input: &str) -> String {
        let mut out = Vec::new();
        footer.filter(input.as_bytes(), &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn reserves_the_last_row() {
        let mut footer = footer();
        assert_eq!(footer.agent_rows(), 23);
        let open = String::from_utf8(footer.open()).unwrap();
        assert_eq!(open, format!("\r\n\x1b[A{PAINT_REGION}"));
        assert_eq!(footer.close(), b"\x1b7\x1b[r\x1b[24;1H\x1b[2K\x1b8");
    }

    #[test]
    fn plain_output_passes_through() {
        let mut footer = footer();
        let text = "hello \x1b[1;31mred\x1b[0m\r\n\x1b[5;7H\x1b[2K\x1b[?25l";
        assert_eq!(filter(&mut footer, text), text);
    }

    #[test]
    fn scroll_region_never_includes_the_footer() {
        let mut footer = footer();
        assert_eq!(filter(&mut footer, "\x1b[r"), "\x1b[1;23r");
        assert_eq!(filter(&mut footer, "\x1b[1;24r"), "\x1b[1;23r");
        assert_eq!(filter(&mut footer, "\x1b[;r"), "\x1b[1;23r");
        assert_eq!(filter(&mut footer, "\x1b[5;10r"), "\x1b[5;10r");
        // Restoring DEC private modes is a different sequence.
        assert_eq!(filter(&mut footer, "\x1b[?1r"), "\x1b[?1r");
    }

    #[test]
    fn cursor_cannot_be_put_on_the_footer() {
        let mut footer = footer();
        assert_eq!(filter(&mut footer, "\x1b[999;999H"), "\x1b[23;999H");
        assert_eq!(filter(&mut footer, "\x1b[24d"), "\x1b[23d");
        assert_eq!(filter(&mut footer, "\x1b[23;5f"), "\x1b[23;5f");
        assert_eq!(filter(&mut footer, "\x1b[H"), "\x1b[H");
    }

    #[test]
    fn repaints_after_an_erase() {
        let mut footer = footer();
        assert_eq!(
            filter(&mut footer, "\x1b[H\x1b[2Jtext"),
            format!("\x1b[H\x1b[2Jtext{PAINT}")
        );
        assert_eq!(filter(&mut footer, "\x1b[J"), format!("\x1b[J{PAINT}"));
        assert_eq!(filter(&mut footer, "\x1b[3J"), "\x1b[3J");
    }

    #[test]
    fn restores_the_region_after_screen_switches_and_resets() {
        let mut footer = footer();
        assert_eq!(
            filter(&mut footer, "\x1b[?1049h"),
            format!("\x1b[?1049h{PAINT_REGION}")
        );
        assert_eq!(
            filter(&mut footer, "\x1b[?25;1049l"),
            format!("\x1b[?25;1049l{PAINT_REGION}")
        );
        assert_eq!(
            filter(&mut footer, "\x1bc"),
            format!("\x1bc{PAINT_REGION}")
        );
        assert_eq!(
            filter(&mut footer, "\x1b[!p"),
            format!("\x1b[!p{PAINT_REGION}")
        );
    }

    #[test]
    fn the_agents_own_region_survives_a_repaint() {
        let mut footer = footer();
        filter(&mut footer, "\x1b[5;10r");
        assert_eq!(
            filter(&mut footer, "\x1b[?1049h"),
            "\x1b[?1049h\x1b7\x1b[5;10r\x1b[24;1H\x1b[0;7mjail      \x1b[0m\x1b8"
        );
    }

    #[test]
    fn sequences_split_across_reads() {
        let mut footer = footer();
        assert_eq!(filter(&mut footer, "a\x1b"), "a");
        assert_eq!(filter(&mut footer, "["), "");
        assert_eq!(filter(&mut footer, "2"), "");
        // The footer is painted only once the sequence is complete.
        assert_eq!(filter(&mut footer, "J"), format!("\x1b[2J{PAINT}"));
        assert_eq!(filter(&mut footer, "\x1b[2J\x1b]0;ti"), "\x1b[2J\x1b]0;ti");
        assert_eq!(filter(&mut footer, "tle\x07"), format!("tle\x07{PAINT}"));
    }

    #[test]
    fn strings_are_not_parsed() {
        let mut footer = footer();
        let osc = "\x1b]8;;http://x/\x1b\\link\x1b]0;[2J[r\x07\x1bP[r\x1b\\";
        assert_eq!(filter(&mut footer, osc), osc);
        let charset = "\x1b(B\x1b[m";
        assert_eq!(filter(&mut footer, charset), charset);
    }

    #[test]
    fn refresh_only_after_output() {
        let mut footer = footer();
        footer.open();
        assert!(footer.refresh().is_empty());
        filter(&mut footer, "text");
        assert_eq!(footer.refresh(), PAINT.as_bytes());
        assert!(footer.refresh().is_empty());
        filter(&mut footer, "\x1b[");
        assert!(footer.refresh().is_empty());
    }

    #[test]
    fn resize_moves_the_footer() {
        let mut footer = footer();
        let grown = String::from_utf8(footer.resize(30, 10)).unwrap();
        assert_eq!(
            grown,
            "\x1b7\x1b[24;1H\x1b[2K\x1b8\
             \x1b7\x1b[1;29r\x1b[30;1H\x1b[0;7mjail      \x1b[0m\x1b8"
        );
        assert_eq!(footer.agent_rows(), 29);
        let shrunk = String::from_utf8(footer.resize(20, 3)).unwrap();
        assert_eq!(shrunk, "\x1b7\x1b[1;19r\x1b[20;1H\x1b[0;7mjai\x1b[0m\x1b8");
    }

    #[test]
    fn a_tiny_terminal_has_no_footer() {
        let mut footer = Footer::new("jail".into(), 4, 10);
        assert_eq!(footer.agent_rows(), 4);
        assert!(footer.open().is_empty());
        assert_eq!(filter(&mut footer, "\x1b[r\x1b[2J"), "\x1b[r\x1b[2J");
        assert!(footer.close().is_empty());
        // Growing brings it back; shrinking releases the region.
        assert!(!footer.resize(24, 10).is_empty());
        assert_eq!(footer.resize(3, 10), b"\x1b7\x1b[r\x1b8");
    }
}
