//! SetupAPI's text logs (`Windows\INF\setupapi.dev.log`, `setupapi.setup.log`,
//! …): one section per device install, driver install or update, between
//! `>>>  [title]`, `>>>  Section start YYYY/MM/DD HH:MM:SS.fff`,
//! `<<<  Section end …` and `<<<  [Exit status: SUCCESS]`. A USB drive's
//! first install (`Device Install (Hardware initiated) - USBSTOR\…`) dates
//! its first connection. Times are local, their zone not recorded.

use common::time::Ts;

use crate::{date_time, decode, Civil, Parsed};

/// A section of a SetupAPI log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Its title's line, from 1.
    pub line: usize,
    /// Its title (`Device Install (Hardware initiated) - USBSTOR\Disk&…`).
    pub title: String,
    /// When it started (local time).
    pub start: Option<Ts>,
    /// When it ended (local time).
    pub end: Option<Ts>,
    /// How it ended (`SUCCESS`, `FAILURE(0xe0000219)`).
    pub exit_status: Option<String>,
}

/// Read a SetupAPI log.
#[must_use]
pub fn read(data: &[u8]) -> Parsed<Section> {
    let mut parsed: Parsed<Section> = Parsed::default();
    let mut open: Option<Section> = None;
    for (index, line) in decode(data).lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(">>>") {
            let rest = rest.trim();
            if let Some(time) = rest.strip_prefix("Section start") {
                match open.as_mut() {
                    Some(section) => section.start = date_time(time).and_then(Civil::local),
                    None => parsed
                        .problems
                        .push(format!("line {line_number}: a start without a title")),
                }
            } else if let Some(title) = rest.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
                parsed.entries.extend(open.take());
                open = Some(Section {
                    line: line_number,
                    title: title.to_owned(),
                    start: None,
                    end: None,
                    exit_status: None,
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("<<<") {
            let rest = rest.trim();
            let Some(section) = open.as_mut() else {
                continue;
            };
            if let Some(time) = rest.strip_prefix("Section end") {
                section.end = date_time(time).and_then(Civil::local);
            } else if let Some(status) = rest
                .strip_prefix("[Exit status:")
                .and_then(|s| s.strip_suffix(']'))
            {
                section.exit_status = Some(status.trim().to_owned());
                parsed.entries.extend(open.take());
            }
        }
    }
    parsed.entries.extend(open);
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_with_their_times_and_status() {
        let log = "[Device Install Log]\n>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_X]\n>>>  Section start 2016/10/05 11:15:58.981\n     dvi: something\n<<<  Section end 2016/10/05 11:16:04.247\n<<<  [Exit status: SUCCESS]\n>>>  [Unfinished]\n";
        let parsed = read(log.as_bytes());
        assert_eq!(parsed.entries.len(), 2);
        let usb = &parsed.entries[0];
        assert_eq!(
            usb.title,
            "Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_X"
        );
        assert_eq!(usb.exit_status.as_deref(), Some("SUCCESS"));
        assert_eq!(
            usb.start.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2016-10-05T11:15:58.9810000")
        );
        assert_eq!(parsed.entries[1].start, None);
    }
}
