//! Windows text logs, for forensics: the plain-text records Windows and
//! common software keep beside the event logs, each read into entries with
//! their time and fields.
//!
//! - [`pca`]: the Program Compatibility Assistant's `PcaAppLaunchDic.txt`
//!   and `PcaGeneralDb0.txt` (Windows 11 22H2 and later,
//!   `Windows\appcompat\pca`): programs run, and when.
//! - [`w3c`]: W3C extended logs, as IIS (`u_ex*.log`: web requests, the
//!   trail of a web shell) and the Windows Firewall (`pfirewall.log`) write
//!   them.
//! - [`transcript`]: PowerShell transcripts: who ran which commands, and
//!   their output.
//! - [`teamviewer`]: TeamViewer's application log and its connection lists
//!   (remote access in and out).
//! - [`setupapi`]: `setupapi.dev.log` and the like: devices installed (USB
//!   drives first plugged in), drivers and updates.
//! - [`sccm`]: Configuration Manager client logs.
//! - [`wer`]: Windows Error Reporting's reports (`Report.wer`): programs
//!   that crashed or hung, when, from where, with their loaded modules.
//! - [`anydesk`]: AnyDesk's traces and `connection_trace.txt`.
//! - [`screenconnect`]: ConnectWise ScreenConnect's client settings
//!   (`system.config`, `user.config`: the relay and session it connects
//!   to) and its server's session database (`Session.db`: sessions,
//!   connections, commands and transfers).
//!
//! [`detect`] says which a file is, from its name and first bytes. Damage
//! goes to `problems`, never a panic.

pub mod anydesk;
pub mod pca;
pub mod sccm;
pub mod screenconnect;
pub mod setupapi;
pub mod teamviewer;
pub mod transcript;
pub mod w3c;
pub mod wer;

use common::time::{days_from_civil, Precision, Ts};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Ticks (100 ns) in a millisecond.
const TICKS_PER_MS: i64 = 10_000;
/// The first bytes of a SQLite database.
const SQLITE_HEADER: &[u8] = b"SQLite format 3\0";

/// Which log a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `PcaAppLaunchDic.txt`.
    PcaLaunches,
    /// `PcaGeneralDb0.txt`, `PcaGeneralDb1.txt`.
    PcaGeneral,
    /// A W3C extended log (IIS, the Windows Firewall, …).
    W3c,
    /// A PowerShell transcript.
    Transcript,
    /// TeamViewer's application log (`TeamViewer15_Logfile.log`).
    TeamViewerLog,
    /// TeamViewer's incoming connections (`Connections_incoming.txt`).
    TeamViewerIncoming,
    /// TeamViewer's outgoing connections (`Connections.txt`).
    TeamViewerOutgoing,
    /// A SetupAPI log (`setupapi.dev.log`, `setupapi.setup.log`, …).
    SetupApi,
    /// A Configuration Manager (SCCM) client log.
    Sccm,
    /// AnyDesk's trace (`ad.trace`, `ad_svc.trace`).
    AnyDeskTrace,
    /// AnyDesk's sessions (`connection_trace.txt`).
    AnyDeskConnections,
    /// A Windows Error Reporting report (`Report.wer`).
    WerReport,
    /// A ScreenConnect client's settings (`system.config`, `user.config`).
    ScreenConnectConfig,
    /// A ScreenConnect server's session database (`Session.db`).
    ScreenConnectSessions,
}

/// Which log a file named `name` (a path or a bare name) starting with
/// `head` is.
#[must_use]
pub fn detect(name: &str, head: &[u8]) -> Option<Kind> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = base.to_ascii_lowercase();
    let start = decode(&head[..head.len().min(4096)]);
    match lower.as_str() {
        "pcaapplaunchdic.txt" => return Some(Kind::PcaLaunches),
        "pcageneraldb0.txt" | "pcageneraldb1.txt" => return Some(Kind::PcaGeneral),
        "connections_incoming.txt" => return Some(Kind::TeamViewerIncoming),
        "connections.txt" => return Some(Kind::TeamViewerOutgoing),
        "ad.trace" | "ad_svc.trace" => return Some(Kind::AnyDeskTrace),
        "connection_trace.txt" => return Some(Kind::AnyDeskConnections),
        "report.wer" => return Some(Kind::WerReport),
        "session.db" if head.starts_with(SQLITE_HEADER) => {
            return Some(Kind::ScreenConnectSessions)
        }
        "system.config" | "user.config" if start.contains("<ScreenConnect.") => {
            return Some(Kind::ScreenConnectConfig)
        }
        _ => {}
    }
    let extension = lower.rsplit_once('.').map_or("", |(_, e)| e);
    if lower.starts_with("teamviewer") && lower.contains("logfile") && extension == "log" {
        return Some(Kind::TeamViewerLog);
    }
    if lower.starts_with("setupapi.") && extension == "log" {
        return Some(Kind::SetupApi);
    }
    if lower.starts_with("powershell_transcript.") && extension == "txt" {
        return Some(Kind::Transcript);
    }
    let mut first_lines = start.lines();
    if first_lines
        .next()
        .is_some_and(|l| l.trim_end() == "**********************")
        && first_lines.next().is_some_and(|l| l.contains("PowerShell"))
    {
        return Some(Kind::Transcript);
    }
    if wer::is_report(&start) {
        return Some(Kind::WerReport);
    }
    if start.contains("<![LOG[") {
        return Some(Kind::Sccm);
    }
    if start.lines().any(|line| line.starts_with("#Fields:")) {
        return Some(Kind::W3c);
    }
    let mut lines = start
        .lines()
        .filter(|l| !l.trim().is_empty() && !anydesk::is_separator(l));
    if lines.next().is_some_and(anydesk::is_trace) {
        return Some(Kind::AnyDeskTrace);
    }
    if start.lines().next().is_some_and(anydesk::is_session) {
        return Some(Kind::AnyDeskConnections);
    }
    None
}

/// What reading a log gave: its entries, and what couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<T> {
    /// The entries, in file order.
    pub entries: Vec<T>,
    /// One line per line or block that couldn't be read.
    pub problems: Vec<String>,
}

impl<T> Default for Parsed<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            problems: Vec::new(),
        }
    }
}

/// A file's text: UTF-16 when it starts with its byte order mark, UTF-8
/// (lossy) otherwise, without the mark.
#[must_use]
pub fn decode(data: &[u8]) -> String {
    let utf16 = |bytes: &[u8], big: bool| {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|p| {
                if big {
                    u16::from_be_bytes([p[0], p[1]])
                } else {
                    u16::from_le_bytes([p[0], p[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    if let Some(rest) = data.strip_prefix(&[0xFF, 0xFE]) {
        utf16(rest, false)
    } else if let Some(rest) = data.strip_prefix(&[0xFE, 0xFF]) {
        utf16(rest, true)
    } else {
        let rest = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
        String::from_utf8_lossy(rest).into_owned()
    }
}

/// A date and time's parts, as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Civil {
    pub(crate) year: i64,
    pub(crate) month: u32,
    pub(crate) day: u32,
    pub(crate) hour: i64,
    pub(crate) minute: i64,
    pub(crate) second: i64,
    pub(crate) millisecond: i64,
}

impl Civil {
    /// Ticks since 1970, counting the wall clock as UTC; `None` for an
    /// impossible date or time.
    fn ticks(self) -> Option<i64> {
        let valid = (1..=12).contains(&self.month)
            && (1..=31).contains(&self.day)
            && (0..24).contains(&self.hour)
            && (0..60).contains(&self.minute)
            && (0..61).contains(&self.second)
            && (0..1000).contains(&self.millisecond);
        if !valid {
            return None;
        }
        let days = days_from_civil(self.year, self.month, self.day);
        let seconds = days * 86_400 + self.hour * 3600 + self.minute * 60 + self.second;
        Some(seconds * 10_000_000 + self.millisecond * TICKS_PER_MS)
    }

    /// The time, in UTC.
    pub(crate) fn utc(self) -> Option<Ts> {
        Some(Ts::from_ticks(self.ticks()?, Precision::Millisecond))
    }

    /// The time, as the wall clock of an unknown zone.
    pub(crate) fn local(self) -> Option<Ts> {
        Some(Ts::from_local_ticks(self.ticks()?, Precision::Millisecond))
    }

    /// The time in UTC, from a local time `bias_minutes` behind UTC (UTC =
    /// local + bias, as Windows counts its time zone bias).
    pub(crate) fn with_bias(self, bias_minutes: i64) -> Option<Ts> {
        let ticks = self.ticks()? + bias_minutes * 60 * 10_000_000;
        Some(Ts::from_ticks(ticks, Precision::Millisecond))
    }
}

/// `YYYY?MM?DD`, any one-character separators.
pub(crate) fn date_ymd(text: &str) -> Option<(i64, u32, u32)> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 {
        return None;
    }
    Some((
        text.get(..4)?.parse().ok()?,
        text.get(5..7)?.parse().ok()?,
        text.get(8..10)?.parse().ok()?,
    ))
}

/// `HH:MM:SS` or `HH:MM:SS.fff` (fewer or more fraction digits read as
/// milliseconds).
pub(crate) fn time_hms(text: &str) -> Option<(i64, i64, i64, i64)> {
    let (clock, fraction) = text.split_once('.').unwrap_or((text, ""));
    let mut parts = clock.split(':');
    let hour = parts.next()?.parse().ok()?;
    let minute = parts.next()?.parse().ok()?;
    let second = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !fraction.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let millisecond = format!("{fraction:0<3}").get(..3)?.parse().unwrap_or(0);
    Some((hour, minute, second, millisecond))
}

/// A date and a time of day joined.
pub(crate) fn civil(
    (year, month, day): (i64, u32, u32),
    (hour, minute, second, millisecond): (i64, i64, i64, i64),
) -> Civil {
    Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
        millisecond,
    }
}

/// `YYYY-MM-DD HH:MM:SS[.fff]` (any date separator).
pub(crate) fn date_time(text: &str) -> Option<Civil> {
    let (date, time) = text.trim().split_once(' ')?;
    Some(civil(date_ymd(date)?, time_hms(time.trim())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection() {
        assert_eq!(
            detect(r"C:\Windows\appcompat\pca\PcaAppLaunchDic.txt", b""),
            Some(Kind::PcaLaunches)
        );
        assert_eq!(detect("PcaGeneralDb1.txt", b""), Some(Kind::PcaGeneral));
        assert_eq!(detect("u_ex220101.log", b"#Software: Microsoft Internet Information Services 10.0\r\n#Fields: date time\r\n"), Some(Kind::W3c));
        assert_eq!(
            detect("TeamViewer15_Logfile.log", b""),
            Some(Kind::TeamViewerLog)
        );
        assert_eq!(detect("setupapi.dev.log", b""), Some(Kind::SetupApi));
        assert_eq!(
            detect("PowerShell_transcript.HOST.x.20220721.txt", b""),
            Some(Kind::Transcript)
        );
        assert_eq!(
            detect("ccmexec.log", b"<![LOG[Started]LOG]!>"),
            Some(Kind::Sccm)
        );
        assert_eq!(detect("notes.txt", b"hello"), None);
        assert_eq!(
            detect(
                r"C:\Program Files (x86)\ScreenConnect\App_Data\Session.db",
                b"SQLite format 3\0"
            ),
            Some(Kind::ScreenConnectSessions)
        );
        assert_eq!(detect("Session.db", b"not sqlite"), None);
        assert_eq!(
            detect(
                "system.config",
                b"<configuration><ScreenConnect.ApplicationSettings>"
            ),
            Some(Kind::ScreenConnectConfig)
        );
        assert_eq!(detect("user.config", b"<configuration/>"), None);
        let transcript = "**********************\r\nStart der Windows PowerShell-Aufzeichnung\r\n";
        assert_eq!(
            detect("x.txt", transcript.as_bytes()),
            Some(Kind::Transcript)
        );
    }

    #[test]
    fn text_in_any_encoding() {
        assert_eq!(decode(b"\xEF\xBB\xBFab"), "ab");
        assert_eq!(decode(&[0xFF, 0xFE, b'a', 0, b'b', 0]), "ab");
        assert_eq!(decode(&[0xFE, 0xFF, 0, b'a']), "a");
    }

    #[test]
    fn times() {
        let utc = date_time("2022-11-14 23:37:11.789").unwrap().utc().unwrap();
        assert_eq!(
            utc.to_iso8601().as_deref(),
            Some("2022-11-14T23:37:11.7890000Z")
        );
        let local = date_time("2005/04/11 08:05:57").unwrap().local().unwrap();
        assert_eq!(
            local.to_iso8601().as_deref(),
            Some("2005-04-11T08:05:57.0000000")
        );
        assert_eq!(date_time("2022-13-01 00:00:00").and_then(Civil::utc), None);
        assert_eq!(time_hms("1:2"), None);
    }
}
