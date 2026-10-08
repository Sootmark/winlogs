//! Windows Error Reporting's reports (`Report.wer`, in
//! `ProgramData\Microsoft\Windows\WER\ReportArchive\<folder>\` and
//! `ReportQueue\`, and the same under each user's `AppData\Local\Microsoft\
//! Windows\WER\`): a program that crashed or hung, when, from where, with
//! the modules it had loaded. Evidence of execution that outlives the
//! program, and of tools that crashed doing their work (a credential dumper
//! taking `lsass.exe` down).
//!
//! UTF-16 lines of `Name=Value`: `EventType` (`APPCRASH`, `BEX64`,
//! `AppHangB1`, …), `EventTime` (a FILETIME), the signature pairs
//! (`Sig[0].Name`, `Sig[0].Value`: application name, version, timestamp,
//! faulting module, exception code, offset), `LoadedModule[n]`, `AppName`,
//! `AppPath`.

use common::time::Ts;

use crate::{decode, Parsed};

/// A report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// `EventType` (`APPCRASH`, `BEX64`, `AppHangB1`, `LiveKernelEvent`).
    pub event_type: Option<String>,
    /// `FriendlyEventName` (`Stopped working`).
    pub friendly_event_name: Option<String>,
    /// `EventTime`: when it happened (UTC).
    pub time: Option<Ts>,
    /// `UploadTime`: when the report was written or sent (UTC).
    pub upload_time: Option<Ts>,
    /// `ReportIdentifier`.
    pub report_id: Option<String>,
    /// `AppName`: the program's friendly name.
    pub app_name: Option<String>,
    /// `AppPath`: the program's path.
    pub app_path: Option<String>,
    /// `NsAppName`: the program's file name.
    pub ns_app_name: Option<String>,
    /// The signature, `Sig[n].Name` and `Sig[n].Value` in order.
    pub signature: Vec<(String, String)>,
    /// The dynamic signature (`DynamicSig[n]`: OS version, locale, …).
    pub dynamic_signature: Vec<(String, String)>,
    /// `LoadedModule[n]`: the modules the program had loaded.
    pub loaded_modules: Vec<String>,
    /// Every line's name and value, in file order.
    pub values: Vec<(String, String)>,
}

impl Report {
    /// The first value named `name` (names are case-insensitive).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The signature value named `name` (`Application Name`, `Fault Module
    /// Name`, `Exception Code`).
    #[must_use]
    pub fn signature(&self, name: &str) -> Option<&str> {
        self.signature
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Whether text starts like a report (`Version=` then `EventType=` within
/// its first lines).
pub(crate) fn is_report(start: &str) -> bool {
    let mut lines = start.lines().map(str::trim).filter(|l| !l.is_empty());
    lines.next().is_some_and(|l| l.starts_with("Version="))
        && lines.take(4).any(|l| l.starts_with("EventType="))
}

/// Read a `Report.wer`: one entry, or none and a problem when it holds no
/// `Name=Value` line.
#[must_use]
pub fn report(data: &[u8]) -> Parsed<Report> {
    let mut parsed = Parsed::default();
    let mut values = Vec::new();
    for (index, line) in decode(data).lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            parsed
                .problems
                .push(format!("line {}: not Name=Value", index + 1));
            continue;
        };
        values.push((name.to_owned(), value.to_owned()));
    }
    if values.is_empty() {
        parsed.problems.push("no Name=Value line".to_owned());
    } else {
        parsed.entries.push(from_values(values));
    }
    parsed
}

/// A report from its lines' names and values.
fn from_values(values: Vec<(String, String)>) -> Report {
    let get = |name: &str| {
        values
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let text = |name: &str| get(name).map(str::to_owned);
    let time = |name: &str| {
        get(name)
            .and_then(|t| t.parse::<u64>().ok())
            .filter(|&t| t != 0)
            .map(Ts::from_filetime)
    };
    Report {
        event_type: text("EventType"),
        friendly_event_name: text("FriendlyEventName"),
        time: time("EventTime"),
        upload_time: time("UploadTime"),
        report_id: text("ReportIdentifier"),
        app_name: text("AppName"),
        app_path: text("AppPath"),
        ns_app_name: text("NsAppName"),
        signature: pairs(&values, "Sig["),
        dynamic_signature: pairs(&values, "DynamicSig["),
        loaded_modules: values
            .iter()
            .filter(|(n, _)| n.starts_with("LoadedModule["))
            .map(|(_, v)| v.clone())
            .collect(),
        values,
    }
}

/// The `<prefix>n].Name` and `<prefix>n].Value` pairs, in index order.
fn pairs(values: &[(String, String)], prefix: &str) -> Vec<(String, String)> {
    let index_of = |name: &str, part: &str| -> Option<u32> {
        name.strip_prefix(prefix)?
            .strip_suffix(part)?
            .strip_suffix(']')?
            .parse()
            .ok()
    };
    let mut named: Vec<(u32, String)> = values
        .iter()
        .filter_map(|(n, v)| Some((index_of(n, ".Name")?, v.clone())))
        .collect();
    named.sort_by_key(|(i, _)| *i);
    named
        .into_iter()
        .map(|(i, name)| {
            let value = values
                .iter()
                .find(|(n, _)| index_of(n, ".Value") == Some(i))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            (name, value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_pairs_in_index_order() {
        let parsed = report(
            b"Version=1\r\nEventType=APPCRASH\r\nSig[1].Name=Application Version\r\nSig[1].Value=1.0\r\nSig[0].Name=Application Name\r\nSig[0].Value=a.exe\r\nbroken line\r\n",
        );
        let r = &parsed.entries[0];
        assert_eq!(
            r.signature,
            [
                ("Application Name".to_owned(), "a.exe".to_owned()),
                ("Application Version".to_owned(), "1.0".to_owned())
            ]
        );
        assert_eq!(r.signature("application name"), Some("a.exe"));
        assert_eq!(parsed.problems, ["line 7: not Name=Value"]);
        assert!(is_report("Version=1\nEventType=APPCRASH\n"));
        assert!(!is_report("[section]\nx=1\n"));
    }
}
